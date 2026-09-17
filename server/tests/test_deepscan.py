# Drishti v0.1 — deep-scan tests (offline: nmap + NVD mocked) | 12-Jul-2026
"""Every external call (nmap subprocess, NVD HTTP) is mocked so the suite runs
fully offline. Asserts: the parser reads real-shaped nmap XML; the CVE lookup
maps a real NVD response and degrades to available:false WITHOUT fabricating;
a scan creates Asset+Service+Vulnerability rows and gets a real engine
risk_score; and the endpoint enforces auth + consent + RFC1918."""
import pytest

from app.services.deepscan import cve_lookup, scanner
from app.services.deepscan.parser import parse_nmap_xml

# a real-shaped `nmap -sV -oX -` fragment: one open ssh port + one closed port
NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" method="probed"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

# a real-shaped NVD 2.0 response for one CVE with a scored CVSS v3.1 metric
NVD_PAYLOAD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [
                    {"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"},
                            "exploitabilityScore": 3.9,
                        }
                    ]
                },
            }
        }
    ]
}


# ── parser ───────────────────────────────────────────────────────────────────
def test_parser_reads_open_services_only():
    parsed = parse_nmap_xml(NMAP_XML)
    assert parsed["up"] is True
    ports = {s["port"]: s for s in parsed["services"]}
    assert set(ports) == {22, 8080}  # closed port 23 dropped, never fabricated
    assert ports[22]["service_name"] == "ssh"
    assert ports[22]["product"] == "OpenSSH"
    assert ports[22]["version"] == "8.9p1"
    assert ports[8080]["product"] == "Apache httpd"


def test_parser_raises_on_garbage():
    with pytest.raises(ValueError):
        parse_nmap_xml("not xml at all <<<")


# ── cve lookup ───────────────────────────────────────────────────────────────
def test_cve_lookup_maps_real_nvd_response(monkeypatch):
    cve_lookup._reset_cache()
    monkeypatch.setattr(cve_lookup, "_MIN_SPACING_S", 0.0)
    monkeypatch.setattr(
        cve_lookup, "fetch_nvd",
        lambda product, version, timeout, api_key: (NVD_PAYLOAD, None),
    )
    out = cve_lookup.lookup_for_services(
        [{"port": 8080, "protocol": "tcp", "product": "Apache httpd", "version": "2.4.49"}]
    )
    assert out["available"] is True
    assert len(out["cves"]) == 1
    cve = out["cves"][0]
    assert cve["id"] == "CVE-2021-41773"
    assert cve["cvss"] == 7.5
    assert cve["severity"] == "high"
    assert cve["exploitability"] == 1.0  # 3.9 / 3.9, from the source, normalized
    assert cve["port"] == 8080


def test_cve_lookup_unavailable_never_fabricates(monkeypatch):
    cve_lookup._reset_cache()
    monkeypatch.setattr(cve_lookup, "_MIN_SPACING_S", 0.0)
    monkeypatch.setattr(
        cve_lookup, "fetch_nvd",
        lambda product, version, timeout, api_key: (None, "NVD rate-limited (HTTP 429)"),
    )
    out = cve_lookup.lookup_for_services(
        [{"port": 8080, "protocol": "tcp", "product": "Apache httpd", "version": "2.4.49"}]
    )
    assert out["available"] is False
    assert out["cves"] == []  # no fabricated CVEs on failure
    assert "429" in out["reason"]


def test_cve_lookup_no_identifiable_product_is_empty_but_available():
    cve_lookup._reset_cache()
    out = cve_lookup.lookup_for_services([{"port": 9999, "protocol": "tcp", "product": None}])
    # nothing to look up → truthfully "no CVEs", and the source was never needed
    assert out == {"available": True, "reason": None, "cves": []}


# ── scanner degradation ──────────────────────────────────────────────────────
def test_scanner_unavailable_on_nmap_failure(monkeypatch):
    monkeypatch.setattr(scanner, "run_nmap", lambda ip, timeout: (None, "nmap is not installed on the server"))
    res = scanner.scan("10.0.0.5")
    assert res["available"] is False
    assert "nmap" in res["reason"]
    assert "services" not in res  # no fabricated services


def test_scanner_parses_real_output(monkeypatch):
    monkeypatch.setattr(scanner, "run_nmap", lambda ip, timeout: (NMAP_XML, None))
    res = scanner.scan("10.0.0.5")
    assert res["available"] is True
    assert len(res["services"]) == 2


# ── engine integration via the endpoint ──────────────────────────────────────
def _mock_scan_pipeline(monkeypatch):
    cve_lookup._reset_cache()
    monkeypatch.setattr(cve_lookup, "_MIN_SPACING_S", 0.0)
    monkeypatch.setattr(scanner, "run_nmap", lambda ip, timeout: (NMAP_XML, None))
    monkeypatch.setattr(
        cve_lookup, "fetch_nvd",
        lambda product, version, timeout, api_key: (
            (NVD_PAYLOAD, None) if "apache" in product.lower() else ({"vulnerabilities": []}, None)
        ),
    )


def test_deep_scan_creates_asset_and_real_risk_score(client, user_headers, monkeypatch):
    _mock_scan_pipeline(monkeypatch)
    resp = client.post(
        "/api/live/deep-scan",
        json={"ip": "10.0.0.5", "consent": True},
        headers=user_headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["available"] is True
    assert data["target"] == "10.0.0.5"
    assert data["asset_id"]
    assert data["risk_score"] is not None and data["risk_score"] > 0  # real engine output
    assert sorted(data["ports"]) == [22, 8080]
    assert len(data["cves"]) == 1
    cve = data["cves"][0]
    assert cve["id"] == "CVE-2021-41773"
    assert cve["finding_id"]  # routes into the existing remediation flow

    # GET replays the same persisted result
    again = client.get(f"/api/live/deep-scan/{data['asset_id']}", headers=user_headers)
    assert again.status_code == 200, again.text
    assert again.json()["cves"][0]["id"] == "CVE-2021-41773"


def test_deep_scan_available_but_no_cves_is_truthful(client, user_headers, monkeypatch):
    cve_lookup._reset_cache()
    monkeypatch.setattr(cve_lookup, "_MIN_SPACING_S", 0.0)
    monkeypatch.setattr(scanner, "run_nmap", lambda ip, timeout: (NMAP_XML, None))
    # source reachable but returns zero matches → available true, empty cves
    monkeypatch.setattr(
        cve_lookup, "fetch_nvd",
        lambda product, version, timeout, api_key: ({"vulnerabilities": []}, None),
    )
    resp = client.post(
        "/api/live/deep-scan",
        json={"ip": "192.168.1.20", "consent": True},
        headers=user_headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["available"] is True
    assert data["cves"] == []
    assert data["cve_lookup_unavailable"] is False  # distinct from "unavailable"


def test_deep_scan_cve_source_down_flags_unavailable(client, user_headers, monkeypatch):
    cve_lookup._reset_cache()
    monkeypatch.setattr(cve_lookup, "_MIN_SPACING_S", 0.0)
    monkeypatch.setattr(scanner, "run_nmap", lambda ip, timeout: (NMAP_XML, None))
    monkeypatch.setattr(
        cve_lookup, "fetch_nvd",
        lambda product, version, timeout, api_key: (None, "NVD unreachable: timeout"),
    )
    resp = client.post(
        "/api/live/deep-scan",
        json={"ip": "10.1.2.3", "consent": True},
        headers=user_headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["available"] is True  # the nmap scan itself succeeded
    assert data["cve_lookup_unavailable"] is True  # but CVE matching couldn't run
    assert data["cves"] == []


# ── gates: auth / consent / RFC1918 ──────────────────────────────────────────
def test_scanned_device_joins_an_attack_path(db_session):
    """A deep-scanned vulnerable device must wire into the topology under the
    discovered gateway so the engine traces INTERNET → gateway → device."""
    from sqlalchemy import select

    from app.models import Asset, AttackPathStep, Connection, NetworkDevice, Organization
    from app.services.deepscan import integration

    org = Organization(name="lan", slug="lan")
    db_session.add(org)
    db_session.flush()
    # the device sweep found the gateway
    db_session.add(NetworkDevice(org_id=org.id, mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.1", is_gateway=True))
    db_session.flush()

    scan = {
        "available": True, "target": "192.168.1.50", "up": True, "os": None,
        "services": [{"port": 5432, "protocol": "tcp", "service_name": "postgresql",
                      "product": "PostgreSQL", "version": "14.2"}],
    }
    cve_result = {"available": True, "reason": None, "cves": [
        {"id": "CVE-2024-9999", "cvss": 9.1, "severity": "critical",
         "summary": "RCE", "exploitability": 0.9, "affected_service": "PostgreSQL 14.2", "port": 5432},
    ]}
    applied = integration.apply_scan(db_session, org.id, "192.168.1.50", scan, cve_result)
    db_session.commit()

    assert applied["top_path_formed"] is True
    assert applied["risk_score"] and applied["risk_score"] > 0
    dev = db_session.scalar(select(Asset).where(Asset.ip == "192.168.1.50"))
    assert dev.asset_type == "database"  # inferred from the DB port
    assert dev.criticality == "critical"  # from the critical CVE
    # a real edge gateway → device exists
    gw = db_session.scalar(select(Asset).where(Asset.ip == "192.168.1.1"))
    assert gw.internet_facing is True
    edge = db_session.scalar(
        select(Connection).where(Connection.from_asset_id == gw.id, Connection.to_asset_id == dev.id)
    )
    assert edge is not None
    # the path actually traverses the device
    step = db_session.scalar(select(AttackPathStep).where(AttackPathStep.asset_id == dev.id))
    assert step is not None


def test_deep_scan_requires_auth(client):
    resp = client.post("/api/live/deep-scan", json={"ip": "10.0.0.5", "consent": True})
    assert resp.status_code == 401


def test_deep_scan_rejects_without_consent(client, user_headers, monkeypatch):
    _mock_scan_pipeline(monkeypatch)
    resp = client.post(
        "/api/live/deep-scan",
        json={"ip": "10.0.0.5", "consent": False},
        headers=user_headers,
    )
    assert resp.status_code == 422
    assert "consent" in resp.text.lower()


def test_deep_scan_rejects_public_ip(client, user_headers, monkeypatch):
    _mock_scan_pipeline(monkeypatch)
    resp = client.post(
        "/api/live/deep-scan",
        json={"ip": "8.8.8.8", "consent": True},
        headers=user_headers,
    )
    assert resp.status_code == 422
    assert "private" in resp.text.lower() or "public" in resp.text.lower()


def test_deep_scan_rejects_garbage_ip(client, user_headers, monkeypatch):
    _mock_scan_pipeline(monkeypatch)
    resp = client.post(
        "/api/live/deep-scan",
        json={"ip": "not-an-ip", "consent": True},
        headers=user_headers,
    )
    assert resp.status_code == 422


# ── subnet / range scan ──────────────────────────────────────────────────────
# a real-shaped multi-host `nmap -sV` run (two hosts, one open port each)
MULTI_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.11" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

# a real-shaped `nmap -sn` discovery run (three hosts up)
DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="192.168.1.11" addrtype="ipv4"/></host>
  <host><status state="down"/><address addr="192.168.1.12" addrtype="ipv4"/></host>
</nmaprun>"""


def test_parser_multi_host():
    from app.services.deepscan.parser import parse_hosts, parse_live_ips

    hosts = parse_hosts(MULTI_XML)
    assert [h["ip"] for h in hosts] == ["192.168.1.10", "192.168.1.11"]
    assert hosts[0]["services"][0]["product"] == "Apache httpd"
    # discovery parser returns only 'up' hosts
    assert parse_live_ips(DISCOVERY_XML) == ["192.168.1.10", "192.168.1.11"]


def _mock_range_pipeline(monkeypatch):
    cve_lookup._reset_cache()
    monkeypatch.setattr(cve_lookup, "_MIN_SPACING_S", 0.0)
    monkeypatch.setattr(scanner, "run_nmap_discovery", lambda cidr, timeout: (DISCOVERY_XML, None))
    monkeypatch.setattr(scanner, "run_nmap_multi", lambda ips, timeout, host_timeout_s: (MULTI_XML, None))
    monkeypatch.setattr(
        cve_lookup, "fetch_nvd",
        lambda product, version, timeout, api_key: (
            (NVD_PAYLOAD, None) if "apache" in product.lower() else ({"vulnerabilities": []}, None)
        ),
    )


def test_deep_scan_range_creates_assets_and_scores(client, user_headers, monkeypatch):
    _mock_range_pipeline(monkeypatch)
    resp = client.post(
        "/api/live/deep-scan-range",
        json={"cidr": "192.168.1.0/24", "consent": True},
        headers=user_headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["available"] is True
    assert data["hosts_discovered"] == 2
    assert data["hosts_scanned"] == 2
    ips = {h["target"] for h in data["hosts"]}
    assert ips == {"192.168.1.10", "192.168.1.11"}
    for h in data["hosts"]:
        assert h["available"] is True
        assert h["risk_score"] is not None and h["risk_score"] > 0  # real engine output
    apache_host = next(h for h in data["hosts"] if h["target"] == "192.168.1.10")
    assert apache_host["cves"][0]["id"] == "CVE-2021-41773"
    assert apache_host["cves"][0]["finding_id"]


def test_deep_scan_range_respects_host_cap(client, user_headers, monkeypatch):
    _mock_range_pipeline(monkeypatch)
    # force a hard total ceiling of 1 via the (lru-cached) settings singleton
    from app.config import get_settings

    get_settings().deepscan_max_total_hosts = 1
    try:
        resp = client.post(
            "/api/live/deep-scan-range",
            json={"cidr": "192.168.1.0/24", "consent": True},
            headers=user_headers,
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["capped"] is True
        assert data["host_cap"] == 1
        assert data["hosts_scanned"] == 1  # only the ceiling's worth scanned
    finally:
        get_settings().deepscan_max_total_hosts = 256


def test_deep_scan_range_batches_scan_all_hosts(client, user_headers, monkeypatch):
    """With a small batch size, ALL discovered hosts still get scanned (batched)."""
    _mock_range_pipeline(monkeypatch)
    from app.config import get_settings

    get_settings().deepscan_max_hosts = 1  # 1 host per nmap run → 2 batches
    try:
        resp = client.post(
            "/api/live/deep-scan-range",
            json={"cidr": "192.168.1.0/24", "consent": True},
            headers=user_headers,
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["hosts_discovered"] == 2
        assert data["hosts_scanned"] == 2  # both, despite batch size 1
        assert data["capped"] is False
        assert {h["target"] for h in data["hosts"]} == {"192.168.1.10", "192.168.1.11"}
    finally:
        get_settings().deepscan_max_hosts = 32


def test_deep_scan_range_discovery_down_is_unavailable(client, user_headers, monkeypatch):
    monkeypatch.setattr(scanner, "run_nmap_discovery", lambda cidr, timeout: (None, "nmap is not installed on the server"))
    resp = client.post(
        "/api/live/deep-scan-range",
        json={"cidr": "10.0.0.0/24", "consent": True},
        headers=user_headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["available"] is False
    assert data["hosts"] == []  # no fabricated hosts
    assert "nmap" in data["unavailable_reason"]


def test_deep_scan_range_no_live_hosts_is_truthful(client, user_headers, monkeypatch):
    empty_disc = '<?xml version="1.0"?><nmaprun></nmaprun>'
    monkeypatch.setattr(scanner, "run_nmap_discovery", lambda cidr, timeout: (empty_disc, None))
    resp = client.post(
        "/api/live/deep-scan-range",
        json={"cidr": "10.0.0.0/24", "consent": True},
        headers=user_headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["available"] is True
    assert data["hosts_discovered"] == 0
    assert data["hosts"] == []


def test_deep_scan_range_requires_auth(client):
    resp = client.post("/api/live/deep-scan-range", json={"cidr": "192.168.1.0/24", "consent": True})
    assert resp.status_code == 401


def test_deep_scan_range_rejects_without_consent(client, user_headers):
    resp = client.post(
        "/api/live/deep-scan-range",
        json={"cidr": "192.168.1.0/24", "consent": False},
        headers=user_headers,
    )
    assert resp.status_code == 422
    assert "consent" in resp.text.lower()


def test_deep_scan_range_rejects_public_cidr(client, user_headers):
    resp = client.post(
        "/api/live/deep-scan-range",
        json={"cidr": "8.8.0.0/24", "consent": True},
        headers=user_headers,
    )
    assert resp.status_code == 422
    assert "private" in resp.text.lower() or "public" in resp.text.lower()


def test_deep_scan_range_rejects_oversized(client, user_headers):
    resp = client.post(
        "/api/live/deep-scan-range",
        json={"cidr": "10.0.0.0/8", "consent": True},
        headers=user_headers,
    )
    assert resp.status_code == 422
    assert "large" in resp.text.lower() or "too" in resp.text.lower()
