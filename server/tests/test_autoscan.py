# Drishti v0.1 — autonomous scanner tests (offline, deterministic) | 12-Jul-2026
"""The deep-scan itself is mocked, so no nmap/NVD runs. Asserts: the scheduler
respects the consent/authorization scope (self-only until scan_subnet is on),
round-robins across devices, marks unscanned devices as unscanned (never 0), and
reflects the real matched-CVE count once scanned."""
from decimal import Decimal

from app.models import Asset, AssetVulnerability, NetworkDevice, Organization, Vulnerability
from app.services import autoscan, live


def _org(db, slug):
    o = Organization(name=slug, slug=slug)
    db.add(o)
    db.flush()
    return o


def _dev(db, org, ip, mac, *, is_self=False, is_gateway=False, online=True):
    d = NetworkDevice(org_id=org.id, ip=ip, mac=mac, is_self=is_self,
                      is_gateway=is_gateway, online=online)
    db.add(d)
    db.flush()
    return d


class _FakeResult:
    available = True


def _fake_scan(calls):
    def fn(db, org_id, ip, consent):
        assert consent is True  # autonomous scans always pass explicit consent
        calls.append(ip)
        return _FakeResult()
    return fn


# ── consent scope ────────────────────────────────────────────────────────────
def test_scope_self_only_until_subnet_authorized(db_session):
    org = _org(db_session, "scope")
    _dev(db_session, org, "192.168.1.40", "aa:1", is_self=True)
    _dev(db_session, org, "192.168.1.1", "aa:2", is_gateway=True)
    _dev(db_session, org, "192.168.1.55", "aa:3")
    db_session.flush()

    cfg = autoscan.get_config(db_session, org.id)
    # default: not authorized to scan the subnet → only THIS host is eligible
    assert [d.ip for d in autoscan.eligible_devices(db_session, org.id, cfg)] == ["192.168.1.40"]

    autoscan.update_config(db_session, org.id, scan_subnet=True)
    cfg = autoscan.get_config(db_session, org.id)
    ips = [d.ip for d in autoscan.eligible_devices(db_session, org.id, cfg)]
    assert ips == ["192.168.1.1", "192.168.1.40", "192.168.1.55"]  # whole subnet, sorted


def test_disabled_autoscan_scans_nothing(db_session):
    org = _org(db_session, "off")
    _dev(db_session, org, "192.168.1.40", "aa:1", is_self=True)
    calls: list[str] = []
    out = autoscan.run_once(db_session, org.id, deep_scan_fn=_fake_scan(calls))
    assert out["scanned"] is False and calls == []


def test_round_robin_advances_across_devices(db_session):
    org = _org(db_session, "rr")
    _dev(db_session, org, "192.168.1.10", "a")
    _dev(db_session, org, "192.168.1.11", "b")
    _dev(db_session, org, "192.168.1.12", "c")
    autoscan.update_config(db_session, org.id, enabled=True, scan_subnet=True)
    calls: list[str] = []
    fn = _fake_scan(calls)
    for _ in range(4):
        autoscan.run_once(db_session, org.id, deep_scan_fn=fn)
    # one device per tick, round-robin, wrapping after the third
    assert calls == ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.10"]


def test_run_once_marks_last_scanned(db_session):
    org = _org(db_session, "mark")
    d = _dev(db_session, org, "192.168.1.40", "aa:1", is_self=True)
    autoscan.update_config(db_session, org.id, enabled=True)
    assert d.last_scanned_at is None
    autoscan.run_once(db_session, org.id, deep_scan_fn=_fake_scan([]))
    db_session.refresh(d)
    assert d.last_scanned_at is not None


# ── vuln count + unscanned marking ───────────────────────────────────────────
def _scanned_asset_with_cves(db, org, ip, sevs):
    a = Asset(org_id=org.id, ip=ip, asset_type="server", criticality="medium",
              business_value=Decimal("10000"), internet_facing=False)
    db.add(a)
    db.flush()
    from app.models import DeepScan

    db.add(DeepScan(org_id=org.id, asset_id=a.id, target_ip=ip, available=True, result_json={}))
    for i, sev in enumerate(sevs):
        v = Vulnerability(cve_id=f"CVE-X-{ip}-{i}", title="t", cvss=Decimal("7.0"), severity=sev,
                          exploitability=Decimal("0.5"))
        db.add(v)
        db.flush()
        db.add(AssetVulnerability(org_id=org.id, asset_id=a.id, vulnerability_id=v.id, status="open"))
    db.flush()


def test_device_list_counts_and_unscanned(db_session):
    org = _org(db_session, "counts")
    # device A: deep-scanned, 2 CVEs (worst = high)
    _dev(db_session, org, "10.0.0.5", "m1")
    _scanned_asset_with_cves(db_session, org, "10.0.0.5", ["high", "medium"])
    # device B: deep-scanned, no CVEs → real 0
    _dev(db_session, org, "10.0.0.6", "m2")
    _scanned_asset_with_cves(db_session, org, "10.0.0.6", [])
    # device C: never scanned → must be "not scanned", NOT 0
    _dev(db_session, org, "10.0.0.7", "m3")
    db_session.commit()

    devices = {d.ip: d for d in live.list_devices(db_session, org.id)}
    assert devices["10.0.0.5"].scanned is True
    assert devices["10.0.0.5"].vuln_count == 2
    assert devices["10.0.0.5"].worst_severity == "high"
    assert devices["10.0.0.6"].scanned is True
    assert devices["10.0.0.6"].vuln_count == 0  # real "no CVEs found"
    assert devices["10.0.0.7"].scanned is False
    assert devices["10.0.0.7"].vuln_count is None  # unscanned != 0


# ── endpoint gates ───────────────────────────────────────────────────────────
def test_autoscan_endpoint_requires_auth(client):
    assert client.get("/api/live/autoscan").status_code == 401
    assert client.put("/api/live/autoscan", json={"enabled": True}).status_code == 401


def test_autoscan_config_roundtrip(client, user_headers):
    r = client.get("/api/live/autoscan", headers=user_headers)
    assert r.status_code == 200
    assert r.json()["enabled"] is False  # off by default
    r2 = client.put("/api/live/autoscan", json={"enabled": True, "scan_subnet": True,
                                                "interval_seconds": 600}, headers=user_headers)
    assert r2.status_code == 200
    body = r2.json()
    assert body["enabled"] is True and body["scan_subnet"] is True and body["interval_seconds"] == 600
