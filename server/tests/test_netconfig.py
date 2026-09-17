# Drishti v0.1 — network-config detector tests (offline, deterministic) | 12-Jul-2026
"""Detectors reason over real observed topology / declared config. Tests build
controlled topologies in-memory so every assertion is deterministic. Covers:
a DMZ host reaching a crown-jewel → high/critical DMZ finding; a segmented one →
none; an internet-exposed internal host → NAT finding; missing DHCP data →
'unknown' (never fabricated); findings changing the engine risk score; and the
endpoint's auth + consent gates."""
from decimal import Decimal

from app.models import Asset, Connection, Organization, RiskZone, Service
from app.schemas.netconfig import NetconfigInput, PortForward
from app.services.netconfig import service


def _svc(db, org, asset, port, name):
    db.add(Service(org_id=org.id, asset_id=asset.id, port=port, protocol="tcp", name=name))
    db.flush()


def _org(db, slug: str) -> Organization:
    org = Organization(name=slug, slug=slug)
    db.add(org)
    db.flush()
    return org


def _zone(db, org, name, kind) -> RiskZone:
    z = RiskZone(org_id=org.id, name=name, kind=kind)
    db.add(z)
    db.flush()
    return z


def _asset(db, org, zone, hostname, ip, *, criticality="medium", internet=False,
           atype="server", value=10000) -> Asset:
    a = Asset(
        org_id=org.id, zone_id=zone.id, hostname=hostname, ip=ip,
        asset_type=atype, criticality=criticality,
        business_value=Decimal(str(value)), internet_facing=internet,
    )
    db.add(a)
    db.flush()
    return a


def _conn(db, org, src, dst, relation="network"):
    db.add(Connection(org_id=org.id, from_asset_id=src.id, to_asset_id=dst.id, relation=relation))
    db.flush()


def _broken_dmz_topology(db, slug="broken"):
    """DMZ host with a route into a crown-jewel DB (broken segmentation)."""
    org = _org(db, slug)
    dmz = _zone(db, org, "DMZ", "dmz")
    data = _zone(db, org, "Data", "crown_jewel")
    web = _asset(db, org, dmz, "edge-web", "10.9.0.10", internet=True, atype="webapp")
    dbp = _asset(db, org, data, "vault-db", "10.9.3.10", criticality="critical",
                 atype="database", value=3_000_000)
    _conn(db, org, web, dbp, "network")  # the broken link: DMZ → crown jewel
    return org, web, dbp


def _segmented_topology(db, slug="segmented"):
    """Same assets but NO DMZ→crown-jewel connection (properly segmented)."""
    org = _org(db, slug)
    dmz = _zone(db, org, "DMZ", "dmz")
    data = _zone(db, org, "Data", "crown_jewel")
    _asset(db, org, dmz, "edge-web", "10.8.0.10", internet=True, atype="webapp")
    _asset(db, org, data, "vault-db", "10.8.3.10", criticality="critical", atype="database")
    return org


# ── DMZ segmentation ─────────────────────────────────────────────────────────
def test_dmz_reaching_crownjewel_is_a_finding(db_session):
    org, web, dbp = _broken_dmz_topology(db_session)
    out = service.analyze(db_session, org.id, consent=True, config=None)
    dmz = [f for f in out.findings if f.category == "DMZ" and f.status == "real"]
    assert dmz, "expected a DMZ segmentation finding"
    seg = next(f for f in dmz if "can reach" in f.title)
    assert seg.severity == "critical"  # reaches a crown jewel
    assert "edge-web" in " ".join(seg.affected)
    assert seg.finding_id  # maps into remediation


def test_segmented_dmz_has_no_finding(db_session):
    org = _segmented_topology(db_session)
    out = service.analyze(db_session, org.id, consent=True, config=None)
    seg = [f for f in out.findings if f.category == "DMZ" and "can reach" in f.title]
    assert seg == []  # no DMZ→internal reachability → no fabricated finding


def test_dmz_finding_changes_engine_risk_and_path(db_session):
    org, web, dbp = _broken_dmz_topology(db_session)
    # baseline recompute (no config findings yet)
    from app.services.recompute import recompute_org

    recompute_org(db_session, org.id)
    db_session.flush()
    db_session.refresh(web)
    before = float(web.risk_score or 0)

    service.analyze(db_session, org.id, consent=True, config=None)
    db_session.refresh(web)
    after = float(web.risk_score or 0)
    assert after > before, f"config finding should raise the DMZ host risk ({before} → {after})"

    # the config finding created an engine finding → an attack path now exists to the crown jewel
    from app.models import AttackPath

    paths = db_session.scalars(
        __import__("sqlalchemy").select(AttackPath).where(AttackPath.org_id == org.id)
    ).all()
    assert paths, "an attack path should form to the crown jewel"


# ── NAT / exposure ───────────────────────────────────────────────────────────
def test_internal_host_internet_exposed_is_nat_finding(db_session):
    org = _org(db_session, "exposed")
    internal = _zone(db_session, org, "App", "internal")
    _asset(db_session, org, internal, "app-01", "10.7.2.10", criticality="high", internet=True)
    out = service.analyze(db_session, org.id, consent=True, config=None)
    nat = [f for f in out.findings if f.category == "NAT" and f.status == "real"
           and "exposed to the internet" in f.title]
    assert nat, "internet-facing internal host should raise a NAT/exposure finding"
    assert nat[0].severity == "high"


def test_correctly_natted_internal_host_has_no_exposure_finding(db_session):
    org = _org(db_session, "natted")
    internal = _zone(db_session, org, "App", "internal")
    _asset(db_session, org, internal, "app-01", "10.6.2.10", criticality="high", internet=False)
    out = service.analyze(db_session, org.id, consent=True, config=None)
    nat = [f for f in out.findings if f.category == "NAT" and f.status == "real"
           and "exposed" in f.title]
    assert nat == []


def test_scanned_sensitive_ports_produce_real_findings_without_zones(db_session):
    # a real user org: scanned devices, NO zone topology
    org = _org(db_session, "scanned")
    nas = _asset(db_session, org, _zone(db_session, org, "Net", "internal"), "nas", "10.1.9.10")
    # (zone here is just to satisfy _asset; the finding is port-driven, not zone-driven)
    _svc(db_session, org, nas, 5432, "postgresql")
    _svc(db_session, org, nas, 22, "ssh")  # SSH on LAN → expected, must NOT flag
    _svc(db_session, org, nas, 3389, "rdp")
    out = service.analyze(db_session, org.id, consent=True, config=None)
    nat = [f for f in out.findings if f.category == "NAT" and f.status == "real"]
    titles = " | ".join(f.title for f in nat)
    assert "PostgreSQL port 5432" in titles  # DB port exposed → real finding
    assert "RDP port 3389" in titles
    assert "SSH" not in titles  # SSH on LAN is expected, not flagged
    assert all(f.finding_id for f in nat)  # each maps into remediation
    assert next(f for f in nat if "5432" in f.title).severity == "high"


def test_no_zones_reports_dmz_unknown(db_session):
    org = _org(db_session, "nozones")
    a = Asset(org_id=org.id, hostname="h", ip="10.1.8.5", asset_type="server",
              criticality="medium", business_value=Decimal("10000"), internet_facing=False)
    db_session.add(a)
    db_session.flush()
    out = service.analyze(db_session, org.id, consent=True, config=None)
    dmz = [f for f in out.findings if f.category == "DMZ"]
    assert len(dmz) == 1 and dmz[0].status == "unknown"  # honest, not a silent nothing


def test_port_forward_to_db_port_is_critical(db_session):
    org = _org(db_session, "forward")
    internal = _zone(db_session, org, "App", "internal")
    _asset(db_session, org, internal, "db-01", "10.5.2.10", criticality="high", atype="database")
    cfg = NetconfigInput(port_forwards=[PortForward(external_port=5432, internal_ip="10.5.2.10", internal_port=5432)])
    out = service.analyze(db_session, org.id, consent=True, config=cfg)
    pf = [f for f in out.findings if f.category == "NAT" and "PostgreSQL" in f.title]
    assert pf and pf[0].severity == "critical" and pf[0].source == "declared"


# ── DHCP ─────────────────────────────────────────────────────────────────────
def test_dhcp_missing_data_is_unknown_not_fabricated(db_session):
    org = _org(db_session, "nodhcp")
    internal = _zone(db_session, org, "App", "internal")
    _asset(db_session, org, internal, "app-01", "10.4.2.10")
    out = service.analyze(db_session, org.id, consent=True, config=None)
    dhcp = [f for f in out.findings if f.category == "DHCP"]
    assert len(dhcp) == 1
    assert dhcp[0].status == "unknown"  # NOT 'passed', NOT 'real'
    assert dhcp[0].severity == "none"
    assert dhcp[0].finding_id is None  # unknown never maps into the engine


def test_dhcp_multiple_responders_is_rogue_finding(db_session):
    org = _org(db_session, "rogue")
    internal = _zone(db_session, org, "App", "internal")
    _asset(db_session, org, internal, "app-01", "10.3.2.10")
    cfg = NetconfigInput(dhcp_servers=["10.3.2.1", "10.3.2.66"])
    out = service.analyze(db_session, org.id, consent=True, config=cfg)
    dhcp = [f for f in out.findings if f.category == "DHCP" and f.status == "real"]
    assert dhcp and "rogue" in dhcp[0].title.lower()


def test_dhcp_single_gateway_server_passes(db_session):
    org = _org(db_session, "okdhcp")
    internal = _zone(db_session, org, "App", "internal")
    _asset(db_session, org, internal, "app-01", "10.2.2.10")
    cfg = NetconfigInput(dhcp_servers=["10.2.2.1"], gateway_ip="10.2.2.1")
    out = service.analyze(db_session, org.id, consent=True, config=cfg)
    dhcp = [f for f in out.findings if f.category == "DHCP"]
    assert dhcp and dhcp[0].status == "passed"


# ── endpoint gates ───────────────────────────────────────────────────────────
def test_netconfig_requires_auth(client):
    resp = client.post("/api/netconfig/analyze", json={"consent": True})
    assert resp.status_code == 401


def test_netconfig_rejects_without_consent(client, user_headers):
    resp = client.post("/api/netconfig/analyze", json={"consent": False}, headers=user_headers)
    assert resp.status_code == 422
    assert "consent" in resp.text.lower()


def test_netconfig_endpoint_runs_on_seed(client, user_headers):
    # the seeded Acme topology has web-app-01 (DMZ) reaching db-prod-01 (crown jewel)
    resp = client.post("/api/netconfig/analyze", json={"consent": True}, headers=user_headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["available"] is True
    cats = {f["category"] for f in data["findings"]}
    assert "DMZ" in cats
    assert any(f["category"] == "DMZ" and f["status"] == "real" for f in data["findings"])
    # last() replays it
    again = client.get("/api/netconfig/last", headers=user_headers)
    assert again.status_code == 200
    assert again.json()["available"] is True