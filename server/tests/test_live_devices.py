# Drishti v0.1 — per-subnet device pruning tests | 18-Jul-2026
"""observe_devices() must prune strictly within the subnets a batch observed:
K agents on K subnets never delete each other's rows, off-link (MAC-less)
devices dedupe on (org, subnet, ip), and legacy batches (no subnet field)
fall back to an inferred /24 that is marked as inferred."""
import pytest

from app.models import NetworkCoverage, NetworkDevice, Organization
from app.schemas.live import DeviceBatch, DeviceIn
from app.services import live


def _org(db, slug="acme-live"):
    o = Organization(name=slug, slug=slug)
    db.add(o)
    db.flush()
    return o


def _batch(subnet, devices, *, gateway_ip=None, agent_id=None, label=None):
    return DeviceBatch(
        devices=[DeviceIn(**d) for d in devices],
        subnet=subnet, gateway_ip=gateway_ip, agent_id=agent_id, label=label,
    )


def _rows(db, org):
    return db.query(NetworkDevice).filter(NetworkDevice.org_id == org.id).all()


def test_two_subnets_do_not_prune_each_other(db_session):
    org = _org(db_session)
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.1", "mac": "aa:00:00:00:00:01"},
        {"ip": "192.168.1.50", "mac": "aa:00:00:00:00:02"},
    ], gateway_ip="192.168.1.1"))
    live.observe_devices(db_session, org.id, _batch("10.0.5.0/24", [
        {"ip": "10.0.5.1", "mac": "bb:00:00:00:00:01"},
        {"ip": "10.0.5.50", "mac": "bb:00:00:00:00:02"},
    ], gateway_ip="10.0.5.1"))

    rows = _rows(db_session, org)
    assert len(rows) == 4
    subnets = {r.subnet for r in rows}
    assert subnets == {"192.168.1.0/24", "10.0.5.0/24"}
    # second batch must not have flipped the first subnet's rows offline
    assert all(r.online for r in rows)


@pytest.mark.parametrize("k", [1, 2, 5])
def test_k_subnets_no_cross_deletion(db_session, k):
    org = _org(db_session)
    for i in range(k):
        live.observe_devices(db_session, org.id, _batch(f"10.{i}.0.0/24", [
            {"ip": f"10.{i}.0.1", "mac": f"aa:00:00:00:0{i}:01"},
            {"ip": f"10.{i}.0.2", "mac": f"aa:00:00:00:0{i}:02"},
        ]))
    assert len(_rows(db_session, org)) == 2 * k
    # re-run the first agent's sweep — every other subnet must be untouched
    live.observe_devices(db_session, org.id, _batch("10.0.0.0/24", [
        {"ip": "10.0.0.1", "mac": "aa:00:00:00:00:01"},
        {"ip": "10.0.0.2", "mac": "aa:00:00:00:00:02"},
    ]))
    assert len(_rows(db_session, org)) == 2 * k


def test_rerun_prunes_only_own_subnet_stale_rows(db_session):
    org = _org(db_session)
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.10", "mac": "aa:00:00:00:00:01"},
        {"ip": "192.168.1.11", "mac": "aa:00:00:00:00:02"},
    ]))
    live.observe_devices(db_session, org.id, _batch("10.0.5.0/24", [
        {"ip": "10.0.5.10", "mac": "bb:00:00:00:00:01"},
    ]))
    # device .11 gone from the re-swept subnet → offline; other subnet untouched
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.10", "mac": "aa:00:00:00:00:01"},
    ]))
    rows = {r.mac: r for r in _rows(db_session, org)}
    assert rows["aa:00:00:00:00:02"].online is False
    assert rows["bb:00:00:00:00:01"].online is True


def test_idempotent_same_batch_twice(db_session):
    org = _org(db_session)
    batch = _batch("192.168.1.0/24", [
        {"ip": "192.168.1.1", "mac": "aa:00:00:00:00:01"},
        {"ip": "192.168.1.50", "mac": "aa:00:00:00:00:02"},
    ], gateway_ip="192.168.1.1")
    r1 = live.observe_devices(db_session, org.id, batch)
    r2 = live.observe_devices(db_session, org.id, batch)
    assert r1.total == r2.total == 2
    assert r2.new == 0
    rows = _rows(db_session, org)
    assert len(rows) == 2
    assert all(r.online for r in rows)


def test_offlink_mac_none_dedupe_and_distinct_subnets(db_session):
    org = _org(db_session)
    # two L3-discovered hosts, no MACs — must NOT collapse into one row
    live.observe_devices(db_session, org.id, _batch("10.0.5.0/24", [
        {"ip": "10.0.5.50", "mac": None, "discovery": "l3"},
        {"ip": "10.0.5.51", "mac": None, "discovery": "l3"},
    ]))
    rows = _rows(db_session, org)
    assert len(rows) == 2
    assert all(r.mac is None and r.discovery == "l3" for r in rows)

    # same batch again → still 2 (deduped on org+subnet+ip)
    live.observe_devices(db_session, org.id, _batch("10.0.5.0/24", [
        {"ip": "10.0.5.50", "mac": None, "discovery": "l3"},
        {"ip": "10.0.5.51", "mac": None, "discovery": "l3"},
    ]))
    assert len(_rows(db_session, org)) == 2

    # same last octet on a different subnet stays a distinct row
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.50", "mac": None, "discovery": "l3"},
    ]))
    ips = {(r.subnet, r.ip) for r in _rows(db_session, org)}
    assert ("10.0.5.0/24", "10.0.5.50") in ips
    assert ("192.168.1.0/24", "192.168.1.50") in ips


def test_legacy_batch_infers_slash24_marked_inferred(db_session):
    org = _org(db_session)
    # old agent: no subnet anywhere in the payload
    live.observe_devices(db_session, org.id, DeviceBatch(devices=[
        DeviceIn(ip="192.168.1.7", mac="aa:00:00:00:00:07"),
    ]))
    row = _rows(db_session, org)[0]
    assert row.subnet == "192.168.1.0/24"
    assert row.subnet_inferred is True

    # observed subnet from a new agent overrides the inference
    live.observe_devices(db_session, org.id, _batch("192.168.0.0/22", [
        {"ip": "192.168.1.7", "mac": "aa:00:00:00:00:07"},
    ]))
    row = _rows(db_session, org)[0]
    assert row.subnet == "192.168.0.0/22"
    assert row.subnet_inferred is False


def test_backfill_marks_legacy_rows_inferred(db_session):
    org = _org(db_session)
    db_session.add(NetworkDevice(org_id=org.id, ip="172.16.3.9", mac="aa:00:00:00:00:09"))
    db_session.commit()
    n = live.backfill_device_subnets(db_session)
    assert n == 1
    row = _rows(db_session, org)[0]
    assert row.subnet == "172.16.3.0/24"
    assert row.subnet_inferred is True
    # idempotent
    assert live.backfill_device_subnets(db_session) == 0


def test_coverage_marks_swept_subnets_inventoried(db_session):
    org = _org(db_session)
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.1", "mac": "aa:00:00:00:00:01"},
        {"ip": "192.168.1.2", "mac": "aa:00:00:00:00:02"},
    ], gateway_ip="192.168.1.1", agent_id="agent-1", label="Floor-3"))
    cov = db_session.query(NetworkCoverage).filter(
        NetworkCoverage.org_id == org.id).all()
    assert len(cov) == 1
    c = cov[0]
    assert c.subnet == "192.168.1.0/24"
    assert c.status == "inventoried"
    assert c.device_count == 2
    assert c.gateway_ip == "192.168.1.1"
    assert c.label == "Floor-3"
    assert "agent-1" in c.evidence

    out = live.list_coverage(db_session, org.id)
    assert len(out) == 1 and out[0].status == "inventoried"


def test_coverage_endpoint_seen_vs_inventoried(client, user_headers, agent_headers):
    # agent sweeps one subnet (inventoried) and reports two it could not cover
    client.post("/api/live/devices", headers=agent_headers, json={
        "devices": [{"ip": "192.168.1.1", "mac": "aa:00:00:00:00:01",
                     "subnet": "192.168.1.0/24"}],
        "subnet": "192.168.1.0/24", "gateway_ip": "192.168.1.1", "agent_id": "a1",
    })
    client.post("/api/live/coverage", headers=agent_headers, json={"networks": [
        {"ssid": "Floor-3-Guest", "subnet": None, "status": "seen_not_joined",
         "evidence": "beacon"},
        {"subnet": "10.9.0.0/24", "status": "unreachable", "evidence": "route, no reply"},
    ]})
    rows = client.get("/api/live/coverage", headers=user_headers).json()
    by_status = {}
    for r in rows:
        by_status.setdefault(r["status"], 0)
        by_status[r["status"]] += 1
    assert by_status.get("inventoried") == 1
    assert by_status.get("seen_not_joined") == 1
    assert by_status.get("unreachable") == 1
