# Drishti v0.1 — per-device presence session tests | Phase 4 Validation
"""Comprehensive test suite for Drishti's Device History Engine:
- Scenario 1: New device (duration=0, presence_state="new")
- Scenario 2: Continuous device across short intervals
- Scenario 3: 1 hour continuous presence (<=5 min gaps)
- Scenario 4: 24 hour continuous presence deterministic simulation
- Scenario 5: Short gap within MAX_OBSERVATION_GAP
- Scenario 6: Gap > 5 minutes closes previous session and starts new
- Scenario 7: Device returns after long absence (no gap inclusion)
- Scenario 8: Offline session closure matches last confirmed observation timestamp
- Scenario 9: Multiple devices independent session histories
- Scenario 10: Multiple networks (subnets) strict isolation
- Scenario 11: Randomized MAC addresses treated as independent identities
- Scenario 12: Missing / legacy history safe fallback
- Restart persistence across database reconnect
- Database growth check (single session row updated in place)
- Full API flow (POST and GET /api/live/devices)
"""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import DevicePresenceSession, NetworkDevice, Organization
from app.schemas.live import DeviceBatch, DeviceIn
from app.services import live


def _org(db, slug="test-sessions"):
    o = Organization(name=slug, slug=slug)
    db.add(o)
    db.flush()
    return o


def _batch(subnet, devices, *, gateway_ip=None, agent_id=None, label=None):
    return DeviceBatch(
        devices=[DeviceIn(**d) for d in devices],
        subnet=subnet,
        gateway_ip=gateway_ip,
        agent_id=agent_id,
        label=label,
    )


def _set_time(monkeypatch, dt):
    monkeypatch.setattr("app.models.base.utcnow", lambda: dt)
    monkeypatch.setattr("app.models.live.utcnow", lambda: dt)
    monkeypatch.setattr(live, "utcnow", lambda: dt)


def _aware(dt):
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


# =========================================================================
# TEST 1 — NEW DEVICE
# =========================================================================
def test_scenario_1_new_device(db_session, monkeypatch):
    """Observation at 10:00:00 with no previous history.
    Expected: session_count=1, observation_count=1, current_session_duration=0, presence_state='new'.
    UI semantics: '< 1 min (newly observed)'."""
    org = _org(db_session, "org-scen-1")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)
    _set_time(monkeypatch, t0)

    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:01", "discovery": "scapy", "source": "scapy"},
    ]))

    devs = live.list_devices(db_session, org.id)
    assert len(devs) == 1
    d = devs[0]
    assert d.session_count == 1
    assert d.observation_count == 1
    assert d.current_session_duration_seconds == 0.0
    assert d.total_observed_duration_seconds == 0.0
    assert d.presence_state == "new"
    assert d.observation_source == "scapy"


# =========================================================================
# TEST 2 — CONTINUOUS DEVICE
# =========================================================================
def test_scenario_2_continuous_device(db_session, monkeypatch):
    """Observations at 10:00, 10:01, 10:02, 10:03.
    Expected: 1 session, 4 observations, current duration ≈ 3 min (180s)."""
    org = _org(db_session, "org-scen-2")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(4):
        t = t0 + timedelta(minutes=i)
        _set_time(monkeypatch, t)
        live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
            {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:02", "source": "arp"},
        ]))

    # Must be exactly 1 session row
    sessions = db_session.scalars(
        select(DevicePresenceSession).where(DevicePresenceSession.org_id == org.id)
    ).all()
    assert len(sessions) == 1
    s = sessions[0]
    assert s.observation_count == 4
    assert s.is_current is True

    # At 10:03, duration is 180s (3m)
    devs = live.list_devices(db_session, org.id)
    assert len(devs) == 1
    d = devs[0]
    assert d.session_count == 1
    assert d.observation_count == 4
    assert d.current_session_duration_seconds == 180.0
    assert d.total_observed_duration_seconds == 180.0
    assert d.presence_state == "continuous"


# =========================================================================
# TEST 3 — 1 HOUR CONTINUOUS
# =========================================================================
def test_scenario_3_one_hour_continuous(db_session, monkeypatch):
    """Observations every 4 minutes from 10:00 to 11:00 (gaps <= 5 min).
    Expected: 1 session, current duration ≈ 60 min (3600s)."""
    org = _org(db_session, "org-scen-3")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)

    # 10:00, 10:04, 10:08, ..., 11:00 (16 observation sweeps)
    for step in range(16):
        t = t0 + timedelta(minutes=step * 4)
        _set_time(monkeypatch, t)
        live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
            {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:03", "source": "icmp"},
        ]))

    sessions = db_session.scalars(
        select(DevicePresenceSession).where(DevicePresenceSession.org_id == org.id)
    ).all()
    assert len(sessions) == 1
    assert sessions[0].observation_count == 16

    devs = live.list_devices(db_session, org.id)
    assert len(devs) == 1
    d = devs[0]
    assert d.session_count == 1
    assert d.observation_count == 16
    assert d.current_session_duration_seconds == 3600.0
    assert d.total_observed_duration_seconds == 3600.0
    assert d.presence_state == "continuous"


# =========================================================================
# TEST 4 — 24 HOUR CONTINUOUS
# =========================================================================
def test_scenario_4_twenty_four_hour_continuous(db_session, monkeypatch):
    """Simulate a full 24h history using deterministic timestamps (steps every 5 min).
    Expected: 1 session, current duration ≈ 24h (86400s)."""
    org = _org(db_session, "org-scen-4")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)

    # Step every 5 minutes for 24 hours = 289 steps (0 to 1440 min)
    for step in range(289):
        t = t0 + timedelta(minutes=step * 5)
        _set_time(monkeypatch, t)
        live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
            {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:04", "source": "scapy"},
        ]))

    sessions = db_session.scalars(
        select(DevicePresenceSession).where(DevicePresenceSession.org_id == org.id)
    ).all()
    assert len(sessions) == 1
    assert sessions[0].observation_count == 289

    devs = live.list_devices(db_session, org.id)
    assert len(devs) == 1
    d = devs[0]
    assert d.session_count == 1
    assert d.observation_count == 289
    assert d.current_session_duration_seconds == 86400.0
    assert d.total_observed_duration_seconds == 86400.0
    assert d.presence_state == "continuous"


# =========================================================================
# TEST 5 — SHORT GAP
# =========================================================================
def test_scenario_5_short_gap(db_session, monkeypatch):
    """Observations at 10:00, 10:04, 10:08 (gaps <= 5 min).
    Expected: 1 continuous session maintained."""
    org = _org(db_session, "org-scen-5")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)

    for offset in (0, 4, 8):
        _set_time(monkeypatch, t0 + timedelta(minutes=offset))
        live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
            {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:05"},
        ]))

    sessions = db_session.scalars(
        select(DevicePresenceSession).where(DevicePresenceSession.org_id == org.id)
    ).all()
    assert len(sessions) == 1
    assert sessions[0].observation_count == 3

    devs = live.list_devices(db_session, org.id)
    assert len(devs) == 1
    assert devs[0].current_session_duration_seconds == 480.0
    assert devs[0].presence_state == "continuous"


# =========================================================================
# TEST 6 — GAP > 5 MINUTES
# =========================================================================
def test_scenario_6_gap_greater_than_five_minutes(db_session, monkeypatch):
    """Session 1: 10:00, 10:04. Device absent. Reappears: 10:20 (gap = 16 min > 5 min).
    Expected: Session 1 ends at 10:04, Session 2 starts at 10:20, session_count=2.
    Continuous duration MUST NOT include 10:04 → 10:20."""
    org = _org(db_session, "org-scen-6")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)

    # 10:00
    _set_time(monkeypatch, t0)
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:06"},
    ]))

    # 10:04
    t1 = t0 + timedelta(minutes=4)
    _set_time(monkeypatch, t1)
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:06"},
    ]))

    # Device reappears at 10:20
    t2 = t0 + timedelta(minutes=20)
    _set_time(monkeypatch, t2)
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:06"},
    ]))

    sessions = db_session.scalars(
        select(DevicePresenceSession)
        .where(DevicePresenceSession.org_id == org.id)
        .order_by(DevicePresenceSession.started_at.asc())
    ).all()
    assert len(sessions) == 2
    s1, s2 = sessions[0], sessions[1]

    # Session 1 closed at 10:04
    assert s1.is_current is False
    assert _aware(s1.ended_at) == t1
    assert s1.observation_count == 2

    # Session 2 active at 10:20
    assert s2.is_current is True
    assert _aware(s2.started_at) == t2
    assert s2.observation_count == 1

    # In list_devices at 10:20:
    devs = live.list_devices(db_session, org.id)
    assert len(devs) == 1
    d = devs[0]
    assert d.session_count == 2
    assert d.observation_count == 3
    # Duration does NOT include the 16 min offline gap:
    assert d.current_session_duration_seconds == 0.0
    assert d.total_observed_duration_seconds == 240.0  # 4m from Session 1


# =========================================================================
# TEST 7 — DEVICE RETURNS AFTER LONG ABSENCE
# =========================================================================
def test_scenario_7_device_returns_after_long_absence(db_session, monkeypatch):
    """Session 1: 10:00 → 11:00 (1h = 3600s).
    Offline: 11:00 → 20:00 (9h offline).
    Session 2: 20:00, 20:05, 20:10 (10m = 600s).
    Expected: session_count=2, total observed ≈ 1h 10m (4200s), current session ≈ 10m (600s),
    NOT 10h 10m (36600s)."""
    org = _org(db_session, "org-scen-7")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)

    # Session 1: 10:00 to 11:00 (13 sweeps every 5 min)
    for step in range(13):
        t = t0 + timedelta(minutes=step * 5)
        _set_time(monkeypatch, t)
        live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
            {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:07"},
        ]))

    # Offline for 9 hours. Returns at 20:00, 20:05, 20:10
    t_ret = datetime(2026, 9, 17, 20, 0, 0, tzinfo=timezone.utc)
    for step in range(3):
        t = t_ret + timedelta(minutes=step * 5)
        _set_time(monkeypatch, t)
        live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
            {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:07"},
        ]))

    sessions = db_session.scalars(
        select(DevicePresenceSession)
        .where(DevicePresenceSession.org_id == org.id)
        .order_by(DevicePresenceSession.started_at.asc())
    ).all()
    assert len(sessions) == 2

    devs = live.list_devices(db_session, org.id)
    assert len(devs) == 1
    d = devs[0]
    assert d.session_count == 2
    assert d.current_session_duration_seconds == 600.0  # exactly 10 min
    assert d.total_observed_duration_seconds == 4200.0  # 1h + 10m = 4200s
    assert d.current_session_duration_seconds != 36600.0  # never includes offline 9 hours!


# =========================================================================
# TEST 8 — OFFLINE SESSION CLOSURE
# =========================================================================
def test_scenario_8_offline_session_closure(db_session, monkeypatch):
    """When a device disappears: ended_at must equal the last confirmed observation timestamp,
    NOT the current clock time."""
    org = _org(db_session, "org-scen-8")
    t0 = datetime(2026, 9, 17, 15, 42, 0, tzinfo=timezone.utc)
    _set_time(monkeypatch, t0)

    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.10", "mac": "aa:bb:cc:00:00:10"},
        {"ip": "192.168.1.20", "mac": "aa:bb:cc:00:00:20"},
    ]))

    # Device .20 disappears in sweep at 15:52 (10 min later)
    t1 = t0 + timedelta(minutes=10)
    _set_time(monkeypatch, t1)
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.10", "mac": "aa:bb:cc:00:00:10"},
    ]))

    s20 = db_session.scalar(
        select(DevicePresenceSession).where(
            DevicePresenceSession.org_id == org.id,
            DevicePresenceSession.device_key == "mac:aa:bb:cc:00:00:20",
        )
    )
    assert s20.is_current is False
    # ended_at must equal 15:42 (t0), NOT current sweep time 15:52 (t1)
    assert _aware(s20.ended_at) == t0
    assert _aware(s20.ended_at) != t1


# =========================================================================
# TEST 9 — MULTIPLE DEVICES
# =========================================================================
def test_scenario_9_multiple_devices_isolation(db_session, monkeypatch):
    """Device A, Device B, Device C maintain independent session histories.
    Observation updates for Device A do NOT affect Device B or C."""
    org = _org(db_session, "org-scen-9")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)

    # Initial discovery of A, B, C at 10:00
    _set_time(monkeypatch, t0)
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.11", "mac": "aa:bb:cc:00:00:0a"},
        {"ip": "192.168.1.12", "mac": "aa:bb:cc:00:00:0b"},
        {"ip": "192.168.1.13", "mac": "aa:bb:cc:00:00:0c"},
    ]))

    # Device A observed again at 10:02 and 10:04 (total 3 obs)
    for offset in (2, 4):
        _set_time(monkeypatch, t0 + timedelta(minutes=offset))
        live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
            {"ip": "192.168.1.11", "mac": "aa:bb:cc:00:00:0a"},
            {"ip": "192.168.1.12", "mac": "aa:bb:cc:00:00:0b"},
        ]))

    # Query all devices at 10:04
    devs = {d.mac: d for d in live.list_devices(db_session, org.id)}
    assert devs["aa:bb:cc:00:00:0a"].observation_count == 3
    assert devs["aa:bb:cc:00:00:0a"].current_session_duration_seconds == 240.0

    assert devs["aa:bb:cc:00:00:0b"].observation_count == 3
    assert devs["aa:bb:cc:00:00:0b"].current_session_duration_seconds == 240.0

    # Device C was not in the 10:02 and 10:04 sweeps, so it was marked offline
    # Verify C's session was closed and its observation_count remains 1
    sc = db_session.scalar(
        select(DevicePresenceSession).where(
            DevicePresenceSession.org_id == org.id,
            DevicePresenceSession.device_key == "mac:aa:bb:cc:00:00:0c",
        )
    )
    assert sc.observation_count == 1
    assert sc.is_current is False
    assert _aware(sc.ended_at) == t0


# =========================================================================
# TEST 10 — MULTIPLE NETWORKS
# =========================================================================
def test_scenario_10_multiple_networks(db_session, monkeypatch):
    """Same device identity observed on DigiSel (192.168.1.0/24) and HomeWiFi (10.0.0.0/24).
    Expected: separate session histories. DigiSel history does NOT leak into HomeWiFi."""
    org = _org(db_session, "org-scen-10")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)
    _set_time(monkeypatch, t0)

    # DigiSel observation
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.88", "mac": "aa:bb:cc:00:00:88"},
    ]))

    # HomeWiFi observation
    t1 = t0 + timedelta(minutes=1)
    _set_time(monkeypatch, t1)
    live.observe_devices(db_session, org.id, _batch("10.0.0.0/24", [
        {"ip": "10.0.0.88", "mac": "aa:bb:cc:00:00:88"},
    ]))

    sessions = db_session.scalars(
        select(DevicePresenceSession).where(
            DevicePresenceSession.org_id == org.id,
            DevicePresenceSession.device_key == "mac:aa:bb:cc:00:00:88",
        )
    ).all()
    assert len(sessions) == 2
    net_keys = {s.network_key for s in sessions}
    assert net_keys == {"192.168.1.0/24", "10.0.0.0/24"}


# =========================================================================
# TEST 11 — RANDOMIZED MAC
# =========================================================================
def test_scenario_11_randomized_mac_independent_identities(db_session, monkeypatch):
    """MAC-A = locally administered (e.g. da:a1:19:64:12:00), MAC-B = different locally administered MAC.
    Expected: treated as independent identities, never merged into a single device or session."""
    org = _org(db_session, "org-scen-11")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)
    _set_time(monkeypatch, t0)

    # da:a1:19:64:12:00 has 0xda byte 0 -> bit 1 is set (locally administered)
    # 02:bb:cc:dd:ee:ff has 0x02 byte 0 -> bit 1 is set (locally administered)
    mac_a = "da:a1:19:64:12:00"
    mac_b = "02:bb:cc:dd:ee:ff"

    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.51", "mac": mac_a, "discovery": "arp"},
        {"ip": "192.168.1.52", "mac": mac_b, "discovery": "arp"},
    ]))

    rows = db_session.scalars(
        select(NetworkDevice).where(NetworkDevice.org_id == org.id)
    ).all()
    assert len(rows) == 2
    for r in rows:
        assert "Private" in (r.vendor or "")

    sessions = db_session.scalars(
        select(DevicePresenceSession).where(DevicePresenceSession.org_id == org.id)
    ).all()
    assert len(sessions) == 2
    dev_keys = {s.device_key for s in sessions}
    assert dev_keys == {f"mac:{mac_a}", f"mac:{mac_b}"}


# =========================================================================
# TEST 12 — MISSING / LEGACY HISTORY
# =========================================================================
def test_scenario_12_missing_legacy_history_safe_fallback(db_session, monkeypatch):
    """Simulate a legacy device row without any session history.
    Expected: no crash, current session handled safely (duration=0), safe frontend fallback."""
    org = _org(db_session, "org-scen-12")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)
    _set_time(monkeypatch, t0)

    # Manually insert legacy NetworkDevice without creating any DevicePresenceSession
    legacy_dev = NetworkDevice(
        org_id=org.id,
        ip="192.168.1.99",
        mac="aa:bb:cc:99:99:99",
        hostname="legacy-node",
        subnet="192.168.1.0/24",
        online=True,
        discovery="arp",
        first_seen=t0,
        last_seen=t0,
    )
    db_session.add(legacy_dev)
    db_session.commit()

    # Query via list_devices()
    devs = live.list_devices(db_session, org.id)
    assert len(devs) == 1
    d = devs[0]
    assert d.ip == "192.168.1.99"
    assert d.current_session_duration_seconds == 0.0
    assert d.total_observed_duration_seconds == 0.0
    assert d.presence_state == "new"


# =========================================================================
# RESTART PERSISTENCE TEST
# =========================================================================
def test_restart_persistence_across_connection(tmp_path, monkeypatch):
    """Verify history survives database disconnect/reconnect (simulating backend/agent restart)."""
    db_file = tmp_path / "drishti_restart_test.db"
    db_url = f"sqlite:///{db_file}"

    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=4)

    # Step 1: Initial connection, create schema, observe device
    engine1 = create_engine(db_url)
    Base.metadata.create_all(engine1)
    Session1 = sessionmaker(bind=engine1)
    s1 = Session1()

    org = Organization(name="restart-org", slug="restart-org")
    s1.add(org)
    s1.commit()
    org_id = org.id

    _set_time(monkeypatch, t0)
    live.observe_devices(s1, org_id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.77", "mac": "aa:bb:cc:77:77:77", "source": "scapy"},
    ]))

    _set_time(monkeypatch, t1)
    live.observe_devices(s1, org_id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.77", "mac": "aa:bb:cc:77:77:77", "source": "scapy"},
    ]))

    s1.commit()
    s1.close()
    engine1.dispose()

    # Step 2: Reconnect fresh engine to same SQLite file (mirroring backend restart)
    engine2 = create_engine(db_url)
    Session2 = sessionmaker(bind=engine2)
    s2 = Session2()

    sessions = s2.scalars(
        select(DevicePresenceSession).where(DevicePresenceSession.org_id == org_id)
    ).all()
    assert len(sessions) == 1
    session_row = sessions[0]
    assert session_row.observation_count == 2
    assert session_row.is_current is True
    assert session_row.device_key == "mac:aa:bb:cc:77:77:77"

    # Verify list_devices() reproduces continuous presence after restart
    _set_time(monkeypatch, t1)
    devs = live.list_devices(s2, org_id)
    assert len(devs) == 1
    assert devs[0].current_session_duration_seconds == 240.0
    assert devs[0].observation_count == 2
    assert devs[0].session_count == 1

    s2.close()
    engine2.dispose()


# =========================================================================
# DATABASE GROWTH CHECK
# =========================================================================
def test_database_growth_single_session_updated(db_session, monkeypatch):
    """Run 20 repeated observations for the same device within MAX_OBSERVATION_GAP.
    Verify: exactly 1 session row is maintained and updated rather than creating 20 rows."""
    org = _org(db_session, "org-growth-check")
    t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(20):
        t = t0 + timedelta(minutes=i)
        _set_time(monkeypatch, t)
        live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
            {"ip": "192.168.1.33", "mac": "aa:bb:cc:33:33:33"},
        ]))

    sessions = db_session.scalars(
        select(DevicePresenceSession).where(DevicePresenceSession.org_id == org.id)
    ).all()
    # Must be bounded: exactly 1 active session record
    assert len(sessions) == 1
    assert sessions[0].observation_count == 20
    assert sessions[0].is_current is True


# =========================================================================
# FULL API FLOW TEST
# =========================================================================
def test_full_api_flow_session_fields(client, seed_acme_org, agent_headers, user_headers):
    """POST /api/live/devices → session tracking in SQLite → GET /api/live/devices.
    Verify all 7 presence telemetry fields are populated correctly in API response."""
    batch = {
        "devices": [
            {
                "ip": "192.168.1.45",
                "mac": "04:d9:f5:95:b8:45",
                "hostname": "workstation-01",
                "discovery": "scapy",
                "source": "scapy",
            }
        ],
        "subnet": "192.168.1.0/24",
    }

    # Agent reports batch
    post_resp = client.post("/api/live/devices", json=batch, headers=agent_headers)
    assert post_resp.status_code == 200, post_resp.text
    assert post_resp.json()["total"] >= 1

    # User fetches live devices
    get_resp = client.get("/api/live/devices", headers=user_headers)
    assert get_resp.status_code == 200, get_resp.text
    devs = get_resp.json()

    target = next((d for d in devs if d["mac"] == "04:d9:f5:95:b8:45"), None)
    assert target is not None

    # Confirm all required fields
    assert target["current_session_started_at"] is not None
    assert target["current_session_duration_seconds"] == 0.0
    assert target["total_observed_duration_seconds"] == 0.0
    assert target["session_count"] == 1
    assert target["observation_count"] == 1
    assert target["observation_source"] == "scapy"
    assert target["presence_state"] == "new"
