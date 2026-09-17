# Drishti v0.1 — truthful activity & telemetry tests | Phase 1 Cleanup
"""Comprehensive tests validating:
1. No IP-based fake applications
2. No IP-based fake domains
3. No domain -> app inference
4. No process -> synthetic domain inference
5. Remote device has empty endpoint_processes
6. Remote device has empty active_browser_tabs
7. Live mode contains no demo activity
8. Device activity isolation (Device A activity != Device B activity)
9. Existing network discovery unaffected
10. Existing session/history functionality unaffected
"""
from datetime import datetime, timezone
import pytest

from app.models import LiveObservation, NetworkDevice, Organization
from app.models.base import utcnow
from app.schemas.live import DeviceBatch, DeviceIn
from app.services import live


def _org(db, slug="activity-test-org"):
    o = Organization(name=slug, slug=slug)
    db.add(o)
    db.flush()
    return o


def _batch(subnet, devices, *, gateway_ip=None, self_mac=None):
    return DeviceBatch(
        devices=[DeviceIn(**d) for d in devices],
        subnet=subnet,
        gateway_ip=gateway_ip,
        self_mac=self_mac,
    )


def test_no_ip_based_fake_applications_or_domains(db_session):
    """Test 1 & 2: Remote devices must NOT receive IP-modulo fake apps or domains."""
    org = _org(db_session, "test-no-fake-presets")
    # Add multiple devices with varying IP last octets (1, 2, 3, 4, 5, 25)
    devices = [
        {"ip": f"192.168.1.{i}", "mac": f"aa:bb:cc:dd:ee:0{i}"}
        for i in (1, 2, 3, 4, 5, 25)
    ]
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", devices))

    listed = live.list_devices(db_session, org.id)
    assert len(listed) == 6

    fake_names = {"Netflix", "Spotify", "Discord", "ChatGPT", "Teams", "WhatsApp", "Slack"}
    fake_doms = {"netflix.com", "spotify.com", "discord.com", "chatgpt.com", "whatsapp.com"}

    for d in listed:
        # Remote devices must have empty active apps and empty active domains
        assert d.active_apps == []
        assert d.active_domains == []
        assert d.endpoint_processes == []
        assert d.active_browser_tabs == []
        # Check that none of the old preset names appear anywhere
        for app in d.active_apps:
            assert app not in fake_names
        for dom in d.active_domains:
            assert dom not in fake_doms


def test_no_domain_to_app_inference(db_session):
    """Test 3: Network domain contact (e.g. netflix.com) must NOT infer a running desktop app."""
    org = _org(db_session, "test-no-domain-to-app")
    target_ip = "192.168.1.42"
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": target_ip, "mac": "aa:bb:cc:dd:ee:42"}
    ]))

    # Record a network traffic observation for netflix.com originating from target_ip
    obs = LiveObservation(
        org_id=org.id,
        domain="netflix.com",
        url="https://netflix.com/",
        source_host=target_ip,
        band="Trusted",
        score=0.1,
        verdict_json={},
        hit_count=1,
        first_seen=utcnow(),
        last_seen=utcnow(),
    )
    db_session.add(obs)
    db_session.commit()

    devices = live.list_devices(db_session, org.id)
    dev = next(d for d in devices if d.ip == target_ip)

    # Truthful check:
    # 1. netflix.com is listed under recent_destinations as NETWORK_TRAFFIC
    assert any(dest.name == "netflix.com" and dest.evidence_type == "NETWORK_TRAFFIC" for dest in dev.recent_destinations)
    # 2. But Netflix is NOT inferred as an active application!
    assert "Netflix" not in dev.active_apps
    assert dev.endpoint_processes == []
    assert dev.active_apps == []


def test_no_process_to_synthetic_domain_inference(db_session):
    """Test 4: Local process (e.g. Spotify) must NOT fabricate an active domain (spotify.com)."""
    org = _org(db_session, "test-no-process-to-domain")
    host_ip = "192.168.1.10"
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": host_ip, "mac": "aa:bb:cc:dd:ee:10"}
    ], self_mac="aa:bb:cc:dd:ee:10"))

    # Sync real endpoint process for the host
    live.sync_active(
        db=db_session,
        org_id=org.id,
        domains=[],  # No real browser tabs open
        source_host=host_ip,
        active_apps=["Spotify", "Code", "pwsh"],
    )

    devices = live.list_devices(db_session, org.id)
    host_dev = next(d for d in devices if d.ip == host_ip)

    # Process is truthfully captured as ENDPOINT_PROCESS
    proc_names = [p.name for p in host_dev.endpoint_processes]
    assert "Spotify" in proc_names
    assert "Code" in proc_names
    assert "pwsh" in proc_names

    # But spotify.com is NOT synthesized into active_domains or recent_destinations
    assert "spotify.com" not in host_dev.active_domains
    assert not any(dest.name == "spotify.com" for dest in host_dev.recent_destinations)
    assert host_dev.active_browser_tabs == []


def test_remote_devices_have_empty_telemetry(db_session):
    """Test 5 & 6: Remote LAN devices must have empty endpoint_processes and active_browser_tabs."""
    org = _org(db_session, "test-remote-empty-telemetry")
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01"},
        {"ip": "192.168.1.88", "mac": "aa:bb:cc:dd:ee:88"},
    ]))

    devices = live.list_devices(db_session, org.id)
    for dev in devices:
        assert dev.endpoint_processes == []
        assert dev.active_browser_tabs == []
        assert dev.active_apps == []
        assert dev.active_domains == []


def test_live_mode_contains_no_demo_activity(db_session):
    """Test 7: Regular live discovery must contain no demo activity."""
    org = _org(db_session, "test-no-demo-in-live")
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.55", "mac": "aa:bb:cc:dd:ee:55"}
    ]))

    devices = live.list_devices(db_session, org.id)
    d = devices[0]
    assert d.label != "DEMO-ATTACK"
    assert d.active_apps == []
    assert d.active_domains == []


def test_device_activity_isolation(db_session):
    """Test 8: Activity from Device A must NOT leak to Device B."""
    org = _org(db_session, "test-device-isolation")
    ip_a = "192.168.1.20"
    ip_b = "192.168.1.21"

    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": ip_a, "mac": "aa:bb:cc:dd:ee:20"},
        {"ip": ip_b, "mac": "aa:bb:cc:dd:ee:21"},
    ]))

    # Device A sends DNS query for github.com
    obs_a = LiveObservation(
        org_id=org.id,
        domain="github.com",
        url="https://github.com/",
        source_host=ip_a,
        band="Trusted",
        score=0.0,
        verdict_json={},
        hit_count=1,
        first_seen=utcnow(),
        last_seen=utcnow(),
    )
    db_session.add(obs_a)
    db_session.commit()

    devices = live.list_devices(db_session, org.id)
    dev_a = next(d for d in devices if d.ip == ip_a)
    dev_b = next(d for d in devices if d.ip == ip_b)

    # Device A must have github.com in recent_destinations
    assert any(dest.name == "github.com" for dest in dev_a.recent_destinations)

    # Device B must have ZERO destinations (strictly isolated)
    assert dev_b.recent_destinations == []
    assert dev_b.active_domains == []
    assert dev_b.active_apps == []


def test_existing_network_discovery_unaffected(db_session):
    """Test 9: Existing network discovery and device inventory remain 100% functional."""
    org = _org(db_session, "test-discovery-unaffected")
    live.observe_devices(db_session, org.id, _batch(
        "10.0.0.0/24",
        [
            {"ip": "10.0.0.1", "mac": "00:50:56:00:00:01", "hostname": "router.lan"},
            {"ip": "10.0.0.15", "mac": "00:0c:29:00:00:02", "hostname": "workstation.lan"},
        ],
        gateway_ip="10.0.0.1",
        self_mac="00:0c:29:00:00:02",
    ))

    devices = live.list_devices(db_session, org.id)
    assert len(devices) == 2

    gw = next(d for d in devices if d.ip == "10.0.0.1")
    assert gw.is_gateway is True
    assert gw.hostname == "router.lan"

    self_dev = next(d for d in devices if d.ip == "10.0.0.15")
    assert self_dev.is_self is True
    assert self_dev.is_gateway is False
    assert self_dev.hostname == "workstation.lan"


def test_existing_session_history_unaffected(db_session):
    """Test 10: Existing session and presence history functionality remain intact."""
    org = _org(db_session, "test-sessions-unaffected")
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": "192.168.1.77", "mac": "aa:bb:cc:dd:ee:77", "source": "arp"}
    ]))

    devices = live.list_devices(db_session, org.id)
    dev = devices[0]
    assert dev.session_count == 1
    assert dev.observation_count == 1
    assert dev.presence_state == "new"
    assert dev.observation_source == "arp"
