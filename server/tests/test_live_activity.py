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

from app.models import DeepScan, LiveObservation, NetworkDevice, Organization
from app.models.base import utcnow
from app.schemas.live import (
    ActivityItem,
    DeepScanCve,
    DeepScanService,
    DeviceBatch,
    DeviceIn,
    NetworkDeviceOut,
    SyncActiveRequest,
)
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


def test_sync_active_request_new_fields_and_defaults():
    """Test 11: SyncActiveRequest must accept all new Phase B2.1 fields and have safe defaults."""
    req_default = SyncActiveRequest()
    assert req_default.domains == []
    assert req_default.source_host == "default"
    assert req_default.active_apps == []
    assert req_default.active_browser_tabs == []
    assert req_default.endpoint_processes == []
    assert req_default.installed_software == []
    assert req_default.installed_browsers == []
    assert req_default.process_connections == []
    assert req_default.vpn_status is None
    assert req_default.vpn_adapters == []
    assert req_default.os_info is None

    tab = ActivityItem(name="https://github.com", evidence_type="BROWSER_TAB", source="browser_endpoint")
    proc = ActivityItem(name="Code.exe", evidence_type="ENDPOINT_PROCESS", source="windows_endpoint")
    soft = ActivityItem(name="Python 3.11", evidence_type="INSTALLED_SOFTWARE", source="windows_registry")
    conn = ActivityItem(name="Code.exe:443", evidence_type="PROCESS_SOCKET", source="netstat")

    req_full = SyncActiveRequest(
        domains=["github.com"],
        source_host="192.168.1.10",
        active_apps=["Code.exe"],
        active_browser_tabs=[tab],
        endpoint_processes=[proc],
        installed_software=[soft],
        installed_browsers=["Chrome", "Brave"],
        process_connections=[conn],
        vpn_status="INACTIVE",
        vpn_adapters=["Tailscale"],
        os_info="Windows 11 Pro 23H2",
    )
    assert req_full.source_host == "192.168.1.10"
    assert len(req_full.active_browser_tabs) == 1
    assert req_full.active_browser_tabs[0].name == "https://github.com"
    assert len(req_full.installed_browsers) == 2
    assert req_full.vpn_status == "INACTIVE"
    assert req_full.os_info == "Windows 11 Pro 23H2"


def test_network_device_out_new_fields_defaults():
    """Test 12: NetworkDeviceOut has all Phase B2.1 device intelligence fields with safe defaults."""
    now = utcnow()
    dev = NetworkDeviceOut(
        id="dev-1",
        ip="192.168.1.50",
        first_seen=now,
        last_seen=now,
    )
    assert dev.open_ports == []
    assert dev.services == []
    assert dev.cves == []
    assert dev.os_info is None
    assert dev.device_type is None
    assert dev.installed_software == []
    assert dev.process_connections == []
    assert dev.installed_browsers == []
    assert dev.vpn_status is None
    assert dev.vpn_adapters == []
    assert dev.security_findings == []
    assert dev.risk_score is None


def test_deepscan_result_forwarding(db_session):
    """Test 13: Forward only real DeepScan result evidence without re-scanning or fabricating."""
    org = _org(db_session, "test-deepscan-forwarding")
    target_ip = "192.168.1.99"
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": target_ip, "mac": "aa:bb:cc:dd:ee:99"}
    ]))

    ds = DeepScan(
        org_id=org.id,
        target_ip=target_ip,
        available=True,
        result_json={
            "available": True,
            "target": target_ip,
            "ports": [22, 80],
            "services": [
                {"port": 22, "protocol": "tcp", "service_name": "ssh", "product": "OpenSSH", "version": "8.9p1"},
                {"port": 80, "protocol": "tcp", "service_name": "http", "product": "nginx", "version": "1.18.0"},
            ],
            "cves": [
                {
                    "id": "CVE-2023-1234",
                    "cvss": 7.5,
                    "severity": "high",
                    "summary": "Sample OpenSSH remote code execution vulnerability",
                    "affected_service": "OpenSSH 8.9p1",
                }
            ],
            "os": "Linux 5.15 (Ubuntu)",
            "risk_score": 68.5,
        },
    )
    db_session.add(ds)
    db_session.commit()

    devices = live.list_devices(db_session, org.id)
    dev = next(d for d in devices if d.ip == target_ip)

    assert dev.scanned is True
    assert dev.open_ports == [22, 80]
    assert len(dev.services) == 2
    assert dev.services[0].service_name == "ssh"
    assert dev.services[0].port == 22
    assert len(dev.cves) == 1
    assert dev.cves[0].id == "CVE-2023-1234"
    assert dev.cves[0].cvss == 7.5
    assert dev.os_info == "Linux 5.15 (Ubuntu)"
    assert dev.risk_score == 68.5
    assert any("CORRELATED CVE: CVE-2023-1234" in f for f in dev.security_findings)


def test_missing_deepscan_fallback(db_session):
    """Test 14: Devices with no DeepScan result must have empty arrays and None for unavailable scalars."""
    org = _org(db_session, "test-missing-deepscan")
    target_ip = "192.168.1.101"
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": target_ip, "mac": "aa:bb:cc:dd:ee:01"}
    ]))

    devices = live.list_devices(db_session, org.id)
    dev = next(d for d in devices if d.ip == target_ip)

    assert dev.scanned is False
    assert dev.open_ports == []
    assert dev.services == []
    assert dev.cves == []
    assert dev.os_info is None
    assert dev.risk_score is None
    assert dev.security_findings == []


def test_deterministic_rdp_and_smb_exposure_findings(db_session):
    """Test 15: Open RDP/SMB ports produce deterministic exposure findings; OPEN != VULNERABLE."""
    org = _org(db_session, "test-rdp-smb-exposure")
    target_ip = "192.168.1.102"
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": target_ip, "mac": "aa:bb:cc:dd:ee:02"}
    ]))

    ds = DeepScan(
        org_id=org.id,
        target_ip=target_ip,
        available=True,
        result_json={
            "available": True,
            "target": target_ip,
            "ports": [445, 3389],
            "services": [
                {"port": 445, "protocol": "tcp", "service_name": "microsoft-ds"},
                {"port": 3389, "protocol": "tcp", "service_name": "ms-wbt-server"},
            ],
            "cves": [],
            "os": "Windows Server 2022",
            "risk_score": 45.0,
        },
    )
    db_session.add(ds)
    db_session.commit()

    devices = live.list_devices(db_session, org.id)
    dev = next(d for d in devices if d.ip == target_ip)

    assert "HIGH EXPOSURE: TCP/3389 Open (Microsoft RDP)" in dev.security_findings
    assert "HIGH EXPOSURE: TCP/445 Open (SMB)" in dev.security_findings
    # OPEN != VULNERABLE: no CVEs were matched, so no CVE findings exist
    assert not any("CVE" in f for f in dev.security_findings)
    assert dev.cves == []


def test_no_cve_fabrication(db_session):
    """Test 16: DeepScan ports without matched CVEs must never fabricate CVEs."""
    org = _org(db_session, "test-no-cve-fabrication")
    target_ip = "192.168.1.103"
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": target_ip, "mac": "aa:bb:cc:dd:ee:03"}
    ]))

    ds = DeepScan(
        org_id=org.id,
        target_ip=target_ip,
        available=True,
        result_json={
            "available": True,
            "target": target_ip,
            "ports": [80, 443],
            "services": [
                {"port": 80, "protocol": "tcp", "service_name": "http"},
                {"port": 443, "protocol": "tcp", "service_name": "https"},
            ],
            "cves": [],
            "os": None,
            "risk_score": 10.0,
        },
    )
    db_session.add(ds)
    db_session.commit()

    devices = live.list_devices(db_session, org.id)
    dev = next(d for d in devices if d.ip == target_ip)

    assert dev.cves == []
    # No risky exposure ports (80/443 are standard web) and no CVEs -> empty findings
    assert dev.security_findings == []


def test_remote_device_telemetry_unavailable_behavior(db_session):
    """Test 17: Remote devices without authorized endpoint telemetry have TELEMETRY UNAVAILABLE."""
    org = _org(db_session, "test-remote-unavailable")
    remote_ip = "192.168.1.104"
    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": remote_ip, "mac": "aa:bb:cc:dd:ee:04"}
    ]))

    devices = live.list_devices(db_session, org.id)
    dev = next(d for d in devices if d.ip == remote_ip)

    assert dev.endpoint_processes == []
    assert dev.active_browser_tabs == []
    assert dev.installed_software == []
    assert dev.process_connections == []
    assert dev.installed_browsers == []
    assert dev.vpn_status == "TELEMETRY UNAVAILABLE"
    assert dev.vpn_adapters == []


def test_endpoint_telemetry_ttl_and_host_isolation(db_session):
    """Test 18: Authorized host telemetry has 20s tab TTL, 60s process TTL, and strict host isolation."""
    from datetime import timedelta
    org = _org(db_session, "test-ttl-isolation")
    host_ip = "192.168.1.105"
    remote_ip = "192.168.1.106"

    live.observe_devices(db_session, org.id, _batch("192.168.1.0/24", [
        {"ip": host_ip, "mac": "aa:bb:cc:dd:ee:05"},
        {"ip": remote_ip, "mac": "aa:bb:cc:dd:ee:06"},
    ], self_mac="aa:bb:cc:dd:ee:05"))

    tab = ActivityItem(name="https://news.ycombinator.com", evidence_type="BROWSER_TAB", source="browser_endpoint")
    proc = ActivityItem(name="WindowsTerminal.exe", evidence_type="ENDPOINT_PROCESS", source="windows_endpoint")
    soft = ActivityItem(name="Git for Windows", evidence_type="INSTALLED_SOFTWARE", source="windows_registry")
    conn = ActivityItem(name="WindowsTerminal.exe:22", evidence_type="PROCESS_SOCKET", source="netstat")

    live.sync_active(
        db=db_session,
        org_id=org.id,
        source_host=host_ip,
        active_browser_tabs=[tab],
        endpoint_processes=[proc],
        installed_software=[soft],
        installed_browsers=["Chrome"],
        process_connections=[conn],
        vpn_status="ACTIVE",
        vpn_adapters=["WireGuard"],
        os_info="Windows 11 Enterprise",
    )

    devices = live.list_devices(db_session, org.id)
    host_dev = next(d for d in devices if d.ip == host_ip)
    remote_dev = next(d for d in devices if d.ip == remote_ip)

    # 1. Host device receives all telemetry
    assert len(host_dev.active_browser_tabs) == 1
    assert host_dev.active_browser_tabs[0].name == "https://news.ycombinator.com"
    assert len(host_dev.endpoint_processes) == 1
    assert host_dev.endpoint_processes[0].name == "WindowsTerminal.exe"
    assert len(host_dev.installed_software) == 1
    assert host_dev.installed_software[0].name == "Git for Windows"
    assert host_dev.installed_browsers == ["Chrome"]
    assert len(host_dev.process_connections) == 1
    assert host_dev.vpn_status == "ACTIVE"
    assert host_dev.vpn_adapters == ["WireGuard"]
    assert host_dev.os_info == "Windows 11 Enterprise"

    # 2. Remote device receives NONE of it (strict isolation)
    assert remote_dev.active_browser_tabs == []
    assert remote_dev.endpoint_processes == []
    assert remote_dev.installed_software == []
    assert remote_dev.installed_browsers == []
    assert remote_dev.process_connections == []
    assert remote_dev.vpn_status == "TELEMETRY UNAVAILABLE"
    assert remote_dev.vpn_adapters == []

    # 3. Simulate tab expiration (>20s)
    telem = live._HOST_TELEMETRY[host_ip]
    telem.tabs_updated_at = utcnow() - timedelta(seconds=25)

    devices_after_25s = live.list_devices(db_session, org.id)
    host_after_25s = next(d for d in devices_after_25s if d.ip == host_ip)
    # Tabs expired after 20s
    assert host_after_25s.active_browser_tabs == []
    # Processes still valid (<60s)
    assert len(host_after_25s.endpoint_processes) == 1
    assert host_after_25s.vpn_status == "ACTIVE"

    # 4. Simulate full endpoint expiration (>60s)
    telem.updated_at = utcnow() - timedelta(seconds=65)

    devices_after_65s = live.list_devices(db_session, org.id)
    host_after_65s = next(d for d in devices_after_65s if d.ip == host_ip)
    # All endpoint telemetry expired -> safe fallback
    assert host_after_65s.endpoint_processes == []
    assert host_after_65s.installed_software == []
    assert host_after_65s.process_connections == []
    assert host_after_65s.vpn_status == "TELEMETRY UNAVAILABLE"


def test_api_sync_active_accepts_structured_payload(client, seed_acme_org, agent_headers):
    """Test 19: POST /api/live/sync_active accepts Phase B2.1 structured telemetry over HTTP."""
    resp = client.post(
        "/api/live/sync_active",
        headers=agent_headers,
        json={
            "source_host": "10.0.0.50",
            "active_browser_tabs": [
                {"name": "https://github.com", "evidence_type": "BROWSER_TAB", "source": "browser_endpoint"}
            ],
            "endpoint_processes": [
                {"name": "code.exe", "evidence_type": "ENDPOINT_PROCESS", "source": "windows_endpoint"}
            ],
            "installed_software": [
                {"name": "Node.js", "evidence_type": "INSTALLED_SOFTWARE", "source": "windows_registry"}
            ],
            "installed_browsers": ["Google Chrome"],
            "process_connections": [
                {"name": "code.exe:443", "evidence_type": "PROCESS_SOCKET", "source": "netstat"}
            ],
            "vpn_status": "INACTIVE",
            "vpn_adapters": [],
            "os_info": "Windows 11 Pro",
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"updated": 0}

    # Verify telemetry in live service
    telem = live._HOST_TELEMETRY.get("10.0.0.50")
    assert telem is not None
    assert telem.os_info == "Windows 11 Pro"
    assert telem.vpn_status == "INACTIVE"
    assert len(telem.active_browser_tabs) == 1
    assert len(telem.endpoint_processes) == 1
    assert len(telem.installed_software) == 1
    assert telem.installed_browsers == ["Google Chrome"]

