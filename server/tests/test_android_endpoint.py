# Drishti v0.1 — Android Endpoint Agent Backend Integration Tests
from __future__ import annotations

import time
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.live import NetworkDevice
from app.models.endpoint import EndpointAgent, EndpointPairingSession
from app.services.ai import service as ai_service
from app.services.endpoint_telemetry import (
    clear_telemetry_store,
    get_telemetry_for_device,
)
from app.services.live import upsert_device_from_endpoint_agent
from app.services.vuln_intel.models import CorrelatedFinding, FindingState



@pytest.fixture(autouse=True)
def clean_telemetry():
    clear_telemetry_store()
    yield
    clear_telemetry_store()


def test_android_pairing_initialization(client: TestClient, db_session: Session):
    """Test pairing initialization with Android OS and null MAC (as required by Android 11+)."""
    agent_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    payload = {
        "agent_id": agent_id,
        "device_id": device_id,
        "hostname": "Pixel 8 Pro",
        "os": "android",
        "os_version": "Android 15 (SDK 35)",
        "mac": None,  # Android 11+ restricts MAC addresses
        "current_ip": "192.168.1.188",
        "agent_version": "0.1.0",
    }
    res = client.post("/api/endpoint/pairing/init", json=payload)
    assert res.status_code == 200, res.text
    data = res.json()
    assert "session_id" in data
    assert "pairing_code" in data
    assert len(data["pairing_code"]) == 9  # XXXX-XXXX format

    # Verify session persisted in DB
    sess = db_session.get(EndpointPairingSession, data["session_id"])
    assert sess is not None
    assert sess.agent_id == agent_id
    assert sess.os == "android"
    assert sess.mac is None
    assert sess.status == "WAITING_FOR_PAIR"


def test_android_pairing_workflow_and_device_upsert(
    client: TestClient, db_session: Session, user_headers: dict, seed_acme_org
):
    """Test full pairing authorization flow and NetworkDevice creation for Android."""
    agent_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    init_res = client.post(
        "/api/endpoint/pairing/init",
        json={
            "agent_id": agent_id,
            "device_id": device_id,
            "hostname": "Samsung Galaxy S24",
            "os": "android",
            "os_version": "14",
            "mac": None,
            "current_ip": "192.168.1.189",
        },
    )
    assert init_res.status_code == 200
    init_data = init_res.json()
    session_id = init_data["session_id"]
    code = init_data["pairing_code"]

    # Operator authorizes pairing
    pair_res = client.post(
        "/api/endpoint/pairing/pair",
        json={"pairing_code": code},
        headers=user_headers,
    )
    assert pair_res.status_code == 200, pair_res.text
    assert pair_res.json()["success"] is True

    # Agent polls and obtains one-time token
    poll_res = client.post(
        "/api/endpoint/pairing/status",
        json={"session_id": session_id, "agent_id": agent_id},
    )
    assert poll_res.status_code == 200
    poll_data = poll_res.json()
    assert poll_data["status"] == "PAIRED"
    token = poll_data["agent_token"]
    assert token is not None

    # Verify agent model in DB
    agent = db_session.scalar(
        select(EndpointAgent).where(EndpointAgent.agent_id == agent_id)
    )
    assert agent is not None
    assert agent.os == "android"
    assert agent.status == "ONLINE"

    # Send heartbeat
    hb_res = client.post(
        "/api/endpoint/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "agent_id": agent_id,
            "device_id": device_id,
            "timestamp": "2026-09-21T12:00:00Z",
            "agent_version": "0.1.0",
        },
    )
    assert hb_res.status_code == 200
    assert hb_res.json()["status"] == "ACK"

    # Upsert to NetworkDevice - the function returns None, check via DB query
    from app.models.live import NetworkDevice as ND
    from sqlalchemy import select as sa_select

    upsert_device_from_endpoint_agent(db_session, org_id=seed_acme_org.id, agent=agent)
    db_session.expire_all()

    net_dev = db_session.scalar(
        sa_select(ND).where(ND.org_id == seed_acme_org.id, ND.ip == "192.168.1.189")
    )
    assert net_dev is not None
    assert net_dev.vendor == "Android"
    assert net_dev.source_agent_id == agent.agent_id


def test_android_telemetry_extended_ingestion(
    client: TestClient, db_session: Session, user_headers: dict, seed_acme_org
):
    """Test ingestion and retrieval of Android extended telemetry (CPU, RAM, Battery, Security Posture, Apps)."""
    # Create and pair agent
    agent_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    init_res = client.post(
        "/api/endpoint/pairing/init",
        json={
            "agent_id": agent_id,
            "device_id": device_id,
            "hostname": "Pixel 9",
            "os": "android",
            "os_version": "15",
            "current_ip": "192.168.1.190",
        },
    )
    session_id = init_res.json()["session_id"]
    code = init_res.json()["pairing_code"]

    client.post("/api/endpoint/pairing/pair", json={"pairing_code": code}, headers=user_headers)
    token = client.post(
        "/api/endpoint/pairing/status", json={"session_id": session_id, "agent_id": agent_id}
    ).json()["agent_token"]

    telemetry_payload = {
        "agent_id": agent_id,
        "device_id": device_id,
        "timestamp": "2026-09-21T12:05:00Z",
        "hostname": "Pixel 9",
        "os_name": "android",
        "os_version": "Android 15 (SDK 35)",
        "device_model": "Pixel 9",
        "manufacturer": "Google",
        "sdk_version": 35,
        "cpu_info": {
            "cores": 8,
            "usage_percent": None,
            "per_core_supported": False,
            "per_core_usage": [],
            "architecture": "arm64-v8a",
        },
        "memory_info": {
            "total_bytes": 12884901888,
            "available_bytes": 6442450944,
            "used_bytes": 6442450944,
            "low_memory": False,
        },
        "storage_info": {
            "total_bytes": 256000000000,
            "available_bytes": 128000000000,
            "used_bytes": 128000000000,
        },
        "battery_info": {
            "percentage": 88,
            "charging": True,
            "health": "GOOD",
            "temperature_c": 29.5,
        },
        "network_info": {
            "connection_type": "WI-FI",
            "local_ip": "192.168.1.190",
            "interface": "wlan0",
            "link_speed_kbps": 866000,
        },
        "security_posture": {
            "screen_lock": True,
            "encryption": "ENCRYPTED",
            "developer_options": False,
            "usb_debugging": False,
            "verified_boot": "release-keys",
            "security_patch": "2026-09-01",
            "biometric_capability": "BIOMETRIC_STRONG",
            "root_detected": False,
        },
        "applications": [
            {
                "package_name": "com.android.chrome",
                "label": "Google Chrome",
                "version_name": "120.0.6099.144",
                "version_code": 609914400,
                "classification": "USER_APP",
                "is_enabled": True,
            },
            {
                "package_name": "org.mozilla.firefox",
                "label": "Firefox",
                "version_name": "125.0.1",
                "version_code": 2016012345,
                "classification": "USER_APP",
                "is_enabled": True,
            },
        ],
        "endpoint_processes": [
            {
                "pid": 10520,
                "name": "com.drishti.agent",
                "category": "SECURITY_AGENT",
                "memory_mb": 42.0,
            }
        ],
    }

    # Ingest telemetry
    tel_res = client.post(
        "/api/endpoint/telemetry",
        headers={"Authorization": f"Bearer {token}"},
        json=telemetry_payload,
    )
    assert tel_res.status_code == 200, tel_res.text
    tel_data = tel_res.json()
    assert tel_data["success"] is True

    # Retrieve telemetry for device
    dev_telemetry = get_telemetry_for_device(seed_acme_org.id, device_id)
    assert dev_telemetry is not None
    assert dev_telemetry.device_model == "Pixel 9"
    assert dev_telemetry.manufacturer == "Google"
    assert dev_telemetry.sdk_version == 35

    cpu = dev_telemetry.cpu_info
    assert cpu is not None
    # cpu_info may be a CpuTelemetry model or a dict depending on how it was stored
    if isinstance(cpu, dict):
        assert cpu.get("per_core_supported") is False
    else:
        assert cpu.per_core_supported is False

    mem = dev_telemetry.memory_info
    assert mem is not None
    if isinstance(mem, dict):
        assert mem.get("total_bytes") == 12884901888
    else:
        assert mem.total_bytes == 12884901888

    bat = dev_telemetry.battery_info
    assert bat is not None
    if isinstance(bat, dict):
        assert bat.get("percentage") == 88
    else:
        assert bat.percentage == 88

    sec = dev_telemetry.security_posture
    assert sec is not None
    if isinstance(sec, dict):
        assert sec.get("encryption") == "ENCRYPTED"
    else:
        assert sec.encryption == "ENCRYPTED"

    assert len(dev_telemetry.applications) == 2

    # Verify installed_software synthesis from applications
    assert len(dev_telemetry.installed_software) >= 2
    sw_names = [
        (sw.name if hasattr(sw, "name") else sw.get("name", ""))
        for sw in dev_telemetry.installed_software
    ]
    assert "Google Chrome" in sw_names
    assert "Firefox" in sw_names


def test_android_defensive_remediation_guardrails(db_session: Session, seed_acme_org):
    """Verify that remediation on an Android device refuses arbitrary shell scripts and yields defensive instructions."""
    finding_id = str(uuid.uuid4())
    c_finding = CorrelatedFinding(
        finding_id=finding_id,
        device_id="android-device-test",
        org_id=seed_acme_org.id,
        finding_state=FindingState.VULNERABLE,
        observed_product="com.android.chrome",
        evidence_source="endpoint_software",
        evidence_type="ENDPOINT_SOFTWARE_VULNERABILITY",
        observed_version="120.0.6099.144",
        cve_id="CVE-2024-0519",
        title="Out of bounds memory access in V8",
        summary="High severity V8 flaw in Google Chrome",
        cvss=8.8,
        severity="high",
        fixed_version_text="120.0.6099.224",
    )
    from app.services.endpoint_telemetry import _DEVICE_VULN_FINDINGS, _DEVICE_TELEMETRY_STORE
    import time

    _DEVICE_VULN_FINDINGS[(seed_acme_org.id, "android-device-test")] = [c_finding]

    # Also populate device telemetry with os_name=android so context resolver sees it
    _DEVICE_TELEMETRY_STORE[(seed_acme_org.id, "android-device-test")] = {
        "org_id": seed_acme_org.id,
        "device_id": "android-device-test",
        "agent_id": "agent-android-test",
        "hostname": "Pixel 9 Pro",
        "os_name": "android",
        "os_version": "Android 15",
        "last_updated_mono": time.monotonic(),
        "last_software_updated_mono": time.monotonic(),
        "installed_software": [],
    }

    # Request shell remediation — the Android guard must intercept this
    rem_result = ai_service.remediate(
        db=db_session,
        org_id=seed_acme_org.id,
        finding_id=finding_id,
        preferred_kind="shell",
        regenerate=False,
    )

    # Must NOT generate root commands like sudo apt-get or systemctl
    assert "sudo" not in rem_result.script.lower()
    assert "apt-get" not in rem_result.script.lower()
    assert "systemctl" not in rem_result.script.lower()

    # Must be refused OR provide defensive Android guidance
    assert (
        rem_result.refused is True
        or "play store" in rem_result.script.lower()
        or "mdm" in rem_result.script.lower()
        or "package update" in rem_result.script.lower()
    )


def test_android_demo_mode_and_expanded_telemetry(
    client: TestClient, db_session: Session, user_headers: dict, seed_acme_org, monkeypatch
):
    """Test demo pairing mode with ABCD-1234 and comprehensive expanded Android telemetry."""
    import os
    monkeypatch.setenv("DRISHTI_DEMO_MODE", "true")

    agent_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())

    init_res = client.post(
        "/api/endpoint/pairing/init",
        json={
            "agent_id": agent_id,
            "device_id": device_id,
            "hostname": "Pixel 9 Pro Demo",
            "os": "android",
            "os_version": "Android 15 (SDK 35)",
            "is_demo": True,
        },
    )
    assert init_res.status_code == 200
    init_data = init_res.json()
    assert init_data["pairing_code"] == "ABCD-1234"
    session_id = init_data["session_id"]

    # Operator enters ABCD-1234
    pair_res = client.post(
        "/api/endpoint/pairing/pair",
        json={"pairing_code": "ABCD-1234"},
        headers=user_headers,
    )
    assert pair_res.status_code == 200
    assert pair_res.json()["success"] is True

    # Agent polls and receives valid token
    poll_res = client.post(
        "/api/endpoint/pairing/status",
        json={"session_id": session_id, "agent_id": agent_id},
    )
    assert poll_res.status_code == 200
    token = poll_res.json()["agent_token"]
    assert token is not None

    # Submit comprehensive expanded telemetry batch
    telemetry_payload = {
        "agent_id": agent_id,
        "device_id": device_id,
        "timestamp": "2026-09-22T12:00:00Z",
        "hostname": "Pixel 9 Pro Demo",
        "os_name": "android",
        "os_version": "Android 15 (SDK 35)",
        "device_info": {
            "manufacturer": "Google",
            "model": "Pixel 9 Pro",
            "device_name": "Pixel 9 Pro Demo",
            "android_version": "15",
            "sdk_version": 35,
            "build_display": "AP2A.240905.003",
            "architecture": "arm64-v8a",
            "supported_abis": ["arm64-v8a"],
            "kernel_version": "6.1.75-android15",
            "locale": "en-US",
            "timezone": "America/New_York",
            "is_emulator": False,
        },
        "uptime_info": {
            "uptime_seconds": 86400,
            "boot_timestamp": "2026-09-21T12:00:00Z",
            "last_heartbeat": "2026-09-22T11:59:00Z",
            "agent_service_running": True,
        },
        "foreground_app": {
            "package_name": "com.android.chrome",
            "app_name": "Google Chrome",
            "foreground_since": "2026-09-22T11:50:00Z",
            "usage_duration_seconds": 600,
            "capability_status": "ACTIVE",
        },
        "browser_visibility": {
            "installed_browsers": ["Google Chrome", "Firefox"],
            "chrome_detected": True,
            "foreground_browser": "com.android.chrome",
            "foreground_state": "FOREGROUND",
            "tab_visibility_capability": "PLATFORM_RESTRICTED",
            "history_capability": "PLATFORM_RESTRICTED",
        },
        "network_flows": [
            {
                "destination_ip": "1.1.1.1",
                "destination_port": 443,
                "protocol": "TCP",
                "packet_count": 45,
                "bytes_total": 12840,
                "first_seen": "2026-09-22T11:55:00Z",
                "last_seen": "2026-09-22T11:59:30Z",
            }
        ],
        "capability_status": [
            {"capability": "CPU_CORE_COUNT", "status": "SUPPORTED"},
            {"capability": "CPU_USAGE_PERCENT", "status": "PLATFORM_RESTRICTED"},
            {"capability": "BROWSER_TABS_HISTORY", "status": "PLATFORM_RESTRICTED"},
            {"capability": "DEFENSIVE_VPN_FLOWS", "status": "ACTIVE"},
        ],
    }

    tel_res = client.post(
        "/api/endpoint/telemetry",
        headers={"Authorization": f"Bearer {token}"},
        json=telemetry_payload,
    )
    assert tel_res.status_code == 200
    assert tel_res.json()["success"] is True

    # Retrieve and verify all expanded telemetry fields
    stored = get_telemetry_for_device(seed_acme_org.id, device_id)
    assert stored is not None
    assert stored.device_info["model"] == "Pixel 9 Pro"
    assert stored.uptime_info["uptime_seconds"] == 86400
    assert stored.foreground_app["package_name"] == "com.android.chrome"
    assert stored.browser_visibility["chrome_detected"] is True
    assert len(stored.network_flows) == 1
    assert stored.network_flows[0]["destination_ip"] == "1.1.1.1"
    assert len(stored.capability_status) == 4


