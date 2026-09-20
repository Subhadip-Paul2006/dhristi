# Drishti v0.1 — Endpoint Telemetry E2E Integration Test | Phase 02
from __future__ import annotations

import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import NetworkDevice
from app.models.base import utcnow
from app.services.endpoint_telemetry import clear_telemetry_store


@pytest.fixture(autouse=True)
def clean_cache():
    clear_telemetry_store()
    yield
    clear_telemetry_store()


def test_endpoint_telemetry_full_e2e_flow(client: TestClient, db_session: Session, seed_acme_org, user_headers):
    org = seed_acme_org

    # 1. Agent launches on Windows workstation
    agent_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    mac_addr = "00:50:56:c0:00:08"
    ip_addr = "192.168.1.188"
    hostname = "win11-corp-sec"

    init_res = client.post(
        "/api/endpoint/pairing/init",
        json={
            "agent_id": agent_id,
            "device_id": device_id,
            "hostname": hostname,
            "os": "windows",
            "os_version": "11.0.22631",
            "mac": mac_addr,
            "current_ip": ip_addr,
            "agent_version": "0.1.0",
        },
    )
    assert init_res.status_code == 200
    init_data = init_res.json()
    session_id = init_data["session_id"]
    code = init_data["pairing_code"]

    # 2. Operator submits pairing code with auth
    pair_res = client.post(
        "/api/endpoint/pairing/pair",
        json={"pairing_code": code},
        headers=user_headers,
    )
    assert pair_res.status_code == 200, pair_res.text

    # 3. Agent polls pairing status and receives token
    poll_res = client.post(
        "/api/endpoint/pairing/status",
        json={"session_id": session_id, "agent_id": agent_id},
    )
    assert poll_res.status_code == 200
    token = poll_res.json()["agent_token"]
    assert token is not None

    # 4. Agent sends authenticated heartbeat
    now_iso = datetime.now(timezone.utc).isoformat()
    hb_res = client.post(
        "/api/endpoint/heartbeat",
        json={
            "agent_id": agent_id,
            "device_id": device_id,
            "timestamp": now_iso,
            "agent_version": "0.1.0",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert hb_res.status_code == 200
    assert hb_res.json()["derived_status"] == "ONLINE"

    # 5. Agent sends telemetry batch
    telem_payload = {
        "agent_id": agent_id,
        "device_id": device_id,
        "timestamp": now_iso,
        "hostname": hostname,
        "os_name": "windows",
        "os_version": "11.0.22631",
        "endpoint_processes": [
            {
                "pid": 5120,
                "name": "code.exe",
                "category": "USER_APPLICATION",
                "cpu_percent": 2.1,
                "memory_mb": 310.5,
            },
            {
                "pid": 1104,
                "name": "svchost.exe",
                "category": "SYSTEM_PROCESS",
                "cpu_percent": 0.05,
                "memory_mb": 18.2,
            },
        ],
        "active_apps": ["code.exe"],
        "installed_software": [
            {
                "name": "Visual Studio Code",
                "version": "1.92.0",
                "vendor": "Microsoft Corporation",
            }
        ],
        "services": [
            {
                "name": "DrishtiSvc",
                "display_name": "Drishti Security Agent",
                "status": "RUNNING",
            }
        ],
        "listening_ports": [
            {
                "port": 9001,
                "protocol": "TCP",
                "bind_address": "0.0.0.0",
                "pid": 5120,
                "process_name": "code.exe",
            }
        ],
        "process_connections": [
            {
                "pid": 5120,
                "process_name": "code.exe",
                "protocol": "TCP",
                "local_address": ip_addr,
                "local_port": 54100,
                "remote_address": "140.82.121.4",
                "remote_port": 443,
                "state": "ESTABLISHED",
            }
        ],
        "installed_browsers": ["Edge"],
        "browser_processes": [
            {
                "browser_name": "Edge",
                "pid": 7890,
            }
        ],
        "os_info": "windows 11.0.22631",
    }

    t_res = client.post(
        "/api/endpoint/telemetry",
        json=telem_payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert t_res.status_code == 200
    assert t_res.json()["processes_count"] == 2
    assert t_res.json()["ports_count"] == 1

    # 6. Dashboard user fetches device telemetry directly
    d_res = client.get(
        f"/api/endpoint/telemetry/{device_id}",
        headers=user_headers,
    )
    assert d_res.status_code == 200
    telemetry_data = d_res.json()
    assert telemetry_data["device_id"] == device_id
    assert len(telemetry_data["endpoint_processes"]) == 2
    assert telemetry_data["endpoint_processes"][0]["name"] == "code.exe"
    assert len(telemetry_data["listening_ports"]) == 1
    assert telemetry_data["listening_ports"][0]["port"] == 9001
    assert telemetry_data["is_stale"] is False

    # 7. Add two network devices: Device 1 matches agent IP/MAC; Device 2 is an unmanaged printer
    dev1 = NetworkDevice(
        org_id=org.id,
        ip=ip_addr,
        mac=mac_addr,
        hostname=hostname,
        online=True,
        first_seen=utcnow(),
        last_seen=utcnow(),
    )
    printer = NetworkDevice(
        org_id=org.id,
        ip="192.168.1.250",
        mac="99:88:77:66:55:44",
        hostname="network-printer-hp",
        online=True,
        first_seen=utcnow(),
        last_seen=utcnow(),
    )
    db_session.add_all([dev1, printer])
    db_session.commit()

    # 8. Dashboard fetches /api/live/devices
    live_res = client.get(
        "/api/live/devices",
        headers=user_headers,
    )
    assert live_res.status_code == 200
    devs = live_res.json()
    assert len(devs) >= 2

    # Find managed device and unmanaged printer
    managed_dev = next(d for d in devs if d["ip"] == ip_addr)
    unmanaged_dev = next(d for d in devs if d["ip"] == "192.168.1.250")

    # Verify managed device has genuine telemetry
    assert managed_dev["capability_state"] == "WINDOWS ENDPOINT"
    assert len(managed_dev["endpoint_processes"]) == 2
    assert any(p["name"] == "code.exe" for p in managed_dev["endpoint_processes"])
    assert len(managed_dev["listening_ports"]) == 1
    assert any(lp["name"] and "9001" in lp["name"] for lp in managed_dev["listening_ports"])
    assert len(managed_dev["installed_software"]) == 1
    assert managed_dev["is_telemetry_stale"] is False
    # Verify no fake browser tabs were inferred from process or network
    assert len(managed_dev["active_browser_tabs"]) == 0

    # Verify unmanaged device is strictly isolated (NETWORK ONLY, 0 processes)
    assert unmanaged_dev["capability_state"] == "NETWORK ONLY"
    assert len(unmanaged_dev["endpoint_processes"]) == 0
    assert len(unmanaged_dev["listening_ports"]) == 0
    assert len(unmanaged_dev["installed_software"]) == 0
