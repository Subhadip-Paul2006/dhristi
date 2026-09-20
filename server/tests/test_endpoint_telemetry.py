# Drishti v0.1 — Endpoint Telemetry Backend Unit & Integration Tests | Phase 02
from __future__ import annotations

import secrets
import time
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import hash_agent_token
from app.models import Organization, User
from app.models.base import utcnow
from app.models.endpoint import EndpointAgent
from app.services.endpoint_telemetry import (
    clear_telemetry_store,
    get_telemetry_for_device,
    record_telemetry,
)


@pytest.fixture(autouse=True)
def clean_telemetry_cache():
    clear_telemetry_store()
    yield
    clear_telemetry_store()


@pytest.fixture
def org_and_user(db_session: Session):
    org = Organization(name="Telemetry Org", slug=f"telem-org-{uuid.uuid4().hex[:6]}")
    db_session.add(org)
    db_session.flush()

    user = User(
        org_id=org.id,
        email=f"soc-analyst-{uuid.uuid4().hex[:6]}@drishti.local",
        password_hash="fakehash",
        role="analyst",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(org)
    db_session.refresh(user)
    return org, user


def _create_paired_agent(db: Session, org_id: str, hostname: str, os_name: str = "windows"):
    agent_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    raw_token = secrets.token_hex(32)
    token_h = hash_agent_token(raw_token)
    now = utcnow()

    agent = EndpointAgent(
        org_id=org_id,
        agent_id=agent_id,
        device_id=device_id,
        hostname=hostname,
        os=os_name,
        os_version="11.0.22631",
        mac="00:11:22:33:44:55",
        current_ip="192.168.1.100",
        agent_version="0.1.0",
        status="ONLINE",
        agent_token_hash=token_h,
        paired_at=now,
        registered_at=now,
        last_heartbeat=now,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent, raw_token


def test_telemetry_ingestion_success(client: TestClient, db_session: Session, org_and_user):
    org, user = org_and_user
    agent, raw_token = _create_paired_agent(db_session, org.id, "lab-workstation-win")

    now_iso = datetime.now(timezone.utc).isoformat()
    payload = {
        "agent_id": agent.agent_id,
        "device_id": agent.device_id,
        "timestamp": now_iso,
        "hostname": agent.hostname,
        "os_name": agent.os,
        "os_version": agent.os_version,
        "endpoint_processes": [
            {
                "pid": 4500,
                "name": "code.exe",
                "category": "USER_APPLICATION",
                "cpu_percent": 1.5,
                "memory_mb": 250.0,
                "exe_path": r"C:\Users\analyst\AppData\Local\Programs\VSCode\Code.exe",
            },
            {
                "pid": 1200,
                "name": "services.exe",
                "category": "SYSTEM_PROCESS",
                "cpu_percent": 0.1,
                "memory_mb": 30.0,
            },
        ],
        "active_apps": ["code.exe"],
        "installed_software": [
            {
                "name": "Visual Studio Code",
                "version": "1.92.0",
                "vendor": "Microsoft Corporation",
                "source": "winreg_uninstall",
            }
        ],
        "services": [
            {
                "name": "DrishtiAgent",
                "display_name": "Drishti Endpoint Agent",
                "status": "RUNNING",
                "start_type": "AUTO_START",
                "pid": 3200,
            }
        ],
        "listening_ports": [
            {
                "port": 8000,
                "protocol": "TCP",
                "bind_address": "127.0.0.1",
                "pid": 4500,
                "process_name": "code.exe",
            }
        ],
        "process_connections": [
            {
                "pid": 4500,
                "process_name": "code.exe",
                "protocol": "TCP",
                "local_address": "192.168.1.100",
                "local_port": 54321,
                "remote_address": "20.42.73.27",
                "remote_port": 443,
                "state": "ESTABLISHED",
            }
        ],
        "installed_browsers": ["Edge"],
        "browser_processes": [
            {
                "browser_name": "Edge",
                "pid": 6000,
                "exe_path": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            }
        ],
        "os_info": "windows 11.0.22631",
    }

    res = client.post(
        "/api/endpoint/telemetry",
        json=payload,
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["success"] is True
    assert data["processes_count"] == 2
    assert data["software_count"] == 1
    assert data["services_count"] == 1
    assert data["ports_count"] == 1


def test_telemetry_ingestion_identity_mismatch_rejection(client: TestClient, db_session: Session, org_and_user):
    org, user = org_and_user
    agent, raw_token = _create_paired_agent(db_session, org.id, "lab-pc")

    # Mismatched agent_id
    bad_payload = {
        "agent_id": str(uuid.uuid4()),
        "device_id": agent.device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint_processes": [],
    }

    res = client.post(
        "/api/endpoint/telemetry",
        json=bad_payload,
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert res.status_code == 403

    # Mismatched device_id
    bad_payload2 = {
        "agent_id": agent.agent_id,
        "device_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint_processes": [],
    }

    res2 = client.post(
        "/api/endpoint/telemetry",
        json=bad_payload2,
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert res2.status_code == 403


def test_cross_device_telemetry_isolation(client: TestClient, db_session: Session, org_and_user):
    """Device A telemetry must never leak into Device B."""
    org, user = org_and_user
    agentA, tokenA = _create_paired_agent(db_session, org.id, "workstation-A")
    agentB, tokenB = _create_paired_agent(db_session, org.id, "workstation-B")

    now_iso = datetime.now(timezone.utc).isoformat()

    # Ingest for Device A: runs app_a.exe on port 7001
    client.post(
        "/api/endpoint/telemetry",
        json={
            "agent_id": agentA.agent_id,
            "device_id": agentA.device_id,
            "timestamp": now_iso,
            "hostname": "workstation-A",
            "endpoint_processes": [{"pid": 111, "name": "app_a.exe", "category": "USER_APPLICATION"}],
            "listening_ports": [{"port": 7001, "protocol": "TCP", "bind_address": "0.0.0.0", "pid": 111, "process_name": "app_a.exe"}],
        },
        headers={"Authorization": f"Bearer {tokenA}"},
    )

    # Ingest for Device B: runs app_b.exe on port 8002
    client.post(
        "/api/endpoint/telemetry",
        json={
            "agent_id": agentB.agent_id,
            "device_id": agentB.device_id,
            "timestamp": now_iso,
            "hostname": "workstation-B",
            "endpoint_processes": [{"pid": 222, "name": "app_b.exe", "category": "USER_APPLICATION"}],
            "listening_ports": [{"port": 8002, "protocol": "TCP", "bind_address": "0.0.0.0", "pid": 222, "process_name": "app_b.exe"}],
        },
        headers={"Authorization": f"Bearer {tokenB}"},
    )

    # Query device A via service
    telemA = get_telemetry_for_device(org.id, agentA.device_id)
    assert telemA is not None
    assert len(telemA.endpoint_processes) == 1
    assert telemA.endpoint_processes[0].name == "app_a.exe"
    assert len(telemA.listening_ports) == 1
    assert telemA.listening_ports[0].port == 7001

    # Query device B via service
    telemB = get_telemetry_for_device(org.id, agentB.device_id)
    assert telemB is not None
    assert len(telemB.endpoint_processes) == 1
    assert telemB.endpoint_processes[0].name == "app_b.exe"
    assert len(telemB.listening_ports) == 1
    assert telemB.listening_ports[0].port == 8002

    # Verify Device A contains NO trace of Device B
    assert not any(p.name == "app_b.exe" for p in telemA.endpoint_processes)
    assert not any(lp.port == 8002 for lp in telemA.listening_ports)


def test_telemetry_ttl_stale_detection(client: TestClient, db_session: Session, org_and_user):
    """Volatile telemetry goes stale after 60s; software inventory goes stale after 300s."""
    org, user = org_and_user
    agent, token = _create_paired_agent(db_session, org.id, "ttl-test-pc")

    now_iso = datetime.now(timezone.utc).isoformat()
    client.post(
        "/api/endpoint/telemetry",
        json={
            "agent_id": agent.agent_id,
            "device_id": agent.device_id,
            "timestamp": now_iso,
            "endpoint_processes": [{"pid": 100, "name": "editor.exe"}],
            "installed_software": [{"name": "Python", "version": "3.11"}],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    # Immediate query: fresh
    fresh = get_telemetry_for_device(org.id, agent.device_id)
    assert fresh is not None
    assert fresh.is_stale is False
    assert fresh.is_software_stale is False

    # Simulate 65s later: volatile is stale, software is still fresh (< 300s)
    simulated_mono = time.monotonic() + 65.0
    stale_volatile = get_telemetry_for_device(org.id, agent.device_id, reference_mono=simulated_mono)
    assert stale_volatile is not None
    assert stale_volatile.is_stale is True
    assert stale_volatile.is_software_stale is False

    # Simulate 310s later: both volatile and software are stale
    simulated_mono_slow = time.monotonic() + 310.0
    stale_both = get_telemetry_for_device(org.id, agent.device_id, reference_mono=simulated_mono_slow)
    assert stale_both is not None
    assert stale_both.is_stale is True
    assert stale_both.is_software_stale is True


def test_unpaired_device_returns_empty_telemetry(org_and_user):
    org, user = org_and_user
    unpaired_id = str(uuid.uuid4())
    telem = get_telemetry_for_device(org.id, unpaired_id)
    assert telem is None
