# Drishti v0.1 — Endpoint Agent & Pairing Backend Tests | Phase 01
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_agent_token
from app.models import Organization, User
from app.models.endpoint import EndpointAgent, EndpointPairingSession
from app.models.base import utcnow


@pytest.fixture
def test_org_and_user(db: Session):
    org = Organization(name="Test Org", slug=f"test-org-{uuid.uuid4().hex[:6]}")
    db.add(org)
    db.flush()

    user = User(
        org_id=org.id,
        email=f"operator-{uuid.uuid4().hex[:6]}@test.com",
        password_hash="fakehash",
        role="analyst",
    )
    db.add(user)
    db.commit()
    db.refresh(org)
    db.refresh(user)
    return org, user


def test_pairing_initialization(client: TestClient, db_session: Session):
    agent_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    payload = {
        "agent_id": agent_id,
        "device_id": device_id,
        "hostname": "test-workstation",
        "os": "windows",
        "os_version": "Windows 11 23H2",
        "mac": "aa:bb:cc:11:22:33",
        "current_ip": "192.168.1.105",
        "agent_version": "0.1.0",
    }
    res = client.post("/api/endpoint/pairing/init", json=payload)
    assert res.status_code == 200, res.text
    data = res.json()
    assert "session_id" in data
    assert "pairing_code" in data
    code = data["pairing_code"]
    assert len(code) == 9  # XXXX-XXXX
    assert "-" in code

    # Verify stored in DB
    sess = db_session.get(EndpointPairingSession, data["session_id"])
    assert sess is not None
    assert sess.agent_id == agent_id
    assert sess.status == "WAITING_FOR_PAIR"


def test_pairing_workflow_and_one_time_token_release(client: TestClient, db_session: Session, user_headers: dict):
    # 1. Agent initializes
    agent_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    init_res = client.post(
        "/api/endpoint/pairing/init",
        json={
            "agent_id": agent_id,
            "device_id": device_id,
            "hostname": "workstation-alpha",
            "os": "darwin",
            "os_version": "macOS 14.5",
            "mac": "00:50:56:c0:00:08",
            "current_ip": "192.168.1.120",
        },
    )
    assert init_res.status_code == 200
    init_data = init_res.json()
    session_id = init_data["session_id"]
    code = init_data["pairing_code"]

    # 2. Agent polls before operator submits -> WAITING_FOR_PAIR
    poll_1 = client.post(
        "/api/endpoint/pairing/status",
        json={"session_id": session_id, "agent_id": agent_id},
    )
    assert poll_1.status_code == 200
    assert poll_1.json()["status"] == "WAITING_FOR_PAIR"

    # 3. Invalid code rejection
    bad_pair = client.post(
        "/api/endpoint/pairing/pair",
        json={"pairing_code": "INVALID-CODE"},
        headers=user_headers,
    )
    assert bad_pair.status_code == 400

    # 4. Operator submits valid pairing code (case-insensitive & dash-tolerant)
    code_no_dash = code.replace("-", "").lower()
    pair_res = client.post(
        "/api/endpoint/pairing/pair",
        json={"pairing_code": code_no_dash},
        headers=user_headers,
    )
    assert pair_res.status_code == 200, pair_res.text
    pair_data = pair_res.json()
    assert pair_data["success"] is True
    assert pair_data["agent"]["hostname"] == "workstation-alpha"

    # 5. Agent polls after operator submits -> receives token exactly once!
    poll_2 = client.post(
        "/api/endpoint/pairing/status",
        json={"session_id": session_id, "agent_id": agent_id},
    )
    assert poll_2.status_code == 200
    assert poll_2.json()["status"] == "PAIRED"
    token = poll_2.json()["agent_token"]
    assert token is not None

    # 6. Subsequent poll -> status is CONSUMED and token is scrubbed
    poll_3 = client.post(
        "/api/endpoint/pairing/status",
        json={"session_id": session_id, "agent_id": agent_id},
    )
    assert poll_3.status_code == 200
    assert poll_3.json()["status"] == "CONSUMED"
    assert poll_3.json()["agent_token"] is None

    # 7. Reusing code is rejected
    reuse = client.post(
        "/api/endpoint/pairing/pair",
        json={"pairing_code": code},
        headers=user_headers,
    )
    assert reuse.status_code == 400

    # 8. Authenticated heartbeat using received token
    hb_res = client.post(
        "/api/endpoint/heartbeat",
        json={
            "agent_id": agent_id,
            "device_id": device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_version": "0.1.0",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert hb_res.status_code == 200, hb_res.text
    hb_data = hb_res.json()
    assert hb_data["status"] == "ACK"
    assert hb_data["derived_status"] == "ONLINE"


def test_pairing_code_expiration(client: TestClient, db_session: Session, user_headers: dict):
    # Initialize pairing session
    agent_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    init_res = client.post(
        "/api/endpoint/pairing/init",
        json={
            "agent_id": agent_id,
            "device_id": device_id,
            "hostname": "expired-host",
            "os": "windows",
            "os_version": "10.0",
        },
    )
    session_id = init_res.json()["session_id"]
    code = init_res.json()["pairing_code"]

    # Backdate session expiration
    sess = db_session.get(EndpointPairingSession, session_id)
    sess.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()

    # Operator attempting to pair expired code -> 400
    res = client.post(
        "/api/endpoint/pairing/pair",
        json={"pairing_code": code},
        headers=user_headers,
    )
    assert res.status_code == 400
    assert "expired" in res.json()["error"]["message"].lower() or "expired" in str(res.json()).lower()

    # Agent polling expired session -> EXPIRED
    poll = client.post(
        "/api/endpoint/pairing/status",
        json={"session_id": session_id, "agent_id": agent_id},
    )
    assert poll.status_code == 200
    assert poll.json()["status"] == "EXPIRED"


def test_heartbeat_unauthorized_rejection(client: TestClient):
    # No auth header
    res_no_auth = client.post(
        "/api/endpoint/heartbeat",
        json={"agent_id": "fake", "device_id": "fake", "timestamp": "2026-09-20T12:00:00Z"},
    )
    assert res_no_auth.status_code == 401

    # Bogus token
    res_bad_token = client.post(
        "/api/endpoint/heartbeat",
        json={"agent_id": "fake", "device_id": "fake", "timestamp": "2026-09-20T12:00:00Z"},
        headers={"Authorization": "Bearer invalid_secret_123"},
    )
    assert res_bad_token.status_code == 401


def test_endpoint_agent_derived_status(db_session: Session):
    now = datetime.now(timezone.utc)
    agent = EndpointAgent(
        org_id="org_1",
        agent_id="agent_1",
        device_id="device_1",
        hostname="srv-01",
        os="windows",
        os_version="11",
        agent_token_hash="hash",
    )

    # 1. No heartbeat -> OFFLINE
    assert agent.calculate_status(now) == "OFFLINE"

    # 2. Heartbeat 20 seconds ago -> ONLINE (<= 60s)
    agent.last_heartbeat = now - timedelta(seconds=20)
    assert agent.calculate_status(now) == "ONLINE"

    # 3. Heartbeat 100 seconds ago -> STALE (60s < t <= 180s)
    agent.last_heartbeat = now - timedelta(seconds=100)
    assert agent.calculate_status(now) == "STALE"

    # 4. Heartbeat 240 seconds ago -> OFFLINE (> 180s)
    agent.last_heartbeat = now - timedelta(seconds=240)
    assert agent.calculate_status(now) == "OFFLINE"


def test_list_and_get_agents_for_org(client: TestClient, user_headers: dict, db_session: Session):
    # Register agent via pairing
    init_res = client.post(
        "/api/endpoint/pairing/init",
        json={
            "agent_id": str(uuid.uuid4()),
            "device_id": str(uuid.uuid4()),
            "hostname": "finance-pc",
            "os": "windows",
            "os_version": "11.0",
        },
    )
    code = init_res.json()["pairing_code"]

    pair_res = client.post(
        "/api/endpoint/pairing/pair",
        json={"pairing_code": code},
        headers=user_headers,
    )
    agent_id = pair_res.json()["agent"]["agent_id"]

    # List endpoint agents
    list_res = client.get("/api/endpoint/agents", headers=user_headers)
    assert list_res.status_code == 200
    agents = list_res.json()
    assert any(a["agent_id"] == agent_id for a in agents)

    # Get single endpoint agent
    get_res = client.get(f"/api/endpoint/agents/{agent_id}", headers=user_headers)
    assert get_res.status_code == 200
    assert get_res.json()["hostname"] == "finance-pc"
    assert get_res.json()["status"] == "ONLINE"

