# server/tests/test_endpoint_e2e_integration.py
# E2E Integration test for Drishti Endpoint Agent Foundation (Phase 01)
import os
import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
import pytest
from starlette.testclient import TestClient

# Ensure endpoint-agent is in python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ENDPOINT_AGENT_DIR = os.path.join(ROOT_DIR, "endpoint-agent")
if ENDPOINT_AGENT_DIR not in sys.path:
    sys.path.insert(0, ENDPOINT_AGENT_DIR)

from common.config import AgentConfig
from common.identity import DeviceIdentity
from common.lifecycle import AgentState
from storage.state import AgentStateStore
from agent import DrishtiEndpointAgent
from transport.client import BackendTransport, TransportError


class FastApiTransport(BackendTransport):
    """Adapter to route BackendTransport calls directly to FastAPI TestClient."""

    def __init__(self, test_client: TestClient):
        super().__init__(server_url="http://testserver")
        self.test_client = test_client

    def _request(self, endpoint: str, method: str = "GET", payload=None, token=None):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        url = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        resp = self.test_client.request(method, url, json=payload, headers=headers)
        if resp.status_code >= 400:
            raise TransportError(f"HTTP {resp.status_code}: {resp.text}")
        return resp.json()


def test_endpoint_agent_e2e_lifecycle(client: TestClient, db_session, user_headers):
    """
    Mandatory Phase 01 Integration Flow:
    Agent -> Pair -> Backend -> Device Registered -> Authenticated Heartbeat -> Dashboard reflects device status
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        config = AgentConfig(
            server_url="http://testserver",
            state_dir=tmpdir,
            heartbeat_interval_seconds=1.0,
            reconnect_initial_delay_seconds=0.1,
            reconnect_max_delay_seconds=0.5,
        )
        transport = FastApiTransport(client)
        agent = DrishtiEndpointAgent(config=config, transport=transport)

        # 1. Agent starts up and prepares pairing session
        assert agent.lifecycle.state == AgentState.STARTING
        session_id, pairing_code = agent.initiate_pairing()

        assert session_id is not None
        assert pairing_code is not None
        assert len(pairing_code.replace("-", "")) == 8
        assert agent.lifecycle.state == AgentState.WAITING_FOR_PAIRING

        # Verify agent cannot poll paired status yet
        is_paired = agent.check_pairing_status()
        assert not is_paired

        # 2. Operator on Dashboard enters pairing code
        # (Dashboard user is authenticated)
        pair_submit_resp = client.post(
            "/api/endpoint/pairing/pair",
            json={"pairing_code": pairing_code},
            headers=user_headers,
        )
        assert pair_submit_resp.status_code == 200, pair_submit_resp.text
        pair_data = pair_submit_resp.json()
        assert pair_data["success"] is True
        assert pair_data["agent"]["agent_id"] == agent.identity.agent_id
        assert pair_data["agent"]["hostname"] == agent.identity.hostname

        # 3. Agent polls status, discovers it is paired, receives token, saves to state store
        is_paired_after = agent.check_pairing_status()
        assert is_paired_after is True
        assert agent.token is not None
        assert agent.lifecycle.state == AgentState.CONNECTED

        # Verify token was written to local state
        reloaded_store = AgentStateStore(tmpdir)
        reloaded_token, _ = reloaded_store.load_auth()
        assert reloaded_token == agent.token

        # 4. Agent sends authenticated heartbeat
        hb_resp = agent.send_heartbeat()
        assert hb_resp["status"] == "ACK"
        assert "server_time" in hb_resp

        # 5. Dashboard reflects registered device and factual server-derived status
        agents_list_resp = client.get(
            "/api/endpoint/agents",
            headers=user_headers,
        )
        assert agents_list_resp.status_code == 200
        agents = agents_list_resp.json()
        assert len(agents) == 1
        dev = agents[0]
        assert dev["agent_id"] == agent.identity.agent_id
        assert dev["hostname"] == agent.identity.hostname
        assert dev["os"] == agent.identity.os
        assert dev["os_version"] == agent.identity.os_version
        assert dev["status"] == "ONLINE"
        assert dev["last_heartbeat"] is not None

        # 6. Verify duplicate registration prevention:
        # Agent restarts with existing persisted state
        agent_restarted = DrishtiEndpointAgent(config=config, transport=transport)
        # It detects it is already paired from stored token!
        assert agent_restarted.is_paired()
        assert agent_restarted.token == agent.token
        # It sends heartbeat immediately without re-pairing
        hb2 = agent_restarted.send_heartbeat()
        assert hb2["status"] == "ACK"

        # Verify no duplicate agent record was created
        agents_after = client.get(
            "/api/endpoint/agents",
            headers=user_headers,
        ).json()
        assert len(agents_after) == 1

        # 7. Graceful shutdown
        agent.stop()
        assert agent.lifecycle.state == AgentState.STOPPED
