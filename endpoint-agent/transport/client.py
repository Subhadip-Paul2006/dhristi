# Drishti v0.1 — Endpoint Agent Transport Client | Phase 01
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger("drishti.agent")


class TransportError(Exception):
    """General network or transport communication failure."""
    pass


class AgentUnauthorizedError(TransportError):
    """401 Unauthorized indicating agent token is invalid or revoked."""
    pass


class SessionNotFoundError(TransportError):
    """404 Not Found indicating pairing session or agent does not exist."""
    pass


class BackendTransport:
    """Zero-dependency HTTP transport client for backend communication."""

    def __init__(self, server_url: str, timeout_seconds: float = 10.0):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout_seconds

    def _request(
        self,
        endpoint: str,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Drishti-Endpoint-Agent/0.1.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        data_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode("utf-8")
            except Exception:
                pass

            if e.code == 401:
                raise AgentUnauthorizedError(f"Unauthorized (401): {error_body}") from e
            elif e.code == 404:
                raise SessionNotFoundError(f"Not Found (404): {error_body}") from e
            else:
                raise TransportError(f"HTTP {e.code}: {error_body or e.reason}") from e
        except urllib.error.URLError as e:
            raise TransportError(f"Connection failed: {e.reason}") from e
        except TimeoutError as e:
            raise TransportError(f"Request timed out after {self.timeout}s") from e
        except Exception as e:
            raise TransportError(f"Unexpected transport error: {e}") from e

    def init_pairing(self, identity_data: dict[str, Any]) -> dict[str, Any]:
        """Request a short-lived pairing session from the backend."""
        return self._request(
            "/api/endpoint/pairing/init",
            method="POST",
            payload=identity_data,
        )

    def check_pairing_status(self, session_id: str, agent_id: str) -> dict[str, Any]:
        """Poll pairing status for the specified session."""
        return self._request(
            "/api/endpoint/pairing/status",
            method="POST",
            payload={"session_id": session_id, "agent_id": agent_id},
        )

    def send_heartbeat(self, agent_token: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Transmit authenticated periodic heartbeat telemetry."""
        return self._request(
            "/api/endpoint/heartbeat",
            method="POST",
            payload=payload,
            token=agent_token,
        )

    def send_telemetry(self, agent_token: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Transmit authenticated endpoint telemetry payload."""
        return self._request(
            "/api/endpoint/telemetry",
            method="POST",
            payload=payload,
            token=agent_token,
        )

