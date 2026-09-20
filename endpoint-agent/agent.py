# Drishti v0.1 — Drishti Endpoint Agent Orchestrator | Phase 01
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from collectors.manager import CollectorManager
from common.config import AgentConfig
from common.identity import DeviceIdentity
from common.lifecycle import AgentState, LifecycleManager
from common.platform import BasePlatformAdapter, get_platform_adapter
from storage.state import AgentStateStore
from transport.client import (
    AgentUnauthorizedError,
    BackendTransport,
    TransportError,
)

logger = logging.getLogger("drishti.agent")


class DrishtiEndpointAgent:
    """Core Drishti Endpoint Agent coordinating identity, pairing, heartbeats, and telemetry."""

    def __init__(
        self,
        config: AgentConfig | None = None,
        platform_adapter: BasePlatformAdapter | None = None,
        transport: BackendTransport | None = None,
        collector_manager: CollectorManager | None = None,
    ):
        self.config = config or AgentConfig.default()
        self.platform = platform_adapter or get_platform_adapter()
        self.state_store = AgentStateStore(self.config.resolve_state_path())
        self.lifecycle = LifecycleManager(AgentState.STARTING)
        self.transport = transport or BackendTransport(
            self.config.server_url,
            timeout_seconds=self.config.request_timeout_seconds,
        )

        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None

        # Load or create persistent device identity
        self.identity: DeviceIdentity = self.state_store.get_or_create_identity(
            self.platform,
            agent_version=self.config.agent_version,
        )

        self.collector_manager = collector_manager or CollectorManager(
            identity=self.identity,
            software_interval_seconds=self.config.software_interval_seconds,
        )
        self._last_telemetry_time: float = 0.0

        logger.info(
            "[Drishti Agent] Initialized on '%s' (%s %s) [Agent ID: %s]",
            self.identity.hostname,
            self.identity.os,
            self.identity.os_version,
            self.identity.agent_id,
        )
        self._current_session_id: str | None = None

    @property
    def token(self) -> str | None:
        token, _ = self.state_store.load_auth()
        return token

    def is_paired(self) -> bool:
        return self.token is not None

    def initiate_pairing(self) -> tuple[str, str]:
        """Request pairing session and transition to WAITING_FOR_PAIRING."""
        self.lifecycle.transition_to(AgentState.WAITING_FOR_PAIRING)
        init_res = self.transport.init_pairing(self.identity.to_dict())
        self._current_session_id = init_res["session_id"]
        pairing_code = init_res["pairing_code"]
        return self._current_session_id, pairing_code

    def check_pairing_status(self, session_id: str | None = None) -> bool:
        """Check pairing status for the given or current session. Returns True if PAIRED and token saved."""
        sid = session_id or self._current_session_id
        if not sid:
            return False
        status_res = self.transport.check_pairing_status(sid, self.identity.agent_id)
        if status_res.get("status") == "PAIRED":
            token = status_res.get("agent_token")
            org_id = status_res.get("org_id")
            if token:
                self.state_store.save_auth(token, org_id)
                self.lifecycle.transition_to(AgentState.CONNECTED, reason="Pairing confirmed")
                return True
        return False

    def send_heartbeat(self, token: str | None = None) -> dict[str, Any]:
        """Send a single authenticated heartbeat with genuine identity metadata."""
        auth_token = token or self.token
        if not auth_token:
            raise TransportError("Cannot send heartbeat: agent is not paired / no token available")
        now_iso = datetime.now(timezone.utc).isoformat()
        payload = {
            "agent_id": self.identity.agent_id,
            "device_id": self.identity.device_id,
            "timestamp": now_iso,
            "agent_version": self.config.agent_version,
            "collector_health": {"identity": "OK", "platform": "OK"},
            "connectivity": {"status": "ONLINE"},
        }
        return self.transport.send_heartbeat(auth_token, payload)

    def collect_and_send_telemetry(self, token: str | None = None, force_slow: bool = False) -> dict[str, Any] | None:
        """Collect current endpoint telemetry and transmit to backend."""
        auth_token = token or self.token
        if not auth_token:
            logger.warning("[Drishti Agent] Cannot send telemetry: agent is not paired / no token available")
            return None

        batch = self.collector_manager.collect_all(force_slow_collect=force_slow)
        payload = batch.to_dict()
        try:
            res = self.transport.send_telemetry(auth_token, payload)
            self._last_telemetry_time = time.monotonic()
            logger.info(
                "[Drishti Agent] Telemetry uploaded successfully (processes: %d, ports: %d, software: %d, services: %d)",
                len(batch.endpoint_processes),
                len(batch.listening_ports),
                len(batch.installed_software),
                len(batch.services),
            )
            return res
        except Exception as e:
            logger.warning("[Drishti Agent] Failed to upload telemetry: %s", e)
            raise

    def print_pairing_banner(self, pairing_code: str, expires_at_str: str) -> None:
        banner = (
            "\n"
            "===============================================================\n"
            "               DRISHTI ENDPOINT AGENT — PAIRING                \n"
            "===============================================================\n"
            f"  Device Hostname : {self.identity.hostname}\n"
            f"  Operating System: {self.identity.os} ({self.identity.os_version})\n"
            f"  Device ID       : {self.identity.device_id}\n"
            f"  Agent ID        : {self.identity.agent_id}\n"
            "---------------------------------------------------------------\n"
            f"  PAIRING CODE    : {pairing_code}\n"
            f"  EXPIRES AT      : {expires_at_str}\n"
            "---------------------------------------------------------------\n"
            "  Enter this code in your Drishti SOC Dashboard:\n"
            "  Dashboard / Live Watch -> Click 'Pair Endpoint Agent'\n"
            "===============================================================\n"
        )
        print(banner)
        logger.info("[Drishti Agent] Pairing code active: %s", pairing_code)

    def perform_pairing_flow(self) -> str:
        """Initiate pairing and poll until authenticated by dashboard operator."""
        while not self._stop_event.is_set():
            self.lifecycle.transition_to(AgentState.WAITING_FOR_PAIRING)
            try:
                init_res = self.transport.init_pairing(self.identity.to_dict())
                session_id = init_res["session_id"]
                pairing_code = init_res["pairing_code"]
                expires_at = init_res["expires_at"]
                self.print_pairing_banner(pairing_code, expires_at)
            except TransportError as e:
                logger.warning("[Drishti Agent] Unable to connect to server for pairing init: %s. Retrying in 5s...", e)
                if self._stop_event.wait(5.0):
                    break
                continue

            # Poll for pairing completion
            while not self._stop_event.is_set():
                if self._stop_event.wait(self.config.pairing_poll_interval_seconds):
                    break

                try:
                    status_res = self.transport.check_pairing_status(session_id, self.identity.agent_id)
                    status = status_res.get("status")

                    if status == "PAIRED":
                        token = status_res.get("agent_token")
                        org_id = status_res.get("org_id")
                        if not token:
                            logger.error("[Drishti Agent] Server indicated PAIRED but returned no token")
                            break
                        self.state_store.save_auth(token, org_id)
                        self.lifecycle.transition_to(AgentState.CONNECTED, reason="Pairing confirmed by dashboard")
                        print("\n[Drishti Agent] >>> PAIRING CONFIRMED & AGENT REGISTERED! <<<\n")
                        return token

                    elif status == "EXPIRED":
                        logger.info("[Drishti Agent] Pairing code expired. Generating fresh pairing session...")
                        break  # Break inner loop to generate fresh pairing session

                    elif status == "WAITING_FOR_PAIR":
                        logger.debug("[Drishti Agent] Waiting for dashboard operator to enter code...")

                    else:
                        logger.info("[Drishti Agent] Pairing session ended with status: %s", status)
                        break

                except TransportError as e:
                    logger.debug("[Drishti Agent] Error polling pairing status: %s", e)

        return ""

    def run_heartbeat_loop(self, token: str) -> None:
        """Run authenticated periodic heartbeat loop with graceful backoff on network blips."""
        current_delay = self.config.reconnect_initial_delay_seconds

        # Immediately trigger initial telemetry collection so dashboard displays data on pair
        try:
            self.collect_and_send_telemetry(token, force_slow=True)
        except Exception as te:
            logger.warning("[Drishti Agent] Initial telemetry collection blip: %s", te)

        while not self._stop_event.is_set():
            now_iso = datetime.now(timezone.utc).isoformat()
            payload = {
                "agent_id": self.identity.agent_id,
                "device_id": self.identity.device_id,
                "timestamp": now_iso,
                "agent_version": self.config.agent_version,
                "collector_health": {"identity": "OK", "platform": "OK"},
                "connectivity": {"status": "ONLINE"},
            }

            try:
                res = self.transport.send_heartbeat(token, payload)
                if self.lifecycle.current_state == AgentState.RECONNECTING:
                    self.lifecycle.transition_to(AgentState.CONNECTED, reason="Connection restored")
                    current_delay = self.config.reconnect_initial_delay_seconds
                logger.info(
                    "[Drishti Agent] Heartbeat ACK received (status: %s, server_time: %s)",
                    res.get("derived_status", "ONLINE"),
                    res.get("server_time"),
                )

                # Periodic telemetry collection
                now_mono = time.monotonic()
                if (now_mono - self._last_telemetry_time) >= self.config.telemetry_interval_seconds:
                    try:
                        self.collect_and_send_telemetry(token)
                    except Exception as te:
                        logger.warning("[Drishti Agent] Periodic telemetry upload blip: %s", te)

                if self._stop_event.wait(self.config.heartbeat_interval_seconds):
                    break

            except AgentUnauthorizedError as e:
                logger.warning("[Drishti Agent] Authentication rejected (401): %s. Clearing local token...", e)
                self.state_store.clear_auth()
                self.lifecycle.transition_to(AgentState.WAITING_FOR_PAIRING, reason="Token invalid or revoked")
                # Return to pairing flow
                token = self.perform_pairing_flow()
                if not token:
                    break

            except TransportError as e:
                if self.lifecycle.current_state != AgentState.RECONNECTING:
                    self.lifecycle.transition_to(AgentState.RECONNECTING, reason=str(e))
                logger.warning(
                    "[Drishti Agent] Heartbeat connection error: %s. Reconnecting in %.1fs...",
                    e,
                    current_delay,
                )
                if self._stop_event.wait(current_delay):
                    break
                current_delay = min(
                    current_delay * self.config.reconnect_backoff_factor,
                    self.config.reconnect_max_delay_seconds,
                )

    def start(self, block: bool = True) -> None:
        """Start the agent lifecycle in the current or background thread."""
        self._stop_event.clear()

        def _target():
            token, _ = self.state_store.load_auth()
            if token:
                logger.info("[Drishti Agent] Found existing authenticated credentials. Testing connection...")
                try:
                    # Test token with immediate heartbeat
                    now_iso = datetime.now(timezone.utc).isoformat()
                    self.transport.send_heartbeat(
                        token,
                        {
                            "agent_id": self.identity.agent_id,
                            "device_id": self.identity.device_id,
                            "timestamp": now_iso,
                            "agent_version": self.config.agent_version,
                        },
                    )
                    self.lifecycle.transition_to(AgentState.CONNECTED, reason="Existing credentials verified")
                except AgentUnauthorizedError:
                    logger.info("[Drishti Agent] Existing credentials no longer valid on server. Re-pairing...")
                    self.state_store.clear_auth()
                    token = self.perform_pairing_flow()
                except TransportError as e:
                    logger.warning("[Drishti Agent] Server not immediately reachable: %s. Will retry with saved credentials.", e)
                    self.lifecycle.transition_to(AgentState.RECONNECTING, reason=str(e))
            else:
                token = self.perform_pairing_flow()

            if token and not self._stop_event.is_set():
                self.run_heartbeat_loop(token)

            self.lifecycle.transition_to(AgentState.STOPPED, reason="Shutdown complete")
            logger.info("[Drishti Agent] Agent process exited cleanly.")

        if block:
            _target()
        else:
            self._worker_thread = threading.Thread(target=_target, daemon=True, name="DrishtiAgentWorker")
            self._worker_thread.start()

    def stop(self) -> None:
        """Signal graceful termination."""
        logger.info("[Drishti Agent] Stopping agent gracefully...")
        self.lifecycle.transition_to(AgentState.STOPPING)
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)
        self.lifecycle.transition_to(AgentState.STOPPED, reason="Shutdown complete")
