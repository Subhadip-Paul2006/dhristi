# Drishti v0.1 — Endpoint Agent Configuration | Phase 01
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AgentConfig:
    server_url: str = "http://localhost:8000"
    pairing_poll_interval_seconds: float = 3.0
    heartbeat_interval_seconds: float = 45.0
    telemetry_interval_seconds: float = 60.0
    software_interval_seconds: float = 300.0
    reconnect_initial_delay_seconds: float = 2.0
    reconnect_max_delay_seconds: float = 30.0
    reconnect_backoff_factor: float = 1.5
    request_timeout_seconds: float = 10.0
    state_dir: str | None = None
    agent_version: str = "0.1.0"

    @classmethod
    def default(cls) -> AgentConfig:
        env_server = os.environ.get("DRISHTI_SERVER_URL", "http://localhost:8000")
        env_state = os.environ.get("DRISHTI_STATE_DIR")
        return cls(
            server_url=env_server.rstrip("/"),
            state_dir=env_state,
        )

    def resolve_state_path(self) -> Path:
        if self.state_dir:
            path = Path(self.state_dir)
        else:
            home = Path.home()
            path = home / ".drishti" / "agent"
        path.mkdir(parents=True, exist_ok=True)
        return path
