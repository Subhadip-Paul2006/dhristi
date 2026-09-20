# Drishti v0.1 — Persistent Endpoint Device Identity | Phase 01
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class DeviceIdentity:
    agent_id: str
    device_id: str
    hostname: str
    os: str
    os_version: str
    mac: str | None
    current_ip: str | None
    agent_version: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceIdentity:
        return cls(
            agent_id=data["agent_id"],
            device_id=data["device_id"],
            hostname=data.get("hostname", "unknown-host"),
            os=data.get("os", "unknown-os"),
            os_version=data.get("os_version", "unknown-version"),
            mac=data.get("mac"),
            current_ip=data.get("current_ip"),
            agent_version=data.get("agent_version", "0.1.0"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )

    def save(self, filepath: Path) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, filepath: Path) -> DeviceIdentity | None:
        if not filepath.exists():
            return None
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls.from_dict(data)
        except Exception:
            return None


def create_new_identity(
    hostname: str,
    os_name: str,
    os_version: str,
    mac: str | None = None,
    current_ip: str | None = None,
    agent_version: str = "0.1.0",
) -> DeviceIdentity:
    """Generate a clean new persistent identity with distinct agent_id and device_id."""
    agent_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    return DeviceIdentity(
        agent_id=agent_id,
        device_id=device_id,
        hostname=hostname,
        os=os_name,
        os_version=os_version,
        mac=mac,
        current_ip=current_ip,
        agent_version=agent_version,
        created_at=now_iso,
    )
