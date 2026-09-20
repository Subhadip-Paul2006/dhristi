# Drishti v0.1 — Secure Local Agent State & Credential Store | Phase 01
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from common.identity import DeviceIdentity, create_new_identity
from common.platform import BasePlatformAdapter

logger = logging.getLogger("drishti.agent")


class AgentStateStore:
    """Manages local state files with strict file permissions and secret isolation."""

    def __init__(self, state_dir: Path | str):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.identity_file = self.state_dir / "identity.json"
        self.auth_file = self.state_dir / "auth.json"

    def _set_restricted_permissions(self, path: Path) -> None:
        """Apply strict owner-only permissions (0600) on POSIX platforms."""
        if not sys.platform.startswith("win"):
            try:
                os.chmod(path, 0o600)
            except Exception as e:
                logger.debug("Failed to set file permissions on %s: %s", path, e)

    def get_or_create_identity(
        self,
        platform_adapter: BasePlatformAdapter,
        agent_version: str = "0.1.0",
    ) -> DeviceIdentity:
        """Load persistent identity or generate and persist a fresh identity."""
        existing = DeviceIdentity.load(self.identity_file)
        if existing:
            # Refresh current runtime metadata without altering persistent agent_id/device_id
            existing.hostname = platform_adapter.get_hostname()
            existing.os = platform_adapter.get_os_name()
            existing.os_version = platform_adapter.get_os_version()
            existing.mac = platform_adapter.get_mac_address() or existing.mac
            existing.current_ip = platform_adapter.get_current_ip() or existing.current_ip
            existing.agent_version = agent_version
            existing.save(self.identity_file)
            self._set_restricted_permissions(self.identity_file)
            return existing

        new_ident = create_new_identity(
            hostname=platform_adapter.get_hostname(),
            os_name=platform_adapter.get_os_name(),
            os_version=platform_adapter.get_os_version(),
            mac=platform_adapter.get_mac_address(),
            current_ip=platform_adapter.get_current_ip(),
            agent_version=agent_version,
        )
        new_ident.save(self.identity_file)
        self._set_restricted_permissions(self.identity_file)
        logger.info("[Drishti Agent] Created new persistent device identity (Agent ID: %s)", new_ident.agent_id)
        return new_ident

    def save_auth(self, agent_token: str, org_id: str | None = None) -> None:
        """Persist authenticated token with restricted permissions."""
        data = {
            "agent_token": agent_token,
            "org_id": org_id,
        }
        with open(self.auth_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self._set_restricted_permissions(self.auth_file)
        logger.info("[Drishti Agent] Authentication credentials securely saved locally")

    def load_auth(self) -> tuple[str | None, str | None]:
        """Load saved credentials without logging secrets."""
        if not self.auth_file.exists():
            return None, None
        try:
            with open(self.auth_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            token = data.get("agent_token")
            org_id = data.get("org_id")
            return token, org_id
        except Exception:
            return None, None

    def clear_auth(self) -> None:
        """Revoke / clear local credentials."""
        if self.auth_file.exists():
            try:
                self.auth_file.unlink()
                logger.info("[Drishti Agent] Local credentials cleared")
            except Exception as e:
                logger.debug("Failed to remove auth file: %s", e)
