# Drishti v0.1 — macOS Platform Adapter | Phase 01
from __future__ import annotations

import platform
import socket
import uuid
from common.platform import BasePlatformAdapter


class MacOSPlatformAdapter(BasePlatformAdapter):
    """Genuine macOS hardware and OS metadata collector."""

    def get_hostname(self) -> str:
        try:
            return socket.gethostname()
        except Exception:
            return "macos-host"

    def get_os_name(self) -> str:
        return "darwin"

    def get_os_version(self) -> str:
        try:
            mac_ver, _, _ = platform.mac_ver()
            if mac_ver:
                return f"macOS {mac_ver}"
            return f"Darwin {platform.release()}"
        except Exception:
            return "macOS Unknown"

    def get_mac_address(self) -> str | None:
        try:
            node = uuid.getnode()
            if (node >> 40) & 1:
                return None
            mac_hex = f"{node:012x}"
            return ":".join(mac_hex[i:i + 2] for i in range(0, 12, 2))
        except Exception:
            return None

    def get_current_ip(self) -> str | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return None
        finally:
            s.close()
