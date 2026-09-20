# Drishti v0.1 — Windows Platform Adapter | Phase 01
from __future__ import annotations

import platform
import socket
import uuid
from common.platform import BasePlatformAdapter


class WindowsPlatformAdapter(BasePlatformAdapter):
    """Genuine Windows hardware and OS metadata collector."""

    def get_hostname(self) -> str:
        try:
            return socket.gethostname()
        except Exception:
            return "windows-host"

    def get_os_name(self) -> str:
        return "windows"

    def get_os_version(self) -> str:
        try:
            rel = platform.release()
            ver = platform.version()
            return f"Windows {rel} (Build {ver})"
        except Exception:
            return "Windows Unknown"

    def get_mac_address(self) -> str | None:
        try:
            node = uuid.getnode()
            # If highest bit of 1st octet is 1, it's a random multicast MAC
            if (node >> 40) & 1:
                return None
            mac_hex = f"{node:012x}"
            return ":".join(mac_hex[i:i + 2] for i in range(0, 12, 2))
        except Exception:
            return None

    def get_current_ip(self) -> str | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Does not actually transmit packets, just resolves local routing interface
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return None
        finally:
            s.close()
