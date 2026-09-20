# Drishti v0.1 — Base Platform Adapter | Phase 01
from __future__ import annotations

from abc import ABC, abstractmethod


class BasePlatformAdapter(ABC):
    """Abstract interface for platform-specific hardware/OS discovery."""

    @abstractmethod
    def get_hostname(self) -> str:
        """Return the device's network hostname."""
        pass

    @abstractmethod
    def get_os_name(self) -> str:
        """Return normalized OS name ('windows', 'darwin', 'linux')."""
        pass

    @abstractmethod
    def get_os_version(self) -> str:
        """Return human-readable OS version and build."""
        pass

    @abstractmethod
    def get_mac_address(self) -> str | None:
        """Return physical hardware MAC address where available, or None."""
        pass

    @abstractmethod
    def get_current_ip(self) -> str | None:
        """Return current primary routable IP address, or None."""
        pass


def get_platform_adapter() -> BasePlatformAdapter:
    import sys
    if sys.platform.startswith("win"):
        from windows.platform import WindowsPlatformAdapter
        return WindowsPlatformAdapter()
    elif sys.platform == "darwin":
        from macos.platform import MacOSPlatformAdapter
        return MacOSPlatformAdapter()
    else:
        # Default Unix / POSIX fallback using standard Python libraries
        from windows.platform import WindowsPlatformAdapter
        return WindowsPlatformAdapter()

