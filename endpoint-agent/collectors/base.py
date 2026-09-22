# Drishti v0.1 — Base Collector Interfaces | Phase 02 (rev 2)
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
from collectors.contracts import (
    BrowserProcessItem,
    CpuInfo,
    ListeningPortItem,
    MemoryInfo,
    NetworkInterfaceInfo,
    ProcessItem,
    ServiceItem,
    SocketConnectionItem,
    SoftwareItem,
)


class BaseProcessCollector(ABC):
    """Abstract base class for platform process enumeration."""

    @abstractmethod
    def collect_processes(self) -> tuple[list[ProcessItem], list[str]]:
        """Return (all_processes, active_user_applications)."""
        pass


class BaseSoftwareCollector(ABC):
    """Abstract base class for platform software inventory."""

    @abstractmethod
    def collect_software(self) -> list[SoftwareItem]:
        """Return list of installed software."""
        pass


class BaseServiceCollector(ABC):
    """Abstract base class for platform service enumeration."""

    @abstractmethod
    def collect_services(self) -> list[ServiceItem]:
        """Return list of local services."""
        pass


class BaseSocketCollector(ABC):
    """Abstract base class for platform network socket enumeration."""

    @abstractmethod
    def collect_sockets(self) -> tuple[list[ListeningPortItem], list[SocketConnectionItem]]:
        """Return (listening_ports, active_connections)."""
        pass


class BaseBrowserCollector(ABC):
    """Abstract base class for platform browser process detection."""

    @abstractmethod
    def collect_browsers(self) -> tuple[list[str], list[BrowserProcessItem]]:
        """Return (installed_or_running_browser_names, browser_process_items)."""
        pass


class BaseHardwareCollector(ABC):
    """Abstract base class for CPU, Memory, and Network interface collection.

    This replaces the missing hardware telemetry layer for desktop/laptop endpoints.
    Android uses its own mobile-specific telemetry path.
    """

    @abstractmethod
    def collect_cpu(self) -> CpuInfo:
        """Return a CpuInfo snapshot with overall and per-core usage."""
        pass

    @abstractmethod
    def collect_memory(self) -> MemoryInfo:
        """Return a MemoryInfo snapshot with total/available/used bytes."""
        pass

    @abstractmethod
    def collect_network_interfaces(self) -> list[NetworkInterfaceInfo]:
        """Return a list of active network interfaces with their addresses."""
        pass
