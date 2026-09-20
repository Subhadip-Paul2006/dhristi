# Drishti v0.1 — Endpoint Telemetry Data Contracts | Phase 02
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ProcessCategory(str, Enum):
    USER_APPLICATION = "USER_APPLICATION"
    BACKGROUND_PROCESS = "BACKGROUND_PROCESS"
    SYSTEM_PROCESS = "SYSTEM_PROCESS"


@dataclass
class ProcessItem:
    pid: int
    name: str
    ppid: int | None = None
    exe_path: str | None = None
    cmdline: list[str] | None = None
    category: str = ProcessCategory.BACKGROUND_PROCESS.value
    start_time: str | None = None
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_collector"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SoftwareItem:
    name: str
    version: str | None = None
    publisher: str | None = None
    install_location: str | None = None
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_inventory"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceItem:
    name: str
    display_name: str | None = None
    status: str = "UNKNOWN"  # RUNNING, STOPPED, PAUSED, etc.
    start_type: str | None = None  # AUTO, MANUAL, DISABLED, etc.
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_services"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ListeningPortItem:
    protocol: str  # TCP, UDP
    local_address: str
    local_port: int
    pid: int | None = None
    process_name: str | None = None
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_sockets"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SocketConnectionItem:
    pid: int | None
    process_name: str | None
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str  # ESTABLISHED, SYN_SENT, TIME_WAIT, etc.
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_sockets"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BrowserProcessItem:
    browser_name: str  # Chrome, Edge, Brave, Firefox, Arc
    pid: int
    exe_path: str | None = None
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "endpoint_browser"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TelemetryBatch:
    agent_id: str
    device_id: str
    hostname: str
    os_name: str
    os_version: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    endpoint_processes: list[ProcessItem] = field(default_factory=list)
    active_apps: list[str] = field(default_factory=list)
    installed_software: list[SoftwareItem] = field(default_factory=list)
    services: list[ServiceItem] = field(default_factory=list)
    listening_ports: list[ListeningPortItem] = field(default_factory=list)
    process_connections: list[SocketConnectionItem] = field(default_factory=list)
    installed_browsers: list[str] = field(default_factory=list)
    browser_processes: list[BrowserProcessItem] = field(default_factory=list)
    os_info: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "device_id": self.device_id,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "timestamp": self.timestamp,
            "endpoint_processes": [p.to_dict() for p in self.endpoint_processes],
            "active_apps": self.active_apps,
            "installed_software": [s.to_dict() for s in self.installed_software],
            "services": [s.to_dict() for s in self.services],
            "listening_ports": [lp.to_dict() for lp in self.listening_ports],
            "process_connections": [pc.to_dict() for pc in self.process_connections],
            "installed_browsers": self.installed_browsers,
            "browser_processes": [bp.to_dict() for bp in self.browser_processes],
            "os_info": self.os_info,
        }
