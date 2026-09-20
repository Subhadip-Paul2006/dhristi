# Drishti v0.1 — Endpoint Agent & Pairing Schemas | Phase 01
from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class PairingInitRequest(BaseModel):
    agent_id: str = Field(..., description="Unique persistent identifier of the agent")
    device_id: str = Field(..., description="Unique persistent identifier of the device")
    hostname: str = Field(..., description="Device hostname")
    os: str = Field(..., description="Operating system name (e.g. windows, darwin)")
    os_version: str = Field(..., description="Operating system release/version")
    mac: str | None = Field(default=None, description="Hardware MAC address where available")
    current_ip: str | None = Field(default=None, description="Current primary IPv4/IPv6 address")
    agent_version: str = Field(default="0.1.0", description="Endpoint agent semantic version")


class PairingInitResponse(BaseModel):
    session_id: str
    pairing_code: str
    expires_at: datetime
    poll_interval_seconds: int = 3


class PairingSubmitRequest(BaseModel):
    pairing_code: str = Field(..., min_length=4, max_length=16, description="Human-readable pairing code displayed by agent")


class EndpointAgentOut(BaseModel):
    id: str
    org_id: str
    agent_id: str
    device_id: str
    hostname: str
    os: str
    os_version: str
    mac: str | None = None
    current_ip: str | None = None
    agent_version: str
    status: str  # ONLINE, STALE, OFFLINE
    paired_at: datetime
    registered_at: datetime
    last_heartbeat: datetime | None = None


class PairingSubmitResponse(BaseModel):
    success: bool
    message: str
    agent: EndpointAgentOut


class PairingStatusRequest(BaseModel):
    session_id: str
    agent_id: str


class PairingStatusResponse(BaseModel):
    status: str  # WAITING_FOR_PAIR, PAIRED, CONSUMED, EXPIRED, REJECTED
    agent_token: str | None = None
    org_id: str | None = None


class HeartbeatRequest(BaseModel):
    agent_id: str
    device_id: str
    timestamp: datetime
    agent_version: str = "0.1.0"
    collector_health: dict[str, Any] = Field(default_factory=dict)
    connectivity: dict[str, Any] = Field(default_factory=dict)


class HeartbeatResponse(BaseModel):
    status: str = "ACK"
    server_time: datetime
    derived_status: str


# Phase 02 — Endpoint Telemetry Schemas
class ProcessTelemetryItem(BaseModel):
    pid: int
    name: str
    category: str = "SYSTEM_PROCESS"
    cpu_percent: float | None = None
    memory_mb: float | None = None
    exe_path: str | None = None
    username: str | None = None
    started_at: str | None = None
    observed_at: str | None = None


class SoftwareTelemetryItem(BaseModel):
    name: str
    version: str | None = None
    vendor: str | None = None
    install_date: str | None = None
    install_location: str | None = None
    source: str = "registry_or_apps"
    observed_at: str | None = None


class ServiceTelemetryItem(BaseModel):
    name: str
    display_name: str
    status: str
    start_type: str = "UNKNOWN"
    pid: int | None = None
    observed_at: str | None = None


class ListeningPortTelemetryItem(BaseModel):
    port: int
    protocol: str = "TCP"
    bind_address: str = "0.0.0.0"
    pid: int | None = None
    process_name: str | None = None
    observed_at: str | None = None


class SocketConnectionTelemetryItem(BaseModel):
    pid: int
    process_name: str
    protocol: str = "TCP"
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    observed_at: str | None = None


class BrowserProcessTelemetryItem(BaseModel):
    browser_name: str
    pid: int
    exe_path: str | None = None
    observed_at: str | None = None


class EndpointTelemetrySubmitRequest(BaseModel):
    agent_id: str
    device_id: str
    timestamp: datetime
    hostname: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    endpoint_processes: list[ProcessTelemetryItem] | None = None
    active_apps: list[str] | None = None
    installed_software: list[SoftwareTelemetryItem] | None = None
    services: list[ServiceTelemetryItem] | None = None
    listening_ports: list[ListeningPortTelemetryItem] | None = None
    process_connections: list[SocketConnectionTelemetryItem] | None = None
    installed_browsers: list[str] | None = None
    browser_processes: list[BrowserProcessTelemetryItem] | None = None
    os_info: str | None = None


class EndpointTelemetrySubmitResponse(BaseModel):
    success: bool = True
    message: str
    accepted_at: datetime
    processes_count: int
    software_count: int
    services_count: int
    ports_count: int


class EndpointTelemetryOut(BaseModel):
    device_id: str
    agent_id: str
    hostname: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    endpoint_processes: list[ProcessTelemetryItem] = Field(default_factory=list)
    active_apps: list[str] = Field(default_factory=list)
    installed_software: list[SoftwareTelemetryItem] = Field(default_factory=list)
    services: list[ServiceTelemetryItem] = Field(default_factory=list)
    listening_ports: list[ListeningPortTelemetryItem] = Field(default_factory=list)
    process_connections: list[SocketConnectionTelemetryItem] = Field(default_factory=list)
    installed_browsers: list[str] = Field(default_factory=list)
    browser_processes: list[BrowserProcessTelemetryItem] = Field(default_factory=list)
    os_info: str | None = None
    last_updated: datetime | None = None
    is_stale: bool = False
    is_software_stale: bool = False
    source: str = "endpoint_agent"


# Phase 03 — Vulnerability Intelligence Schemas
class CorrelatedFindingOut(BaseModel):
    finding_id: str
    device_id: str
    org_id: str
    finding_state: str  # OPEN, EXPOSED, POTENTIAL_MATCH, VULNERABLE, KNOWN_EXPLOITED, NO_CONFIRMED_VULNERABILITY
    observed_product: str
    evidence_source: str  # endpoint_software | network_service
    evidence_type: str
    observed_vendor: str | None = None
    observed_version: str | None = None
    cve_id: str | None = None
    title: str | None = None
    summary: str | None = None
    cvss: float = 0.0
    severity: str = "none"
    in_kev: bool = False
    kev_date_added: str | None = None
    ghsa_ids: list[str] = Field(default_factory=list)
    affected_range_text: str | None = None
    fixed_version_text: str | None = None
    intel_sources: list[str] = Field(default_factory=list)
    source_freshness: str = "live"  # live | cached | stale | source_unavailable
    source_status_reason: str | None = None
    source_details: dict[str, Any] = Field(default_factory=dict)
    observed_at: str | None = None


class SourceStatusOut(BaseModel):
    source_name: str
    available: bool = True
    last_sync: str | None = None
    error_reason: str | None = None
    is_stale: bool = False


class EndpointVulnerabilitiesResponse(BaseModel):
    device_id: str
    findings: list[CorrelatedFindingOut] = Field(default_factory=list)
    total_findings: int = 0
    vulnerable_count: int = 0
    known_exploited_count: int = 0
    potential_match_count: int = 0
    source_statuses: list[SourceStatusOut] = Field(default_factory=list)


