# Drishti v0.1 — live network watch schemas | 11-Jul-2026
"""Request/response schemas for the live network watch (agent observes a domain
→ real trust verdict → live threat node → AI block recommendation)."""
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    DEVICE_PRESENCE = "DEVICE_PRESENCE"       # Layer 1: IP/MAC/hostname/vendor/online state
    NETWORK_SOCKET = "NETWORK_SOCKET"         # process/PID ↔ local:remote socket (agent-only)
    DNS_QUERY = "DNS_QUERY"                   # observed DNS request + resolved IP
    NETWORK_TRAFFIC = "NETWORK_TRAFFIC"       # TCP/UDP flow observation (SNI/flow metadata)
    BROWSER_ACTIVE_TAB = "BROWSER_ACTIVE_TAB" # extension-sourced only, never derived elsewhere
    OPEN_PORT = "OPEN_PORT"                   # Nmap port discovery
    SERVICE_DETECTION = "SERVICE_DETECTION"   # Nmap service/product/version
    CVE_CORRELATION = "CVE_CORRELATION"       # CPE+version → CVE match result


class EvidenceEnvelope(BaseModel):
    evidence_type: EvidenceType | str
    device_id: str
    observed_at: datetime
    source: str
    confidence: str = "high"  # "high" | "medium" | "low"
    is_stale: bool = False
    is_inferred: bool = False  # OBSERVED (False) vs INFERRED (True)
    raw_value: str
    inferred_label: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class TimelineQueryIn(BaseModel):
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=200, ge=1, le=1000)


class ActivityItem(BaseModel):
    name: str
    evidence_type: str = "UNKNOWN"
    source: str = "network"
    observed_at: datetime | None = None
    details: str | None = None
    browser: str | None = None
    url: str | None = None
    domain: str | None = None
    title: str | None = None
    category: str | None = None  # "USER_APPLICATION" | "BACKGROUND_PROCESS" | "SYSTEM_PROCESS"
    device_id: str | None = None
    confidence: str = "high"
    is_stale: bool = False
    is_inferred: bool = False
    inferred_label: str | None = None


class DeepScanService(BaseModel):
    port: int
    protocol: str  # tcp | udp
    service_name: str
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    banner: str | None = None
    confidence: float | None = None
    tunnel: str | None = None
    extrainfo: str | None = None
    evidence_type: str = "SERVICE_DETECTION"
    source: str = "nmap"
    is_stale: bool = False
    is_inferred: bool = False


class HttpEndpoint(BaseModel):
    url: str
    port: int
    scheme: str  # http | https
    service_name: str
    product: str | None = None
    version: str | None = None
    evidence_type: str = "SERVICE_DETECTION"
    source: str = "nmap"
    is_inferred: bool = False


class DeepScanCve(BaseModel):
    id: str  # CVE-YYYY-NNNN
    cvss: float
    severity: str  # low | medium | high | critical
    summary: str
    affected_service: str  # "product version" the CVE was matched against
    finding_id: str | None = None  # AssetVulnerability id → routes into remediation
    evidence_type: str = "CVE_CORRELATION"
    source: str = "cve_database"
    intel_sources: list[str] = Field(default_factory=lambda: ["nvd"])
    in_kev: bool = False
    ghsa_ids: list[str] = Field(default_factory=list)
    evidence_basis: str | None = None  # cpe_version | product_version
    is_stale: bool = False
    is_inferred: bool = True


class NetworkDestinationOut(BaseModel):
    domain: str
    resolved_service_label: str | None = None
    category: str = "unclassified"
    protocol: str = "DNS"  # "TLS/443" | "DNS" | "UDP"
    connection_count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    possible_vpn: bool = False
    evidence_source: str = "dns_query_log"  # "sni_sniffing" | "dns_query_log"
    confidence: str = "medium"  # "high" | "medium" | "low"
    is_stale: bool = False
    is_inferred: bool = False
    device_id: str | None = None


class TrafficSecurityAnnotation(BaseModel):
    finding_type: str = "traffic_to_vulnerable_service"
    device_id: str
    related_cve_finding_id: str  # REQUIRED — never None. If no CVE finding exists, do not create
    traffic_evidence: str
    why: str


class ObserveRequest(BaseModel):
    domain: str
    source_host: str | None = None
    protocol: str = "DNS"
    evidence_source: str = "dns_query_log"
    dest_port: int | None = None
    connection_count: int = 1


class SyncActiveRequest(BaseModel):
    domains: list[str] = []
    source_host: str = "default"
    agent_id: str | None = None
    mac: str | None = None
    active_apps: list[str] = []
    active_browser_tabs: list[ActivityItem] = []
    endpoint_processes: list[ActivityItem] = []
    installed_software: list[ActivityItem] = []
    installed_browsers: list[str] = []
    process_connections: list[ActivityItem] = []
    vpn_status: str | None = None
    vpn_adapters: list[str] = []
    os_info: str | None = None
    dns_queries: list[dict] = []
    network_traffic: list[dict] = []


class LiveThreat(BaseModel):
    id: str
    domain: str
    band: str  # Trusted | Caution | High Risk
    score: float
    hit_count: int
    source_host: str | None = None
    reasons: list[str] = []  # the concrete failing/warning signals
    verdict_json: dict = {}  # full signals, website facts, providers & AI summary
    first_seen: datetime
    last_seen: datetime


class ObserveResponse(BaseModel):
    id: str
    domain: str
    band: str
    score: float
    is_threat: bool  # band != Trusted


class BlockCommand(BaseModel):
    platform: str  # hosts | linux | macos | windows | dns
    command: str


class BlockFixOut(BaseModel):
    refused: bool = False
    reason: str | None = None
    domain: str
    band: str
    summary: str = ""
    why_risky: list[str] = []
    commands: list[BlockCommand] = []
    disclaimer: str = "Generated suggestion — review before applying. Blocks this domain only."


class DeviceIn(BaseModel):
    ip: str
    # null for off-link (L3-discovered) hosts — ARP can't see their MAC
    mac: str | None = None
    hostname: str | None = None
    # the observed CIDR this device was found on (e.g. "10.0.5.0/24");
    # legacy agents omit it and the server infers /24 (marked inferred)
    subnet: str | None = None
    discovery: str = "arp"  # arp | l3
    source: str | None = None  # observational source e.g. "scapy" | "arp" | "icmp" | "l3"


class DeviceBatch(BaseModel):
    devices: list[DeviceIn]
    self_mac: str | None = None  # this host's own MAC, so we can flag it
    gateway_ip: str | None = None
    subnet: str | None = None  # batch-level default CIDR for devices without one
    label: str | None = None  # human name for this network, e.g. "Floor-3-Guest"
    agent_id: str | None = None  # which agent reported this batch
    # ALL subnets this agent is currently connected to/scanning. Rows this agent
    # reported earlier on subnets NOT in this list are marked offline at once —
    # that's how a WiFi switch drops the old network's devices immediately.
    active_subnets: list[str] | None = None


class NetworkDeviceOut(BaseModel):
    id: str
    ip: str
    mac: str | None = None
    subnet: str | None = None
    subnet_inferred: bool = False
    discovery: str = "arp"
    label: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    is_self: bool = False
    is_gateway: bool = False
    online: bool = True
    first_seen: datetime
    last_seen: datetime
    # deep-scan status — scanned=False means "not scanned yet" (distinct from a
    # real scanned result with vuln_count 0). vuln_count/worst_severity are None
    # until the device has actually been deep-scanned.
    scanned: bool = False
    vuln_count: int | None = None
    worst_severity: str | None = None  # critical | high | medium | low
    last_scanned_at: datetime | None = None
    active_domains: list[str] = []
    active_apps: list[str] = []
    recent_destinations: list[ActivityItem] = []
    endpoint_processes: list[ActivityItem] = []
    active_browser_tabs: list[ActivityItem] = []
    # session presence history (backward-compatible additive fields)
    current_session_started_at: datetime | None = None
    current_session_duration_seconds: float = 0.0
    total_observed_duration_seconds: float = 0.0
    session_count: int = 1
    observation_count: int = 1
    observation_source: str | None = None
    presence_state: str = "new"  # "new" | "continuous" | "offline"
    # Master Phase 2 (B2.1) additions:
    open_ports: list[int] = []
    services: list[DeepScanService] = []
    http_endpoints: list[HttpEndpoint] = []
    cves: list[DeepScanCve] = []
    os_info: str | None = None
    device_type: str | None = None
    installed_software: list[ActivityItem] = []
    process_connections: list[ActivityItem] = []
    installed_browsers: list[str] = []
    vpn_status: str | None = None
    vpn_adapters: list[str] = []
    security_findings: list[str] = []
    risk_score: float | None = None
    capability_state: str = "NETWORK ONLY"  # "NETWORK ONLY" | "AGENT CONNECTED" | "BROWSER EXTENSION CONNECTED" | "FULL ENDPOINT TELEMETRY"
    network_destinations: list[NetworkDestinationOut] = []
    traffic_security_annotations: list[TrafficSecurityAnnotation] = []
    network_timeline: list[EvidenceEnvelope] = []
    network_evidence: list[EvidenceEnvelope] = []
    ladder_state: str | None = None



class AutoScanConfigIn(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=60, le=86400)
    scan_subnet: bool | None = None  # authorization to scan the whole subnet


class AutoScanConfigOut(BaseModel):
    enabled: bool
    interval_seconds: int
    scan_subnet: bool
    last_run_at: datetime | None = None
    running: bool = False  # background loop active on this server
    eligible_count: int = 0  # devices in scope for the current authorization
    scanned_count: int = 0  # devices deep-scanned at least once


class DeviceBatchResponse(BaseModel):
    total: int
    new: int


class CoverageNetworkIn(BaseModel):
    ssid: str | None = None
    subnet: str | None = None
    gateway_ip: str | None = None
    label: str | None = None
    status: str  # inventoried | reachable_not_scanned | seen_not_joined | unreachable
    evidence: str


class CoverageReport(BaseModel):
    networks: list[CoverageNetworkIn]


class CoverageOut(BaseModel):
    id: str
    ssid: str | None = None
    subnet: str | None = None
    gateway_ip: str | None = None
    label: str | None = None
    status: str  # inventoried | reachable_not_scanned | seen_not_joined | unreachable
    evidence: str
    device_count: int = 0
    last_seen: datetime


# ── Deep Scan (consented device vulnerability scan) ──────────────────────────
class DeepScanRequest(BaseModel):
    ip: str = Field(min_length=3, max_length=45)
    # explicit, required consent — the caller affirms they own/are authorized to
    # test this device. The endpoint rejects the scan unless this is true.
    consent: bool = False





class DeepScanResult(BaseModel):
    available: bool
    target: str
    unavailable_reason: str | None = None
    os: str | None = None
    ports: list[int] = []
    services: list[DeepScanService] = []
    http_endpoints: list[HttpEndpoint] = []
    cves: list[DeepScanCve] = []
    # True only when the CVE source itself couldn't be reached (distinct from an
    # empty cves list, which truthfully means "no known CVEs matched").
    cve_lookup_unavailable: bool = False
    cve_lookup_reason: str | None = None
    asset_id: str | None = None
    risk_score: float | None = None
    top_path_risk: float | None = None
    top_path_formed: bool = False
    scanned_at: datetime | None = None


class DeepScanRangeRequest(BaseModel):
    cidr: str = Field(min_length=9, max_length=18)  # e.g. 192.168.1.0/24
    consent: bool = False


class DeepScanRangeResult(BaseModel):
    available: bool
    cidr: str
    unavailable_reason: str | None = None
    hosts_discovered: int = 0  # how many responded to discovery
    hosts_scanned: int = 0  # how many were version-scanned (after the cap)
    host_cap: int = 0
    capped: bool = False  # more hosts were up than the cap allowed
    hosts: list[DeepScanResult] = []  # per-host real results (never fabricated)
    scanned_at: datetime | None = None
