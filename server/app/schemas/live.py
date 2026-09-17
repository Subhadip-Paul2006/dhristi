# Drishti v0.1 — live network watch schemas | 11-Jul-2026
"""Request/response schemas for the live network watch (agent observes a domain
→ real trust verdict → live threat node → AI block recommendation)."""
from datetime import datetime

from pydantic import BaseModel, Field


class ObserveRequest(BaseModel):
    domain: str
    source_host: str | None = None


class SyncActiveRequest(BaseModel):
    domains: list[str]
    source_host: str
    active_apps: list[str] = []


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


class ActivityItem(BaseModel):
    name: str
    evidence_type: str = "UNKNOWN"
    source: str = "network"
    observed_at: datetime | None = None
    details: str | None = None


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


class DeepScanService(BaseModel):
    port: int
    protocol: str  # tcp | udp
    service_name: str
    product: str | None = None
    version: str | None = None


class DeepScanCve(BaseModel):
    id: str  # CVE-YYYY-NNNN
    cvss: float
    severity: str  # low | medium | high | critical
    summary: str
    affected_service: str  # "product version" the CVE was matched against
    finding_id: str | None = None  # AssetVulnerability id → routes into remediation


class DeepScanResult(BaseModel):
    available: bool
    target: str
    unavailable_reason: str | None = None
    os: str | None = None
    ports: list[int] = []
    services: list[DeepScanService] = []
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
