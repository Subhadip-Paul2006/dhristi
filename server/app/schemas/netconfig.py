# Drishti v0.1 — network-config vulnerability schemas | 12-Jul-2026
"""Request/response schemas for network-configuration vulnerability detection
(NAT / DMZ / DHCP misconfigurations). Findings are inferred from REAL observed
topology or explicit user-declared config — never fabricated. A check with
insufficient data is reported as status='unknown', visually distinct from a real
finding and from a passed check."""
from datetime import datetime

from pydantic import BaseModel, Field


# ── optional user-declared config ────────────────────────────────────────────
class PortForward(BaseModel):
    external_port: int = Field(ge=0, le=65535)
    internal_ip: str
    internal_port: int = Field(ge=0, le=65535)
    proto: str = "tcp"


class NetconfigInput(BaseModel):
    """Optional topology a user declares for analysis. Everything here is
    labelled 'declared' in the resulting findings' provenance."""
    port_forwards: list[PortForward] = []
    dhcp_servers: list[str] = []  # IPs of observed/known DHCP responders
    dhcp_snooping: bool | None = None  # None = not declared → check is 'unknown'
    dmz_hosts: list[str] = []  # IPs/hostnames the user declares as DMZ-resident
    gateway_ip: str | None = None


class NetconfigRequest(BaseModel):
    consent: bool = False
    config: NetconfigInput | None = None


# ── findings + response ──────────────────────────────────────────────────────
class NetconfigFinding(BaseModel):
    id: str  # stable-ish key for the UI (category + slug)
    category: str  # NAT | DMZ | DHCP
    title: str
    severity: str  # critical | high | medium | low | none (for passed/unknown)
    status: str  # real | unknown | passed
    source: str  # observed | declared
    evidence: str  # the concrete data this was inferred from
    affected: list[str] = []  # hostnames / ips / zone names
    remediation_hint: str = ""
    finding_id: str | None = None  # AssetVulnerability id → AI remediation flow


class RiskSummary(BaseModel):
    total_assets: int
    average_risk: float  # 0..100
    real_findings: int
    unknown_findings: int
    passed_checks: int
    top_path_risk: float | None = None


class NetconfigAnalysisOut(BaseModel):
    available: bool = True
    findings: list[NetconfigFinding] = []
    recomputed_risk: RiskSummary
    used_declared_config: bool = False
    generated_at: datetime | None = None
