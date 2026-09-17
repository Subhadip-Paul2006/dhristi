# Drishti v0.1 — network intelligence report schemas | 11-Jul-2026
"""Response schemas for the network intelligence report (CVE table, risk-band
distribution, ML anomaly/segment analysis, and the AI executive summary)."""
from pydantic import BaseModel


class AffectedHost(BaseModel):
    hostname: str | None = None
    ip: str


class CveRow(BaseModel):
    cve_id: str | None = None
    title: str
    cvss: float
    severity: str
    affected_count: int
    affected: list[AffectedHost]


class RiskBand(BaseModel):
    band: str  # critical | high | medium | safe
    count: int
    pct: float  # 0..100


class Distribution(BaseModel):
    total_assets: int
    average_risk: float  # 0..100
    bands: list[RiskBand]


class AnomalousNode(BaseModel):
    hostname: str | None = None
    ip: str
    anomaly_score: float  # more negative = more anomalous
    risk_score: float
    reason: str


class SecuritySegment(BaseModel):
    segment: int
    risk_pct: float  # 0..100
    label: str  # HIGH | MEDIUM | LOW
    members: list[str]  # hostnames/ips


class MlAnalysis(BaseModel):
    available: bool
    algorithm_note: str
    anomalies: list[AnomalousNode] = []
    segments: list[SecuritySegment] = []


class NetworkSummaryOut(BaseModel):
    refused: bool = False
    reason: str | None = None
    headline: str = ""
    narrative: str = ""
    top_risks: list[str] = []
    priority_actions: list[str] = []


class HardeningAction(BaseModel):
    kind: str  # CLOSE_PORT | PATCH | VLAN_SEGMENT | ISOLATE_CONNECTION
    label: str
    risk_reduction_pct: float  # measured drop for THIS action alone, 0..100


class NodeHardening(BaseModel):
    hostname: str | None = None
    ip: str
    current_score: float  # 0..100
    projected_score: float  # 0..100 after applying all actions
    reduction_pct: float  # overall, 0..100
    band_before: str  # HIGH | MEDIUM | LOW | SAFE
    band_after: str
    actions: list[HardeningAction]
