# Drishti v0.1 — dashboard response schemas | 11-Jul-2026
from pydantic import BaseModel

from app.schemas.graph import PathSummary


class ZoneSummary(BaseModel):
    name: str
    kind: str
    asset_count: int
    worst_risk: float


class SeverityBreakdown(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class DashboardResponse(BaseModel):
    total_exposure_usd: float
    open_findings: int
    critical_assets: int
    top_path_risk: float
    top_paths: list[PathSummary]
    zone_summary: list[ZoneSummary]
    severity_breakdown: SeverityBreakdown


class StatsResponse(BaseModel):
    nodes: int
    edges: int
    paths: int
    recompute_ms: float
    top_path_risk: float
    assets: int
    open_findings: int
    ai_calls: int = 0
    ai_mock_calls: int = 0
