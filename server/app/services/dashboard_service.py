# Drishti v0.1 — dashboard aggregation service | 11-Jul-2026
"""Dashboard + stats aggregation from cached engine output."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Asset, AssetVulnerability, AttackPath, RiskZone, Vulnerability
from app.schemas.dashboard import (
    DashboardResponse,
    SeverityBreakdown,
    StatsResponse,
    ZoneSummary,
)
from app.services.read_service import _path_summary
from app.services.recompute import last_stats


def _total_exposure_from_cache(db: Session, org_id: str) -> float:
    """Dedupe to the max cached path impact per unique target (BACKEND.md §7.1)."""
    paths = db.scalars(select(AttackPath).where(AttackPath.org_id == org_id)).all()
    best_per_target: dict[str, float] = {}
    for p in paths:
        val = float(p.impact_usd)
        if val > best_per_target.get(p.target_asset_id, 0.0):
            best_per_target[p.target_asset_id] = val
    return round(sum(best_per_target.values()), 2)


def build_dashboard(db: Session, org_id: str) -> DashboardResponse:
    total = _total_exposure_from_cache(db, org_id)

    open_findings = db.scalar(
        select(func.count())
        .select_from(AssetVulnerability)
        .where(AssetVulnerability.org_id == org_id, AssetVulnerability.status == "open")
    )
    critical_assets = db.scalar(
        select(func.count())
        .select_from(Asset)
        .where(Asset.org_id == org_id, Asset.criticality == "critical")
    )

    top_paths_rows = db.scalars(
        select(AttackPath)
        .where(AttackPath.org_id == org_id)
        .order_by(AttackPath.path_risk.desc())
        .limit(5)
    ).all()
    top_paths = [_path_summary(db, p) for p in top_paths_rows]
    top_path_risk = top_paths[0].path_risk if top_paths else 0.0

    # zone summary
    zones = db.scalars(select(RiskZone).where(RiskZone.org_id == org_id)).all()
    zone_summary: list[ZoneSummary] = []
    for z in zones:
        assets = db.scalars(select(Asset).where(Asset.zone_id == z.id)).all()
        worst = max((float(a.risk_score or 0.0) for a in assets), default=0.0)
        zone_summary.append(
            ZoneSummary(name=z.name, kind=z.kind, asset_count=len(assets), worst_risk=round(worst, 1))
        )

    # severity breakdown over open findings
    sev_rows = db.execute(
        select(Vulnerability.severity, func.count())
        .join(AssetVulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
        .where(AssetVulnerability.org_id == org_id, AssetVulnerability.status == "open")
        .group_by(Vulnerability.severity)
    ).all()
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for severity, count in sev_rows:
        if severity in sev:  # ignore any unexpected severity → no stray kwarg → no 500
            sev[severity] = count

    return DashboardResponse(
        total_exposure_usd=total,
        open_findings=open_findings or 0,
        critical_assets=critical_assets or 0,
        top_path_risk=top_path_risk,
        top_paths=top_paths,
        zone_summary=zone_summary,
        severity_breakdown=SeverityBreakdown(**sev),
    )


def build_stats(db: Session, org_id: str) -> StatsResponse:
    stats = last_stats(org_id)
    assets = db.scalar(select(func.count()).select_from(Asset).where(Asset.org_id == org_id)) or 0
    open_findings = (
        db.scalar(
            select(func.count())
            .select_from(AssetVulnerability)
            .where(AssetVulnerability.org_id == org_id, AssetVulnerability.status == "open")
        )
        or 0
    )
    # last_stats is per-process; if this server booted from a seed loaded in a
    # different process, fall back to live graph/path counts so /stats is real.
    if not stats:
        from app.models import Connection

        paths = db.scalar(
            select(func.count()).select_from(AttackPath).where(AttackPath.org_id == org_id)
        ) or 0
        edges = db.scalar(
            select(func.count()).select_from(Connection).where(Connection.org_id == org_id)
        ) or 0
        exposed = db.scalar(
            select(func.count())
            .select_from(Asset)
            .where(Asset.org_id == org_id, Asset.internet_facing.is_(True))
        ) or 0
        top = db.scalar(
            select(func.max(AttackPath.path_risk)).where(AttackPath.org_id == org_id)
        )
        stats = {
            "nodes": assets + 1,  # + synthetic INTERNET
            "edges": edges + exposed,  # + injected exposure edges
            "paths": paths,
            "recompute_ms": 0.0,
            "top_path_risk": float(top) if top is not None else 0.0,
        }

    from app.services.ai.client import ai_stats

    ai = ai_stats()
    return StatsResponse(
        nodes=stats.get("nodes", 0),
        edges=stats.get("edges", 0),
        paths=stats.get("paths", 0),
        recompute_ms=stats.get("recompute_ms", 0.0),
        top_path_risk=stats.get("top_path_risk", 0.0),
        assets=assets,
        open_findings=open_findings,
        ai_calls=int(ai.get("calls", 0)),
        ai_mock_calls=int(ai.get("mock_calls", 0)),
    )
