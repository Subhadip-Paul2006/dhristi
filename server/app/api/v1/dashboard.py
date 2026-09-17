"""Dashboard summary endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.schemas.common import DashboardOut, PathSummary
from app.services.dashboard_service import get_dashboard, get_stats

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardOut)
def get_dashboard_summary(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 data = get_dashboard(db, org_id)
 stats = get_stats(org_id)
 top_path = None
 if data.get("top_path"):
 tp = data["top_path"]
 top_path = PathSummary(
 path_id=tp["path_id"], entry={"id": tp["entry"], "hostname": tp["entry"]},
 target={"id": tp["target"], "hostname": tp["target"]},
 hops=tp["hops"], risk_score=tp["risk_score"], likelihood=tp["likelihood"],
 impact_usd=tp["impact_usd"], narrative=tp.get("narrative", ""),
 )
 paths = [PathSummary(
 path_id=p["path_id"], entry={"id": p["entry"], "hostname": p["entry"]},
 target={"id": p["target"], "hostname": p["target"]},
 hops=p["hops"], risk_score=p["risk_score"], likelihood=p["likelihood"],
 impact_usd=p["impact_usd"], narrative=p.get("narrative", ""),
 ) for p in data.get("paths", [])]

 from app.schemas.common import ZoneSummary
 zones = [ZoneSummary(**z) for z in data.get("zone_summary", [])]

 return DashboardOut(
 total_exposure_usd=data["total_exposure_usd"],
 open_findings=data["open_findings"],
 critical_assets=data["critical_assets"],
 top_path=top_path, paths=paths, zone_summary=zones,
 severity_counts=data["severity_counts"],
 last_recompute_at=data.get("last_recompute_at"),
 recompute_ms=stats.get("recompute_ms", 0.0),
 )
