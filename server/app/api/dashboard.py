# Drishti v0.1 — dashboard stats aggregation endpoint | 11-Jul-2026
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_org, require_role
from app.db import get_db
from app.models import Organization
from app.schemas.dashboard import DashboardResponse, StatsResponse
from app.services.dashboard_service import build_dashboard, build_stats

router = APIRouter()


@router.get("/dashboard", response_model=DashboardResponse)
def get_dashboard(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> DashboardResponse:
    return build_dashboard(db, org.id)


@router.get("/stats", response_model=StatsResponse)
def get_stats(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> StatsResponse:
    return build_stats(db, org.id)


@router.post("/recompute", response_model=StatsResponse)
def post_recompute(
    org: Organization = Depends(get_current_org),
    _user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> StatsResponse:
    from app.services.recompute import recompute_org

    recompute_org(db, org.id)
    db.commit()
    return build_stats(db, org.id)
