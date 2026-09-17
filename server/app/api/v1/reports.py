"""Report and export endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.services.intel import network_summary_ai, cve_summary
from app.services.risk_engine import build_engine, NodeData
from app.services.attack_paths import enumerate_paths, total_exposure

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/network-summary")
def network_summary(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 from app.services.intel import network_summary_ai
 return network_summary_ai(db, org_id)


@router.get("/cves")
def report_cves(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 return cve_summary(db, org_id)
