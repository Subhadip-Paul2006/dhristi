"""Network intelligence routes — CVE summary, ML summary, AI summary."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.models import Asset, AssetVulnerability
from app.services.intel import cve_summary, severity_distribution, ml_summary, network_summary_ai
from app.services.risk_engine import build_engine, NodeData
from app.services.attack_paths import enumerate_paths, total_exposure
from app.schemas.common import NetworkSummaryOut

router = APIRouter(prefix="/intel", tags=["intel"])


@router.get("/cves")
def get_cves(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 from app.services.intel import cve_summary
 return cve_summary(db, org_id)


@router.get("/severity")
def get_severity(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 from app.services.intel import severity_distribution
 return severity_distribution(db, org_id)


@router.get("/ml")
def get_ml_summary(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 from app.services.intel import ml_summary
 return ml_summary(db, org_id)


@router.get("/summary", response_model=NetworkSummaryOut)
def get_network_summary(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 from app.services.intel import network_summary_ai
 return network_summary_ai(db, org_id)
