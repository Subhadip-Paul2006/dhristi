# Drishti v0.1 — network intelligence report endpoints | 11-Jul-2026
"""Network-wide intelligence report: CVE aggregation, risk-band distribution,
unsupervised ML analysis, and an AI executive threat narrative. Thin router —
all logic lives in services/intel.py."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_org
from app.db import get_db
from app.models import Organization
from app.schemas.report import CveRow, Distribution, MlAnalysis, NetworkSummaryOut, NodeHardening
from app.services import hardening, intel

router = APIRouter()


@router.get("/report/cves", response_model=list[CveRow])
def get_cves(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[CveRow]:
    return intel.cve_report(db, org.id)


@router.get("/report/distribution", response_model=Distribution)
def get_distribution(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> Distribution:
    return intel.distribution(db, org.id)


@router.get("/report/ml", response_model=MlAnalysis)
def get_ml(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> MlAnalysis:
    return intel.ml_analysis(db, org.id)


@router.get("/report/hardening", response_model=list[NodeHardening])
def get_hardening(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[NodeHardening]:
    return hardening.hardening_report(db, org.id)


@router.post("/report/summary", response_model=NetworkSummaryOut)
def post_summary(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> NetworkSummaryOut:
    return intel.network_summary(db, org.id)
