# Drishti v0.1 — AI remediation endpoint | 11-Jul-2026
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_org, rate_limit_ai, require_role
from app.db import get_db
from app.models import Organization
from app.schemas.ai import (
    ImpactOut,
    ImpactRequest,
    PredictOut,
    PredictRequest,
    RemediateRequest,
    RemediationOut,
)
from app.services.ai import service as ai_service

router = APIRouter()


@router.post("/remediate", response_model=RemediationOut, dependencies=[Depends(rate_limit_ai)])
def remediate(
    body: RemediateRequest,
    org: Organization = Depends(get_current_org),
    _user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> RemediationOut:
    return ai_service.remediate(db, org.id, body.finding_id, body.preferred_kind, body.regenerate)


@router.post("/impact", response_model=ImpactOut, dependencies=[Depends(rate_limit_ai)])
def impact(
    body: ImpactRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> ImpactOut:
    return ai_service.impact(db, org.id, body.path_id)


@router.post("/predict", response_model=PredictOut, dependencies=[Depends(rate_limit_ai)])
def predict(
    body: PredictRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> PredictOut:
    return ai_service.predict(db, org.id, body.asset_id)
