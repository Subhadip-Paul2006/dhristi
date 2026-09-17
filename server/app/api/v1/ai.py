"""AI remediation and impact estimation routes."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.models import Remediation, AssetVulnerability, Vulnerability
from app.schemas.common import RemediateRequest, RemediationOut, ImpactRequest, ImpactOut, PredictRequest, PredictOut
from app.services.ai.ai_remediate import generate_remediation, estimate_impact, predict_next_compromises, _REFUSED_REASONS

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/remediate", response_model=RemediationOut)
def remediate(
 payload: RemediateRequest,
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 result = generate_remediation(db, org_id, payload.finding_id, payload.preferred_kind, payload.regenerate)
 if result.get("refused"):
 return RemediationOut(refused=True, reason=result.get("reason"), kind=payload.preferred_kind, title="", summary="", script="", steps=[])
 return RemediationOut(id=result.get("id"), **{k: v for k, v in result.items() if k != "id"})


@router.post("/impact", response_model=ImpactOut)
def estimate_impact_endpoint(
 payload: ImpactRequest,
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 return estimate_impact(db, org_id, payload.path_id)


@router.post("/predict", response_model=PredictOut)
def predict_next(
 payload: PredictRequest,
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 return predict_next_compromises(db, org_id, payload.asset_id)
