"""Attack path list and detail endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.models import AttackPath
from app.schemas.common import PathSummary
from app.services.risk_engine import build_engine
from app.services.attack_paths import enumerate_paths, total_exposure, path_impact_usd

router = APIRouter(prefix="/paths", tags=["paths"])


@router.get("", response_model=list[PathSummary])
def list_paths(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 paths = db.query(AttackPath).filter(AttackPath.org_id == org_id).order_by(AttackPath.path_risk.desc()).limit(25).all()
 return [PathSummary(
 path_id=p.id, entry={"id": p.entry_label, "hostname": p.entry_label},
 target={"id": p.target_asset_id, "hostname": p.target_asset_id},
 hops=p.hop_count, risk_score=float(p.path_risk), likelihood=float(p.likelihood),
 impact_usd=float(p.impact_usd), narrative=p.narrative or "",
 ) for p in paths]


@router.get("/{path_id}", response_model=PathSummary)
def get_path(
 path_id: str,
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 p = db.query(AttackPath).filter(AttackPath.id == path_id, AttackPath.org_id == org_id).first()
 if not p:
 raise HTTPException(status_code=404, detail="Path not found")
 return PathSummary(
 path_id=p.id, entry={"id": p.entry_label, "hostname": p.entry_label},
 target={"id": p.target_asset_id, "hostname": p.target_asset_id},
 hops=p.hop_count, risk_score=float(p.path_risk), likelihood=float(p.likelihood),
 impact_usd=float(p.impact_usd), narrative=p.narrative or "",
 )
