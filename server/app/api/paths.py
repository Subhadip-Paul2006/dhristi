# Drishti v0.1 — attack path enumeration endpoint | 11-Jul-2026
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.deps import get_current_org
from app.core.errors import NotFoundError
from app.db import get_db
from app.models import Organization
from app.schemas.graph import BlastRadiusOut, PathDetail, PathSummary
from app.services.read_service import blast_radius_response, get_path_detail, list_paths

router = APIRouter()


@router.get("/paths", response_model=list[PathSummary])
def get_paths(
    k: int = Query(default=25, ge=1, le=100),
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[PathSummary]:
    return list_paths(db, org.id, k)


@router.get("/paths/{path_id}", response_model=PathDetail)
def get_path(
    path_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> PathDetail:
    detail = get_path_detail(db, org.id, path_id)
    if detail is None:
        raise NotFoundError("Attack path not found")
    return detail


@router.get("/assets/{asset_id}/blast-radius", response_model=BlastRadiusOut)
def get_blast_radius(
    asset_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> BlastRadiusOut:
    out = blast_radius_response(db, org.id, asset_id)
    if out is None:
        raise NotFoundError("Asset not found")
    return out
