# Drishti v0.1 — asset CRUD and risk-zone queries | 11-Jul-2026
from decimal import Decimal
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.deps import get_current_org, require_role
from app.core.errors import NotFoundError
from app.db import get_db
from app.models import Asset, Organization, RiskZone
from app.schemas.graph import AssetDetail, AssetSummary
from app.services.read_service import get_asset_detail, list_assets

router = APIRouter()


class AssetPatch(BaseModel):
    criticality: Literal["low", "medium", "high", "critical"] | None = None
    # cap well under the impact column's Numeric(14,2) ceiling: dollar impact is
    # ~business_value + breach_cost_base, so 1e11 leaves ample headroom and a
    # bad input returns 422 instead of overflowing to a 500 on Postgres.
    business_value: float | None = Field(default=None, ge=0, le=100_000_000_000)
    zone_id: str | None = None


@router.get("/assets", response_model=list[AssetSummary])
def get_assets(
    zone: str | None = Query(default=None),
    criticality: str | None = Query(default=None),
    internet_facing: bool | None = Query(default=None),
    q: str | None = Query(default=None),
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[AssetSummary]:
    return list_assets(
        db,
        org.id,
        {"zone": zone, "criticality": criticality, "internet_facing": internet_facing, "q": q},
    )


@router.get("/assets/{asset_id}", response_model=AssetDetail)
def get_asset(
    asset_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> AssetDetail:
    detail = get_asset_detail(db, org.id, asset_id)
    if detail is None:
        raise NotFoundError("Asset not found")
    return detail


@router.patch("/assets/{asset_id}", response_model=AssetDetail)
def patch_asset(
    asset_id: str,
    body: AssetPatch,
    org: Organization = Depends(get_current_org),
    _user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> AssetDetail:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise NotFoundError("Asset not found")
    if body.criticality is not None:
        asset.criticality = body.criticality
    if body.business_value is not None:
        asset.business_value = Decimal(str(body.business_value))
    if body.zone_id is not None:
        # only allow re-homing into a zone that belongs to the caller's org
        zone = db.get(RiskZone, body.zone_id)
        if zone is None or zone.org_id != org.id:
            raise NotFoundError("Risk zone not found")
        asset.zone_id = body.zone_id
    db.flush()

    from app.services.recompute import recompute_org

    recompute_org(db, org.id)
    db.commit()
    return get_asset_detail(db, org.id, asset_id)
