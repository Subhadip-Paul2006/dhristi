"""Scan endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.models import Asset, Scan

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("/trigger/{asset_id}")
def trigger_scan(
 asset_id: str,
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 asset = db.query(Asset).filter(Asset.org_id == org_id, Asset.id == asset_id).first()
 if not asset:
 raise HTTPException(status_code=404, detail="Asset not found")
 scan = Scan(org_id=org_id, asset_count=1, status="queued")
 db.add(scan)
 db.commit()
 return {"scan_id": scan.id, "status": "queued", "asset_ip": asset.ip}


@router.get("/history")
def scan_history(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
 limit: int = 20,
):
 scans = db.query(Scan).filter(Scan.org_id == org_id).order_by(Scan.created_at.desc()).limit(limit).all()
 return [{
 "id": s.id, "status": s.status, "asset_count": s.asset_count or 0,
 "findings_found": 0,
 "started_at": s.created_at.isoformat() if s.created_at else None,
 "completed_at": s.updated_at.isoformat() if s.updated_at else None,
 } for s in scans]
