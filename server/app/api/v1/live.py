"""Live device and threat endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.models import NetworkDevice, LiveObservation
from app.schemas.common import DeviceBatch, LiveThreatOut
from app.services.live import observe_devices, list_threats, list_coverage

router = APIRouter(prefix="/live", tags=["live"])


@router.post("/devices/batch")
def post_devices(
 payload: DeviceBatch,
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 from app.services.live import observe_devices
 result = observe_devices(db, org_id, payload.model_dump())
 return result


@router.get("/devices", response_model=list[dict])
def get_devices(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 from app.services.live import list_devices
 return [{
 "id": d.id, "mac": d.mac, "ip": d.ip, "subnet": d.subnet,
 "hostname": d.hostname or "", "vendor": d.vendor or "",
 "is_gateway": d.is_gateway, "is_self": d.is_self,
 "online": d.online, "last_seen": d.last_seen.isoformat() if d.last_seen else "",
 } for d in list_devices(db, org_id)]


@router.get("/threats", response_model=list[dict])
def get_threats(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 return [t.__dict__ for t in list_threats(db, org_id)]


@router.get("/coverage", response_model=list[dict])
def get_coverage(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 from app.services.live import list_coverage
 return [{
 "subnet": c.subnet, "gateway_ip": c.gateway_ip,
 "status": c.status, "evidence": c.evidence or "",
 "device_count": c.device_count or 0,
 } for c in list_coverage(db, org_id)]


@router.post("/demo")
def inject_demo(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 from app.services.live_threats import inject_demo, clear_demo
 return {"injected": inject_demo()}


@router.delete("/demo")
def clear_demo_endpoint(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 from app.services.live_threats import clear_demo
 devices = db.query(NetworkDevice).filter(NetworkDevice.org_id == org_id).all()
 kept = clear_demo(devices)
 return {"cleared": len(devices) - len(kept)}
