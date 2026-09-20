# Drishti v0.1 — live per-device tracking API endpoints | Phase 01
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_org
from app.db import get_db
from app.models import Organization
from app.schemas.tracking import (
    TrackingResultsOut,
    TrackingSessionOut,
    TrackingStartRequest,
    TrackingStopRequest,
)
from app.services.traffic.session_manager import tracking_manager

router = APIRouter()


@router.post("/live/tracking/start", response_model=TrackingSessionOut)
def start_tracking(
    body: TrackingStartRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> TrackingSessionOut:
    """Start live network traffic tracking explicitly bound to the selected authorized device."""
    return tracking_manager.start_tracking(
        db=db,
        org_id=org.id,
        device_id=body.device_id,
        ip=body.ip,
        mac=body.mac,
        hostname=body.hostname,
    )


@router.post("/live/tracking/stop", response_model=TrackingSessionOut)
def stop_tracking(
    body: TrackingStopRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> TrackingSessionOut:
    """Stop active live network traffic tracking for a session and preserve historical results."""
    return tracking_manager.stop_tracking(
        db=db,
        org_id=org.id,
        session_id=body.tracking_session_id,
    )


@router.get("/live/tracking/{session_id}", response_model=TrackingSessionOut)
def get_tracking_session(
    session_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> TrackingSessionOut:
    """Retrieve metadata and status for a specific tracking session."""
    return tracking_manager.get_session(
        db=db,
        org_id=org.id,
        session_id=session_id,
    )


@router.get("/live/tracking/{session_id}/results", response_model=TrackingResultsOut)
def get_tracking_results(
    session_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> TrackingResultsOut:
    """Retrieve live flow metrics, protocol breakdown, top destinations, and current detection."""
    return tracking_manager.get_results(
        db=db,
        org_id=org.id,
        session_id=session_id,
    )
