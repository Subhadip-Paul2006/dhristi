# Drishti v0.1 — network-config vulnerability endpoints | 12-Jul-2026
"""Network-configuration vulnerability detection (NAT / DMZ / DHCP). Reads the
org's real topology (+ optional declared config), maps real findings into the
existing risk engine, and returns them. Thin router — logic in
services/netconfig/service.py. Defensive + consent-gated; never intercepts
traffic."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_org, rate_limit_ai
from app.db import get_db
from app.models import Organization
from app.schemas.netconfig import NetconfigAnalysisOut, NetconfigRequest
from app.services.netconfig import service as netconfig

router = APIRouter()


@router.post("/netconfig/analyze", response_model=NetconfigAnalysisOut,
             dependencies=[Depends(rate_limit_ai)])
def analyze(
    body: NetconfigRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> NetconfigAnalysisOut:
    """Run NAT/DMZ/DHCP detectors on the org network (+ optional declared config),
    map real findings into the engine, recompute, and return them. Requires
    consent=true."""
    return netconfig.analyze(db, org.id, body.consent, body.config)


@router.get("/netconfig/last", response_model=NetconfigAnalysisOut)
def last(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> NetconfigAnalysisOut:
    """The most recent stored analysis (available:false if none has run yet)."""
    return netconfig.last(db, org.id)
