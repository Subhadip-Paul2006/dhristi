# Drishti v0.1 — vulnerability findings listing | 11-Jul-2026
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.deps import get_current_org, require_role
from app.core.errors import NotFoundError
from app.db import get_db
from app.models import Asset, AssetVulnerability, Organization, Service, Vulnerability
from app.models.base import utcnow
from app.schemas.graph import FindingOut
from app.services.read_service import list_findings

router = APIRouter()


class FindingPatch(BaseModel):
    # closed enum → an invalid status fails request validation (422 envelope)
    status: Literal["open", "remediating", "resolved", "accepted"]


@router.get("/findings", response_model=list[FindingOut])
def get_findings(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[FindingOut]:
    return list_findings(db, org.id, {"severity": severity, "status": status})


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def patch_finding(
    finding_id: str,
    body: FindingPatch,
    org: Organization = Depends(get_current_org),
    _user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> FindingOut:
    finding = db.get(AssetVulnerability, finding_id)
    if finding is None or finding.org_id != org.id:
        raise NotFoundError("Finding not found")
    finding.status = body.status
    finding.resolved_at = utcnow() if body.status == "resolved" else None
    db.flush()

    from app.services.recompute import recompute_org

    recompute_org(db, org.id)
    db.commit()

    # build the response straight from the updated row (same mapping as
    # list_findings) — re-listing every finding just to pick one is wasteful and
    # IndexErrors to a 500 if the row isn't in the filtered list.
    vuln = db.get(Vulnerability, finding.vulnerability_id)
    asset = db.get(Asset, finding.asset_id)
    svc = db.get(Service, finding.service_id) if finding.service_id else None
    return FindingOut(
        id=finding.id,
        status=finding.status,
        cve_id=vuln.cve_id,
        title=vuln.title,
        severity=vuln.severity,
        cvss=float(vuln.cvss),
        exploitability=float(vuln.exploitability),
        description=vuln.description,
        asset_id=asset.id,
        asset_hostname=asset.hostname,
        asset_ip=asset.ip,
        service_port=svc.port if svc else None,
        detected_at=finding.detected_at.isoformat() if finding.detected_at else None,
    )
