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


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_single_finding(
    finding_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> FindingOut:
    finding = db.get(AssetVulnerability, finding_id)
    if finding is not None and finding.org_id == org.id:
        vuln = db.get(Vulnerability, finding.vulnerability_id)
        asset = db.get(Asset, finding.asset_id)
        svc = db.get(Service, finding.service_id) if finding.service_id else None
        return FindingOut(
            id=finding.id,
            status=finding.status,
            cve_id=vuln.cve_id if vuln else None,
            title=vuln.title if vuln else "Unknown vulnerability",
            severity=vuln.severity if vuln else "medium",
            cvss=float(vuln.cvss) if vuln else 0.0,
            exploitability=float(vuln.exploitability) if vuln else 0.30,
            description=vuln.description if vuln else None,
            asset_id=asset.id if asset else "",
            asset_hostname=asset.hostname if asset else None,
            asset_ip=asset.ip if asset else "0.0.0.0",
            service_port=svc.port if svc else None,
            detected_at=finding.detected_at.isoformat() if finding.detected_at else None,
            source="network",
        )

    # Check Phase 03/04 Endpoint Finding
    from app.services.endpoint_telemetry import (
        get_endpoint_finding_by_id,
        get_endpoint_finding_status,
    )

    res = get_endpoint_finding_by_id(org.id, finding_id)
    if res is not None:
        c_finding, telemetry = res
        ep_status = get_endpoint_finding_status(org.id, c_finding.finding_id)
        return FindingOut(
            id=c_finding.finding_id,
            status=ep_status,
            cve_id=c_finding.cve_id,
            title=c_finding.title or c_finding.summary or f"Vulnerability in {c_finding.observed_product}",
            severity=c_finding.severity,
            cvss=float(c_finding.cvss),
            exploitability=0.30,
            description=c_finding.summary or c_finding.affected_range_text,
            asset_id=c_finding.device_id,
            asset_hostname=telemetry.get("hostname"),
            asset_ip=telemetry.get("ip") or c_finding.device_id,
            service_port=None,
            detected_at=c_finding.observed_at,
            source="endpoint",
            observed_product=c_finding.observed_product,
            observed_version=c_finding.observed_version,
            fixed_version=c_finding.fixed_version_text,
            in_kev=c_finding.in_kev,
            finding_state=(
                c_finding.finding_state.value
                if hasattr(c_finding.finding_state, "value")
                else str(c_finding.finding_state)
            ),
        )

    raise NotFoundError("Finding not found")


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def patch_finding(
    finding_id: str,
    body: FindingPatch,
    org: Organization = Depends(get_current_org),
    _user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> FindingOut:
    finding = db.get(AssetVulnerability, finding_id)
    if finding is not None and finding.org_id == org.id:
        finding.status = body.status
        finding.resolved_at = utcnow() if body.status == "resolved" else None
        db.flush()

        from app.services.recompute import recompute_org

        recompute_org(db, org.id)
        db.commit()

        vuln = db.get(Vulnerability, finding.vulnerability_id)
        asset = db.get(Asset, finding.asset_id)
        svc = db.get(Service, finding.service_id) if finding.service_id else None
        return FindingOut(
            id=finding.id,
            status=finding.status,
            cve_id=vuln.cve_id if vuln else None,
            title=vuln.title if vuln else "Unknown vulnerability",
            severity=vuln.severity if vuln else "medium",
            cvss=float(vuln.cvss) if vuln else 0.0,
            exploitability=float(vuln.exploitability) if vuln else 0.30,
            description=vuln.description if vuln else None,
            asset_id=asset.id if asset else "",
            asset_hostname=asset.hostname if asset else None,
            asset_ip=asset.ip if asset else "0.0.0.0",
            service_port=svc.port if svc else None,
            detected_at=finding.detected_at.isoformat() if finding.detected_at else None,
            source="network",
        )

    # Check Phase 03/04 Endpoint Finding
    from app.services.endpoint_telemetry import (
        get_endpoint_finding_by_id,
        update_endpoint_finding_status,
    )

    res = get_endpoint_finding_by_id(org.id, finding_id)
    if res is not None:
        c_finding, telemetry = res
        update_endpoint_finding_status(org.id, finding_id, body.status)
        return FindingOut(
            id=c_finding.finding_id,
            status=body.status,
            cve_id=c_finding.cve_id,
            title=c_finding.title or c_finding.summary or f"Vulnerability in {c_finding.observed_product}",
            severity=c_finding.severity,
            cvss=float(c_finding.cvss),
            exploitability=0.30,
            description=c_finding.summary or c_finding.affected_range_text,
            asset_id=c_finding.device_id,
            asset_hostname=telemetry.get("hostname"),
            asset_ip=telemetry.get("ip") or c_finding.device_id,
            service_port=None,
            detected_at=c_finding.observed_at,
            source="endpoint",
            observed_product=c_finding.observed_product,
            observed_version=c_finding.observed_version,
            fixed_version=c_finding.fixed_version_text,
            in_kev=c_finding.in_kev,
            finding_state=(
                c_finding.finding_state.value
                if hasattr(c_finding.finding_state, "value")
                else str(c_finding.finding_state)
            ),
        )

    raise NotFoundError("Finding not found")

