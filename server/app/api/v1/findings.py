"""Finding list endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.schemas.common import FindingOut
from app.models import AssetVulnerability, Vulnerability, Asset, Remediation, Scan

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[dict])
def list_findings(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 rows = (
 db.query(AssetVulnerability, Vulnerability, Asset)
 .join(Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
 .join(Asset, AssetVulnerability.asset_id == Asset.id)
 .filter(AssetVulnerability.org_id == org_id)
 .filter(AssetVulnerability.status.in_(["open", "remediating"]))
 .all()
 )
 out = []
 for f, v, a in rows:
 rm = db.query(Remediation).filter(
 Remediation.finding_id == f.id,
 Remediation.kind != "refused",
 ).first()
 out.append({
 "id": f.id,
 "asset_id": a.id,
 "asset_ip": a.ip,
 "asset_hostname": a.hostname or "",
 "cve_id": v.cve_id or "",
 "title": v.title,
 "severity": v.severity,
 "cvss": float(v.cvss),
 "port": f.port,
 "service_name": f.service_name or "",
 "status": f.status,
 "auto_resolved": f.auto_resolved or False,
 "accepted_until": f.accepted_until.isoformat() if f.accepted_until else None,
 "remediation_id": rm.id if rm else None,
 })
 return out
