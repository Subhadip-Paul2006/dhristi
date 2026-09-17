"""Asset inventory and findings routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.models import User, Asset, AssetVulnerability, Vulnerability, Service
from app.schemas.common import AssetSummary, AssetDetail, ServiceOut, FindingOut, FindingUpdate, NodeHardening
from app.services.hardening import compute_hardening

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=list[AssetSummary])
def list_assets(
 db: Session = Depends(get_db),
 current: User = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 assets = db.query(Asset).filter(Asset.org_id == org_id).all()
 out = []
 for a in assets:
 zone_name = a.zone.name if a.zone else ""
 out.append(AssetSummary(
 id=a.id, ip=a.ip, hostname=a.hostname, zone=zone_name,
 asset_type=a.asset_type, criticality=a.criticality,
 internet_facing=a.internet_facing,
 risk_score=a.risk_score or 0.0,
 is_crown_jewel=a.is_crown_jewel or a.criticality == "critical",
 blast_radius_count=a.blast_radius_count or 0,
 downstream_value_usd=a.downstream_value_usd or 0.0,
 last_scanned_at=a.last_scanned_at.isoformat() if a.last_scanned_at else None,
 ))
 return out


@router.get("/{asset_id}", response_model=AssetDetail)
def get_asset(
 asset_id: str,
 db: Session = Depends(get_db),
 current: User = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 asset = db.query(Asset).filter(Asset.org_id == org_id, Asset.id == asset_id).first()
 if not asset:
 raise HTTPException(status_code=404, detail="Asset not found")

 services = db.query(Service).filter(Service.asset_id == asset_id).all()
 svc_out = [ServiceOut(id=s.id, port=s.port, protocol=s.protocol, name=s.name, version=s.version) for s in services]

 findings = (
 db.query(AssetVulnerability, Vulnerability)
 .join(Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
 .filter(AssetVulnerability.asset_id == asset_id, AssetVulnerability.status.in_(["open", "remediating"]))
 .all()
 )
 f_out = []
 for f, v in findings:
 f_out.append(FindingOut(
 id=f.id, asset_id=f.asset_id, cve_id=v.cve_id or "", title=v.title,
 severity=v.severity, cvss=float(v.cvss), status=f.status,
 auto_resolved=f.auto_resolved or False, accepted_until=f.accepted_until.isoformat() if f.accepted_until else None,
 ))

 hardening = compute_hardening(asset, asset.risk_score or 0.0)

 return AssetDetail(
 id=asset.id, ip=asset.ip, hostname=asset.hostname,
 os=asset.os, zone=asset.zone.name if asset.zone else "",
 asset_type=asset.asset_type, criticality=asset.criticality,
 internet_facing=asset.internet_facing, base_value_usd=asset.business_value,
 risk_score=asset.risk_score or 0.0,
 is_crown_jewel=asset.is_crown_jewel or asset.criticality == "critical",
 blast_radius_count=asset.blast_radius_count or 0,
 downstream_value_usd=asset.downstream_value_usd or 0.0,
 services=svc_out, findings=f_out, hardening=[{"action": h.action, "risk_reduction": h.risk_reduction, "detail": h.detail} for h in hardening],
 )


@router.patch("/{asset_id}/findings/{finding_id}", response_model=dict)
def update_finding(
 asset_id: str,
 finding_id: str,
 update: FindingUpdate,
 db: Session = Depends(get_db),
 current: User = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 finding = db.query(AssetVulnerability).filter(
 AssetVulnerability.id == finding_id,
 AssetVulnerability.asset_id == asset_id,
 ).first()
 if not finding:
 raise HTTPException(status_code=404, detail="Finding not found")

 if update.status == "accepted":
 finding.accepted_until = datetime.now(timezone.utc) + timedelta(days=30)
 elif update.status == "auto-resolved":
 finding.status = "auto-resolved"
 finding.auto_resolved = True
 elif update.status in ("open", "resolved", "remediating"):
 finding.status = update.status
 if finding.status in ("resolved", "auto-resolved"):
 finding.auto_resolved = True

 db.commit()
 return {"ok": True}
