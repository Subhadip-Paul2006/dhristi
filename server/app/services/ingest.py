# Drishti v0.1 — idempotent data ingestion pipeline | 11-Jul-2026
"""Ingestion: validate → upsert (idempotent by org+ip) → trigger recompute."""
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenError
from app.models import (
    Agent,
    Asset,
    AssetVulnerability,
    Connection,
    Organization,
    RiskZone,
    Scan,
    Service,
    Vulnerability,
)
from app.models.base import utcnow
from app.schemas.ingest import IngestCounts, IngestPayload, IngestResponse

_CRIT_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _resolve_zone(db: Session, org_id: str, zone_hint: str | None) -> str | None:
    if not zone_hint:
        return None
    zone = db.scalar(
        select(RiskZone).where(RiskZone.org_id == org_id, RiskZone.kind == zone_hint)
    )
    return zone.id if zone else None


def _upsert_asset(db: Session, org_id: str, payload: IngestPayload) -> Asset:
    host = payload.host
    asset = db.scalar(select(Asset).where(Asset.org_id == org_id, Asset.ip == host.ip))
    if asset is None and host.hostname:
        # IP may have shifted — fall back to hostname identity (ARCHITECTURE.md §4).
        asset = db.scalar(
            select(Asset).where(Asset.org_id == org_id, Asset.hostname == host.hostname)
        )
    if asset is None:
        asset = Asset(
            org_id=org_id,
            ip=host.ip,
            hostname=host.hostname,
            criticality=host.criticality_hint or "medium",
        )
        try:
            with db.begin_nested():
                db.add(asset)
        except IntegrityError:
            # Lost the (org_id, ip) race to a concurrent ingest — adopt its row.
            asset = db.scalar(select(Asset).where(Asset.org_id == org_id, Asset.ip == host.ip))
            if asset is None:
                raise

    asset.ip = host.ip
    asset.hostname = host.hostname
    if host.os:
        asset.os = host.os
    asset.asset_type = host.asset_type
    zone_id = _resolve_zone(db, org_id, host.zone_hint)
    if zone_id:
        asset.zone_id = zone_id
    # Never downgrade an operator-set criticality from an agent hint (BACKEND.md §4.1).
    if host.criticality_hint and _CRIT_RANK[host.criticality_hint] > _CRIT_RANK.get(
        asset.criticality, 0
    ):
        asset.criticality = host.criticality_hint
    # NOTE: the payload has no internet_facing field; a DMZ zone hint is the
    # closest signal an agent can give, so new DMZ assets default to exposed.
    if asset.id is None or asset.risk_score is None:
        if host.zone_hint == "dmz":
            asset.internet_facing = True
    db.flush()
    return asset


def _replace_services(db: Session, org_id: str, asset: Asset, payload: IngestPayload) -> dict:
    existing = {(s.port, s.protocol): s for s in asset.services}
    seen: set[tuple[int, str]] = set()
    by_port: dict[int, Service] = {}
    for svc in payload.services:
        key = (svc.port, svc.protocol)
        seen.add(key)
        row = existing.get(key)
        if row is None:
            row = Service(org_id=org_id, asset_id=asset.id, port=svc.port, protocol=svc.protocol)
            db.add(row)
        row.name = svc.name
        row.version = svc.version
        by_port[svc.port] = row
    for key, row in existing.items():
        if key not in seen:
            db.delete(row)
    db.flush()
    return by_port


def _upsert_findings(
    db: Session, org_id: str, asset: Asset, payload: IngestPayload, services_by_port: dict
) -> int:
    count = 0
    current_vuln_ids: set[str] = set()
    for v in payload.vulnerabilities:
        if v.cve_id:
            vuln = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == v.cve_id))
        else:
            # No CVE to key on — fall back to title+severity so re-scans of the
            # same non-CVE finding update the existing row instead of piling up.
            vuln = db.scalar(
                select(Vulnerability).where(
                    Vulnerability.title == v.title, Vulnerability.severity == v.severity
                )
            )
        if vuln is None:
            vuln = Vulnerability(
                cve_id=v.cve_id,
                title=v.title,
                cvss=Decimal(str(v.cvss)),
                severity=v.severity,
                exploitability=Decimal(str(v.exploitability)),
                description=v.summary,
            )
            db.add(vuln)
            db.flush()

        finding = db.scalar(
            select(AssetVulnerability).where(
                AssetVulnerability.asset_id == asset.id,
                AssetVulnerability.vulnerability_id == vuln.id,
            )
        )
        if finding is None:
            finding = AssetVulnerability(
                org_id=org_id,
                asset_id=asset.id,
                vulnerability_id=vuln.id,
            )
            db.add(finding)
        # A finding an operator resolved/accepted stays that way on re-ingest.
        if finding.status not in ("resolved", "accepted"):
            finding.status = "open"
        svc = services_by_port.get(v.port) if v.port else None
        if svc is not None:
            finding.service_id = svc.id
        current_vuln_ids.add(vuln.id)
        count += 1

    # Reconcile: a re-scan that no longer reports a finding means it was fixed —
    # close this asset's still-open findings absent from the payload, mirroring
    # how _replace_services prunes vanished services, so risk drops after a fix.
    stale = db.scalars(
        select(AssetVulnerability).where(
            AssetVulnerability.asset_id == asset.id,
            AssetVulnerability.status == "open",
        )
    ).all()
    for finding in stale:
        if finding.vulnerability_id not in current_vuln_ids:
            finding.status = "resolved"
    db.flush()
    return count


def _upsert_connections(db: Session, org_id: str, asset: Asset, payload: IngestPayload) -> None:
    for conn in payload.connectivity:
        target = db.scalar(select(Asset).where(Asset.org_id == org_id, Asset.ip == conn.to_ip))
        if target is None:
            continue  # unknown neighbor; another agent will report it
        existing = db.scalar(
            select(Connection).where(
                Connection.from_asset_id == asset.id,
                Connection.to_asset_id == target.id,
                Connection.relation == conn.via,
            )
        )
        if existing is None:
            db.add(
                Connection(
                    org_id=org_id,
                    from_asset_id=asset.id,
                    to_asset_id=target.id,
                    relation=conn.via,
                    note=conn.note,
                )
            )
    db.flush()


def ingest_payload(db: Session, agent: Agent, payload: IngestPayload) -> IngestResponse:
    org = db.get(Organization, agent.org_id)
    if org is None or org.slug != payload.org_slug:
        raise ForbiddenError("Agent token does not match org_slug")

    scan = Scan(org_id=org.id, agent_id=agent.id, status="running")
    db.add(scan)
    db.flush()

    asset = _upsert_asset(db, org.id, payload)
    services_by_port = _replace_services(db, org.id, asset, payload)
    vuln_count = _upsert_findings(db, org.id, asset, payload, services_by_port)
    _upsert_connections(db, org.id, asset, payload)

    scan.status = "complete"
    scan.finished_at = utcnow()
    scan.asset_count = 1
    scan.vuln_count = vuln_count
    db.flush()

    from app.services.recompute import recompute_org

    recompute_org(db, org.id)
    db.commit()

    return IngestResponse(
        asset_id=asset.id,
        ingested=IngestCounts(services=len(payload.services), vulnerabilities=vuln_count),
        server_time=utcnow(),
    )
