# Drishti v0.1 — deep-scan → engine integration | 12-Jul-2026
"""Turn a REAL deep-scan result into the existing domain objects and run the
existing risk engine on it — no special-casing.

We upsert the scanned device as an Asset, its detected ports as Services, and
each matched CVE as a Vulnerability + AssetVulnerability (finding), then call
the SAME recompute_org used everywhere else. The device's risk score, blast
radius, attack paths and $-impact are therefore computed by the existing engine
on this real data. Nothing here is hardcoded; empty scans create no findings."""
from __future__ import annotations

import logging
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    Asset,
    AssetVulnerability,
    AttackPath,
    AttackPathStep,
    Connection,
    NetworkDevice,
    RiskZone,
    Service,
    Vulnerability,
)

logger = logging.getLogger("drishti")

# database ports → the device is a database asset (higher-value target)
_DB_PORTS = {5432, 3306, 1433, 6379, 27017, 9200}
_SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _worst_severity(cves: list[dict]) -> str | None:
    worst = None
    for c in cves:
        s = c.get("severity")
        if s in _SEV_RANK and (worst is None or _SEV_RANK[s] > _SEV_RANK[worst]):
            worst = s
    return worst


def _ensure_zone(db: Session, org_id: str, name: str, kind: str) -> RiskZone:
    z = db.scalar(select(RiskZone).where(RiskZone.org_id == org_id, RiskZone.name == name))
    if z is None:
        z = RiskZone(org_id=org_id, name=name, kind=kind)
        db.add(z)
        db.flush()
    return z


def _ensure_gateway_asset(db: Session, org_id: str, gw_ip: str) -> Asset:
    """The discovered gateway modelled as the internet-facing network edge — a
    real reachability anchor (the router faces the internet and routes to the
    LAN). Reuses an existing asset for that IP if present."""
    gw = db.scalar(select(Asset).where(Asset.org_id == org_id, Asset.ip == gw_ip))
    if gw is None:
        gw = Asset(
            org_id=org_id, ip=gw_ip, hostname="gateway", os=None,
            asset_type="router", criticality="high",
            business_value=Decimal("40000"), internet_facing=True,
            zone_id=_ensure_zone(db, org_id, "Network Edge", "dmz").id,
        )
        db.add(gw)
        db.flush()
    elif not gw.internet_facing:
        gw.internet_facing = True  # it IS the internet edge
        db.flush()
    return gw


def _ensure_edge(db: Session, org_id: str, src_id: str, dst_id: str, relation: str) -> None:
    exists = db.scalar(
        select(Connection).where(
            Connection.from_asset_id == src_id,
            Connection.to_asset_id == dst_id,
            Connection.relation == relation,
        )
    )
    if exists is None:
        db.add(Connection(org_id=org_id, from_asset_id=src_id, to_asset_id=dst_id,
                          relation=relation, note="LAN reachability (deep scan)"))
        db.flush()


def _shape_and_connect(db: Session, org_id: str, asset: Asset, scan: dict, cve_result: dict) -> None:
    """Place the scanned device in the topology so the EXISTING engine can trace
    a real attack path to it: infer its type/criticality from the scan and wire
    it under the discovered gateway (INTERNET → gateway → device)."""
    ports = {s.get("port") for s in scan.get("services", [])}
    if ports & _DB_PORTS and asset.asset_type == "server":
        asset.asset_type = "database"

    # a reachable device carrying a high/critical vuln is a crown-jewel-level risk
    worst = _worst_severity(cve_result.get("cves", []))
    if worst in ("critical", "high"):
        asset.zone_id = _ensure_zone(db, org_id, "At-Risk Devices", "crown_jewel").id
        asset.criticality = "critical" if worst == "critical" else "high"
    elif asset.zone_id is None:
        asset.zone_id = _ensure_zone(db, org_id, "LAN Devices", "internal").id

    # connect under the discovered gateway (if the device sweep found one) —
    # prefer the gateway the agent still sees ONLINE so a stale gateway from a
    # previous Wi-Fi can't keep re-attaching new scans to a dead edge node.
    gw_ip = db.scalar(
        select(NetworkDevice.ip).where(
            NetworkDevice.org_id == org_id,
            NetworkDevice.is_gateway.is_(True),
            NetworkDevice.online.is_(True),
        ).order_by(NetworkDevice.last_seen.desc())
    ) or db.scalar(
        select(NetworkDevice.ip).where(
            NetworkDevice.org_id == org_id, NetworkDevice.is_gateway.is_(True)
        ).order_by(NetworkDevice.last_seen.desc())
    )
    if gw_ip and gw_ip != asset.ip:
        gw = _ensure_gateway_asset(db, org_id, gw_ip)
        _ensure_edge(db, org_id, gw.id, asset.id, "network")
    db.flush()


def _upsert_asset(db: Session, org_id: str, ip: str, os_name: str | None) -> Asset:
    asset = db.scalar(select(Asset).where(Asset.org_id == org_id, Asset.ip == ip))
    if asset is None:
        asset = Asset(
            org_id=org_id,
            ip=ip,
            hostname=None,
            os=os_name,
            asset_type="server",  # generic until the scan tells us otherwise
            criticality="medium",
            business_value=Decimal("10000"),
            internet_facing=False,  # a LAN device — never fabricate exposure
        )
        db.add(asset)
        db.flush()
    elif os_name and not asset.os:
        asset.os = os_name
    return asset


def _replace_services(db: Session, org_id: str, asset: Asset, services: list[dict]) -> dict[int, str]:
    """Replace this asset's services with the freshly scanned ones. Returns port→service_id."""
    from sqlalchemy import delete
    db.execute(delete(Service).where(Service.asset_id == asset.id))
    db.flush()
    by_port: dict[int, str] = {}
    for s in services:
        svc = Service(
            org_id=org_id,
            asset_id=asset.id,
            port=s["port"],
            protocol=s.get("protocol", "tcp"),
            name=(s.get("service_name") or "unknown")[:120],
            version=(s.get("version") or None),
        )
        db.add(svc)
        db.flush()
        by_port[s["port"]] = svc.id
    return by_port


def _upsert_vuln(db: Session, cve: dict) -> Vulnerability:
    vuln = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve["id"]))
    severity = cve["severity"] if cve["severity"] in ("low", "medium", "high", "critical") else "medium"
    if vuln is None:
        vuln = Vulnerability(
            cve_id=cve["id"],
            title=f"{cve['id']} — {cve.get('affected_service', '').strip()}".strip(" —"),
            description=cve.get("summary") or None,
            cvss=Decimal(str(cve["cvss"])),
            severity=severity,
            exploitability=Decimal(str(cve.get("exploitability", 0.3))),
        )
        db.add(vuln)
        db.flush()
    return vuln


def _persist_host(db: Session, org_id: str, ip: str, scan: dict, cve_result: dict) -> dict:
    """Persist ONE scanned host as Asset+Services+Findings. No recompute here.

    Returns a partial summary (asset_id, services, ports, cves) that
    `_summarize_host` completes with engine numbers after a recompute."""
    asset = _upsert_asset(db, org_id, ip, scan.get("os"))
    by_port = _replace_services(db, org_id, asset, scan.get("services", []))

    cves = cve_result.get("cves", [])

    # batch-load the vulns for these CVEs (one query instead of one per CVE) and
    # create any that are missing in a single flush.
    cve_ids = [c["id"] for c in cves]
    vuln_by_cve: dict[str, Vulnerability] = (
        {
            v.cve_id: v
            for v in db.scalars(
                select(Vulnerability).where(Vulnerability.cve_id.in_(cve_ids))
            ).all()
        }
        if cve_ids
        else {}
    )
    created_vuln = False
    for cve in cves:
        if cve["id"] in vuln_by_cve:
            continue
        severity = cve["severity"] if cve["severity"] in ("low", "medium", "high", "critical") else "medium"
        vuln = Vulnerability(
            cve_id=cve["id"],
            title=f"{cve['id']} — {cve.get('affected_service', '').strip()}".strip(" —"),
            description=cve.get("summary") or None,
            cvss=Decimal(str(cve["cvss"])),
            severity=severity,
            exploitability=Decimal(str(cve.get("exploitability", 0.3))),
        )
        db.add(vuln)
        vuln_by_cve[cve["id"]] = vuln
        created_vuln = True
    if created_vuln:
        db.flush()

    # batch-load existing findings for this asset over exactly these vulns.
    vuln_ids = {vuln_by_cve[c["id"]].id for c in cves}
    finding_by_vuln: dict[str, AssetVulnerability] = (
        {
            f.vulnerability_id: f
            for f in db.scalars(
                select(AssetVulnerability).where(
                    AssetVulnerability.asset_id == asset.id,
                    AssetVulnerability.vulnerability_id.in_(vuln_ids),
                )
            ).all()
        }
        if vuln_ids
        else {}
    )
    created_finding = False
    for cve in cves:
        vuln = vuln_by_cve[cve["id"]]
        if vuln.id in finding_by_vuln:
            continue
        service_id = by_port.get(cve.get("port")) if cve.get("port") is not None else None
        finding = AssetVulnerability(
            org_id=org_id,
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            service_id=service_id,
            status="open",
        )
        db.add(finding)
        finding_by_vuln[vuln.id] = finding
        created_finding = True
    if created_finding:
        db.flush()

    cves_out: list[dict] = []
    for cve in cves:
        vuln = vuln_by_cve[cve["id"]]
        finding = finding_by_vuln[vuln.id]
        cves_out.append(
            {
                "id": cve["id"],
                "cvss": float(cve["cvss"]),
                "severity": vuln.severity,
                "summary": cve.get("summary") or "",
                "affected_service": cve.get("affected_service") or "",
                "finding_id": finding.id,
            }
        )

    # wire the device into the topology so the engine can trace a path to it
    _shape_and_connect(db, org_id, asset, scan, cve_result)

    return {
        "asset_id": asset.id,
        "target": ip,
        "os": asset.os,
        "services": [
            {
                "port": s["port"],
                "protocol": s.get("protocol", "tcp"),
                "service_name": s.get("service_name") or "unknown",
                "product": s.get("product"),
                "version": s.get("version"),
            }
            for s in scan.get("services", [])
        ],
        "ports": sorted({s["port"] for s in scan.get("services", [])}),
        "cves": cves_out,
    }


def _summarize_host(db: Session, org_id: str, partial: dict) -> dict:
    """Attach engine risk_score + top attack path to a persisted host (post-recompute)."""
    asset = db.get(Asset, partial["asset_id"])
    if asset is not None:
        db.refresh(asset)
    top_risk, formed = _top_path_for_asset(db, org_id, partial["asset_id"])
    return {
        **partial,
        "risk_score": float(asset.risk_score) if asset and asset.risk_score is not None else None,
        "top_path_risk": top_risk,
        "top_path_formed": formed,
    }


def apply_scan(db: Session, org_id: str, ip: str, scan: dict, cve_result: dict) -> dict:
    """Single-host: persist the real scan, run the EXISTING engine, summarize.

    Caller commits. Returns the fields the endpoint needs, including a finding_id
    per CVE so the UI can route into AI remediation."""
    from app.services.recompute import recompute_org

    partial = _persist_host(db, org_id, ip, scan, cve_result)
    recompute_org(db, org_id)  # the same engine used everywhere — no special-casing
    db.flush()
    return _summarize_host(db, org_id, partial)


def apply_range(db: Session, org_id: str, hosts: list[dict]) -> list[dict]:
    """Multi-host: persist every scanned host, run the engine ONCE, summarize each.

    `hosts` is a list of {scan, cve_result}. One recompute covers the whole batch
    so cross-host attack paths form on the real data. Caller commits."""
    from app.services.recompute import recompute_org

    partials = [
        _persist_host(db, org_id, h["scan"]["target"], h["scan"], h["cve_result"])
        for h in hosts
    ]
    recompute_org(db, org_id)
    db.flush()
    return [_summarize_host(db, org_id, p) for p in partials]


def _top_path_for_asset(db: Session, org_id: str, asset_id: str) -> tuple[float | None, bool]:
    """Highest-risk engine attack path that touches this asset (None if none formed)."""
    paths = db.scalars(
        select(AttackPath)
        .join(AttackPathStep, AttackPathStep.path_id == AttackPath.id)
        .where(AttackPath.org_id == org_id, AttackPathStep.asset_id == asset_id)
        .order_by(AttackPath.path_risk.desc())
    ).all()
    if not paths:
        return None, False
    return float(paths[0].path_risk), True
