# Drishti v0.1 — bulk graph loader from database | 11-Jul-2026
"""Bulk-load an org's graph from the DB into the engine (few queries, no per-node round trips)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AssetVulnerability, Connection, RiskZone, Vulnerability
from app.services.risk_engine import EdgeData, Engine, NodeData, RiskConfig, build_engine


def load_engine(db: Session, org_id: str, config: RiskConfig | None = None) -> Engine:
    zones = {z.id: z for z in db.scalars(select(RiskZone).where(RiskZone.org_id == org_id)).all()}
    assets = db.scalars(select(Asset).where(Asset.org_id == org_id)).all()

    # open findings joined with their vuln, grouped by asset
    rows = db.execute(
        select(AssetVulnerability, Vulnerability)
        .join(Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
        .where(
            AssetVulnerability.org_id == org_id,
            AssetVulnerability.status.in_(("open", "remediating")),
        )
    ).all()

    findings_by_asset: dict[str, list[tuple[AssetVulnerability, Vulnerability]]] = {}
    for av, vuln in rows:
        findings_by_asset.setdefault(av.asset_id, []).append((av, vuln))

    nodes: list[NodeData] = []
    for a in assets:
        zone = zones.get(a.zone_id)
        finds = findings_by_asset.get(a.id, [])
        max_exploit = 0.1
        max_cvss = 1.0
        top_vuln_id: str | None = None
        best_rank = -1.0
        for _av, vuln in finds:
            expl = float(vuln.exploitability or 0.0)
            cvss = float(vuln.cvss or 0.0)
            max_exploit = max(max_exploit, expl)
            max_cvss = max(max_cvss, cvss)
            rank = 0.6 * expl + 0.4 * (cvss / 10.0)
            if rank > best_rank:
                best_rank = rank
                top_vuln_id = vuln.id
        nodes.append(
            NodeData(
                id=a.id,
                label=a.hostname or a.ip,
                asset_type=a.asset_type,
                zone=zone.name if zone else None,
                zone_kind=zone.kind if zone else None,
                criticality=a.criticality,
                business_value=float(a.business_value or 0.0),
                internet_facing=bool(a.internet_facing),
                open_findings=len(finds),
                max_exploitability=max_exploit,
                max_cvss=max_cvss,
                top_finding_vuln_id=top_vuln_id,
            )
        )

    connections = db.scalars(select(Connection).where(Connection.org_id == org_id)).all()
    edges = [
        EdgeData(source=c.from_asset_id, target=c.to_asset_id, relation=c.relation)
        for c in connections
    ]

    return build_engine(nodes, edges, config)
