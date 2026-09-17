# Drishti v0.1 — read-side query assembler | 11-Jul-2026
"""Read-side queries that assemble API response DTOs from cached engine output."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models import (
    Asset,
    AssetVulnerability,
    AttackPath,
    NetworkDevice,
    RiskZone,
    Service,
    Vulnerability,
)
from app.schemas.graph import (
    AssetDetail,
    AssetSummary,
    BlastRadiusOut,
    FindingOut,
    GraphEdge,
    GraphEdgeData,
    GraphMeta,
    GraphNode,
    GraphNodeData,
    GraphResponse,
    PathDetail,
    PathStepOut,
    PathSummary,
    ServiceOut,
)
from app.services.engine_loader import load_engine
from app.services.graph_layout import compute_positions
from app.services.attack_paths import find_targets
from app.services.recompute import blast_radius_for_asset
from app.services.risk_engine import INTERNET


def _open_findings_count(db: Session, org_id: str) -> dict[str, int]:
    rows = db.execute(
        select(AssetVulnerability.asset_id, func.count())
        .where(AssetVulnerability.org_id == org_id, AssetVulnerability.status == "open")
        .group_by(AssetVulnerability.asset_id)
    ).all()
    return {asset_id: count for asset_id, count in rows}


_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_LIVE_WINDOW_SECONDS = 90


def _live_device_ips(db: Session, org_id: str) -> set[str]:
    """IPs of devices the agent sees on the wire RIGHT NOW — online AND refreshed
    within the live window. Stale online rows (e.g. a previous Wi-Fi's gateway
    that never got marked offline) are excluded."""
    from datetime import timedelta, timezone

    from app.models import NetworkDevice
    from app.models.base import utcnow

    cutoff = utcnow() - timedelta(seconds=_LIVE_WINDOW_SECONDS)
    out: set[str] = set()
    for d in db.scalars(
        select(NetworkDevice).where(
            NetworkDevice.org_id == org_id, NetworkDevice.online.is_(True)
        )
    ).all():
        last = d.last_seen
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if last is not None and last >= cutoff:
            out.add(d.ip)
    return out


def _threats_by_ip(db: Session, org_id: str) -> dict:
    """Most-severe active network threat per device IP — so the attack map can
    light up the nodes an attack is actually touching."""
    from app.services.live_threats import network_threats

    out: dict = {}
    for t in network_threats(db, org_id):
        ip = t.device_ip
        if not ip:
            continue
        cur = out.get(ip)
        if cur is None or _SEV_RANK.get(t.severity, 0) > _SEV_RANK.get(cur.severity, 0):
            out[ip] = t
    return out


def _live_gateway(db: Session, org_id: str):
    """The gateway the agent sees ONLINE right now (most-recent), or None."""
    from datetime import timedelta, timezone

    from app.models import NetworkDevice
    from app.models.base import utcnow

    cutoff = utcnow() - timedelta(seconds=_LIVE_WINDOW_SECONDS)
    for d in db.scalars(
        select(NetworkDevice).where(
            NetworkDevice.org_id == org_id,
            NetworkDevice.is_gateway.is_(True),
            NetworkDevice.online.is_(True),
        ).order_by(NetworkDevice.last_seen.desc())
    ).all():
        last = d.last_seen
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if last is not None and last >= cutoff:
            return d
    return None


def _live_device_nodes(
    db: Session, org_id: str, gateway, asset_id_by_ip: dict, threats_by_ip: dict
) -> tuple[list[GraphNode], list[GraphEdge]]:
    """Render the devices the agent sees on the wire as attack-map nodes, wired
    INTERNET → gateway → device. The gateway ALWAYS renders as its own gateway
    node (even when it's been deep-scanned into an asset) so it can't vanish;
    every other live device — raw or deep-scanned asset — hangs off it. This is
    what makes the attack map show the REAL live network."""
    from datetime import timedelta, timezone

    from app.models import NetworkDevice
    from app.models.base import utcnow

    cutoff = utcnow() - timedelta(seconds=_LIVE_WINDOW_SECONDS)
    rows = db.scalars(
        select(NetworkDevice).where(
            NetworkDevice.org_id == org_id, NetworkDevice.online.is_(True)
        )
    ).all()
    gw_ip = gateway.ip if gateway is not None else None

    # raw (non-asset, non-gateway) devices, deduped by IP
    by_ip: dict[str, NetworkDevice] = {}
    for r in rows:
        last = r.last_seen
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if last is None or last < cutoff:
            continue
        if r.ip == gw_ip or r.ip in asset_id_by_ip:
            continue  # gateway + deep-scanned devices render elsewhere
        if r.ip not in by_ip:
            by_ip[r.ip] = r

    others = list(by_ip.values())

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    def _node(d: NetworkDevice, x: float, y: float) -> GraphNode:
        t = threats_by_ip.get(d.ip)
        atype = "router" if d.is_gateway else ("workstation" if d.is_self else "iot")
        label = d.hostname or d.ip
        return GraphNode(
            id=f"dev:{d.id}",
            type="device",
            data=GraphNodeData(
                label=label, asset_type=atype, zone=None, criticality="low",
                risk_score=(90.0 if t and t.severity == "critical"
                            else 70.0 if t and t.severity == "high"
                            else 45.0 if t else 0.0),
                business_value=0.0, internet_facing=bool(d.is_gateway),
                open_findings=0, is_device=True, is_gateway=bool(d.is_gateway),
                online=bool(d.online), mac=d.mac, vendor=d.vendor, ip=d.ip,
                threat=bool(t), threat_kind=t.kind if t else None,
                threat_severity=t.severity if t else None,
                threat_title=t.title if t else None, mitre=t.mitre if t else None,
            ),
            position={"x": x, "y": y},
        )

    def _edge(src: str, dst: str) -> GraphEdge:
        return GraphEdge(
            id=f"{src}->{dst}", source=src, target=dst,
            data=GraphEdgeData(relation="network", weight=1.0),
        )

    # gateway hangs off INTERNET (always its own node, even if deep-scanned)
    gw_id = None
    if gateway is not None:
        gw_id = f"dev:{gateway.id}"
        nodes.append(_node(gateway, 320.0, 320.0))
        edges.append(_edge(INTERNET, gw_id))
    # raw devices hang off the gateway
    for i, d in enumerate(others):
        did = f"dev:{d.id}"
        col = i % 2
        row = i // 2
        nodes.append(_node(d, 620.0 + col * 200.0, 120.0 + row * 120.0))
        edges.append(_edge(gw_id or INTERNET, did))

    # deep-scanned live-device assets also hang off the current gateway
    if gw_id is not None:
        for aid in asset_id_by_ip.values():
            edges.append(_edge(gw_id, aid))

    return nodes, edges


def build_graph(db: Session, org_id: str, focus: str | None = None) -> GraphResponse:
    engine = load_engine(db, org_id)
    positions = compute_positions(engine)
    open_counts = _open_findings_count(db, org_id)
    targets = set(find_targets(engine))

    # on-top-path edges from cached paths; each edge remembers the highest-risk
    # path it belongs to so the UI can open that path on edge click
    top_edges: set[tuple[str, str]] = set()
    edge_path_ids: dict[tuple[str, str], str] = {}
    paths = db.scalars(
        select(AttackPath)
        .where(AttackPath.org_id == org_id)
        .order_by(AttackPath.path_risk.desc())
        .options(selectinload(AttackPath.steps))
    ).all()
    for p in paths:
        prev = INTERNET
        for step in p.steps:
            top_edges.add((prev, step.asset_id))
            edge_path_ids.setdefault((prev, step.asset_id), p.id)
            prev = step.asset_id

    blast_ids: set[str] = set()
    if focus and focus in engine.graph:
        blast_ids, _ = blast_radius_for_asset(engine, focus)

    # vuln cve lookup for edge via_cve — only load the vulns actually referenced
    # by an edge (Vulnerability has no org_id, so a blanket select loads the
    # whole global catalog).
    referenced_vuln_ids = {
        edge.via_vuln_id for edge in engine.edges.values() if edge.via_vuln_id
    }
    vuln_map = (
        {
            v.id: v
            for v in db.scalars(
                select(Vulnerability).where(Vulnerability.id.in_(referenced_vuln_ids))
            ).all()
        }
        if referenced_vuln_ids
        else {}
    )

    # Resolve live gateway or fallback gateway for this org
    gateway_dev = _live_gateway(db, org_id)
    if gateway_dev is None:
        gateway_dev = db.scalars(
            select(NetworkDevice).where(
                NetworkDevice.org_id == org_id,
                NetworkDevice.is_gateway.is_(True),
            ).order_by(NetworkDevice.last_seen.desc())
        ).first()
    gateway_ip = gateway_dev.ip if gateway_dev is not None else None

    nodes: list[GraphNode] = []
    # synthetic INTERNET / Entry Gateway node
    inet_pos = positions.get(INTERNET, {"x": 40.0, "y": 320.0})
    nodes.append(
        GraphNode(
            id=INTERNET,
            type="internet",
            data=GraphNodeData(
                label=f"GATEWAY ({gateway_ip})" if gateway_ip else "GATEWAY / UPLINK",
                ip=gateway_ip,
                mac=gateway_dev.mac if gateway_dev else None,
                vendor=gateway_dev.vendor if gateway_dev else None,
                asset_type="router" if gateway_ip else "cloud",
                zone="Uplink / Perimeter",
                criticality="low",
                risk_score=0.0,
                business_value=0.0,
                internet_facing=True,
                open_findings=0,
                is_gateway=bool(gateway_ip),
                in_blast_radius=(INTERNET in blast_ids) if focus else None,
            ),
            position=inet_pos,
        )
    )

    assets = db.scalars(select(Asset).where(Asset.org_id == org_id)).all()
    zones = {z.id: z for z in db.scalars(select(RiskZone).where(RiskZone.org_id == org_id)).all()}

    # Live-only gate: once the agent has reported ANY device for this org, the
    # attack map reflects the REAL network — an asset shows only if its IP is a
    # device the agent currently sees ONLINE. A machine that went offline drops
    # off; an asset with no live device (a fabricated/stale row) is never shown.
    # When no device has been reported yet (a pure sample/imported assessment,
    # or the DEMO_SEED demo before an agent runs), nothing is gated, so the
    # seeded graph renders as-is. The count of live devices is what flips the
    # gate — it is never hardcoded.
    # A device counts as "live" only if it is online AND was refreshed recently
    # (same 90s window as list_devices) — a stale online row from a previous
    # Wi-Fi must not keep an asset (or an old gateway) on the map forever.
    any_device_rows = (
        db.scalar(select(NetworkDevice.id).where(NetworkDevice.org_id == org_id)) is not None
    )
    live_ips = _live_device_ips(db, org_id)
    if any_device_rows:
        hidden_ids: set[str] = {a.id for a in assets if a.ip not in live_ips}
    else:
        hidden_ids = set()
    assets = [a for a in assets if a.id not in hidden_ids]

    # the live gateway always renders as its own gateway node (below), even when
    # it's been deep-scanned into an asset — so skip its asset row here
    gateway_dev = _live_gateway(db, org_id)
    gateway_ip = gateway_dev.ip if gateway_dev is not None else None

    # active threats per device IP — asset nodes on a threatened IP light up too
    threats_by_ip = _threats_by_ip(db, org_id)

    for a in assets:
        if a.ip == gateway_ip:
            continue  # rendered as the gateway device node instead
        zone = zones.get(a.zone_id)
        t = threats_by_ip.get(a.ip)
        nodes.append(
            GraphNode(
                id=a.id,
                type="asset",
                data=GraphNodeData(
                    label=a.hostname or a.ip,
                    ip=a.ip,
                    asset_type=a.asset_type,
                    zone=zone.name if zone else None,
                    criticality=a.criticality,
                    risk_score=float(a.risk_score or 0.0),
                    business_value=float(a.business_value or 0.0),
                    internet_facing=bool(a.internet_facing),
                    open_findings=open_counts.get(a.id, 0),
                    is_crown_jewel=a.id in targets,
                    in_blast_radius=(a.id in blast_ids) if focus else None,
                    threat=bool(t), threat_kind=t.kind if t else None,
                    threat_severity=t.severity if t else None,
                    threat_title=t.title if t else None, mitre=t.mitre if t else None,
                ),
                position=positions.get(a.id, {"x": 620.0, "y": 320.0}),
            )
        )

    edges: list[GraphEdge] = []
    for (u, v), edge in engine.edges.items():
        if u in hidden_ids or v in hidden_ids:
            continue
        via_cve = None
        if edge.via_vuln_id and edge.via_vuln_id in vuln_map:
            via_cve = vuln_map[edge.via_vuln_id].cve_id
        edges.append(
            GraphEdge(
                id=f"{u}->{v}",
                source=u,
                target=v,
                data=GraphEdgeData(
                    relation=edge.relation,
                    weight=edge.weight,
                    via_cve=via_cve,
                    on_top_path=(u, v) in top_edges,
                    path_id=edge_path_ids.get((u, v)),
                ),
            )
        )

    # add the live devices the agent sees on the wire (not already assets), so
    # the attack map shows the REAL network + any attack lighting up its nodes
    asset_id_by_ip = {a.ip: a.id for a in assets if a.ip != gateway_ip}
    dev_nodes, dev_edges = _live_device_nodes(db, org_id, gateway_dev, asset_id_by_ip, threats_by_ip)
    nodes.extend(dev_nodes)
    # drop any duplicate edge ids (a re-wired asset already reachable via engine)
    seen_edge_ids = {e.id for e in edges}
    edges.extend(e for e in dev_edges if e.id not in seen_edge_ids)

    return GraphResponse(
        nodes=nodes,
        edges=edges,
        meta=GraphMeta(
            entry_nodes=[INTERNET],
            crown_jewels=[t for t in targets if t not in hidden_ids],
            focus=focus,
            blast_radius_ids=sorted(blast_ids - hidden_ids),
        ),
    )


def _asset_summary(db: Session, a: Asset, zones: dict, open_counts: dict) -> AssetSummary:
    zone = zones.get(a.zone_id)
    return AssetSummary(
        id=a.id,
        hostname=a.hostname,
        ip=a.ip,
        asset_type=a.asset_type,
        zone=zone.name if zone else None,
        criticality=a.criticality,
        business_value=float(a.business_value or 0.0),
        internet_facing=bool(a.internet_facing),
        risk_score=float(a.risk_score) if a.risk_score is not None else None,
        blast_radius_count=a.blast_radius_count,
        open_findings=open_counts.get(a.id, 0),
    )


def list_assets(db: Session, org_id: str, filters: dict) -> list[AssetSummary]:
    stmt = select(Asset).where(Asset.org_id == org_id)
    if filters.get("internet_facing") is not None:
        stmt = stmt.where(Asset.internet_facing == filters["internet_facing"])
    if filters.get("criticality"):
        stmt = stmt.where(Asset.criticality == filters["criticality"])
    if filters.get("q"):
        like = f"%{filters['q']}%"
        stmt = stmt.where((Asset.hostname.ilike(like)) | (Asset.ip.ilike(like)))
    assets = db.scalars(stmt.order_by(Asset.risk_score.desc().nullslast())).all()
    zones = {z.id: z for z in db.scalars(select(RiskZone).where(RiskZone.org_id == org_id)).all()}
    open_counts = _open_findings_count(db, org_id)
    result = [_asset_summary(db, a, zones, open_counts) for a in assets]
    if filters.get("zone"):
        result = [r for r in result if r.zone == filters["zone"]]
    return result


def get_asset_detail(db: Session, org_id: str, asset_id: str) -> AssetDetail | None:
    a = db.scalar(select(Asset).where(Asset.org_id == org_id, Asset.id == asset_id))
    if a is None:
        return None
    zones = {z.id: z for z in db.scalars(select(RiskZone).where(RiskZone.org_id == org_id)).all()}
    open_counts = _open_findings_count(db, org_id)
    summary = _asset_summary(db, a, zones, open_counts)

    services = [
        ServiceOut(id=s.id, port=s.port, protocol=s.protocol, name=s.name, version=s.version)
        for s in db.scalars(select(Service).where(Service.asset_id == a.id)).all()
    ]
    findings = _findings_for_asset(db, org_id, a)

    engine = load_engine(db, org_id)
    _, downstream = blast_radius_for_asset(engine, a.id)

    return AssetDetail(
        **summary.model_dump(),
        os=a.os,
        services=services,
        findings=findings,
        downstream_value=downstream,
    )


def _findings_for_asset(db: Session, org_id: str, asset: Asset) -> list[FindingOut]:
    rows = db.execute(
        select(AssetVulnerability, Vulnerability, Service)
        .join(Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
        .join(Service, AssetVulnerability.service_id == Service.id, isouter=True)
        .where(AssetVulnerability.asset_id == asset.id)
    ).all()
    out = []
    for av, vuln, svc in rows:
        out.append(
            FindingOut(
                id=av.id,
                status=av.status,
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
                detected_at=av.detected_at.isoformat() if av.detected_at else None,
            )
        )
    return out


def blast_radius_response(db: Session, org_id: str, asset_id: str) -> BlastRadiusOut | None:
    a = db.scalar(select(Asset).where(Asset.org_id == org_id, Asset.id == asset_id))
    if a is None:
        return None
    engine = load_engine(db, org_id)
    blast, value = blast_radius_for_asset(engine, asset_id)
    return BlastRadiusOut(
        asset_id=asset_id,
        count=len(blast),
        downstream_value=value,
        reachable_ids=sorted(blast),
    )


def list_findings(db: Session, org_id: str, filters: dict) -> list[FindingOut]:
    stmt = (
        select(AssetVulnerability, Vulnerability, Asset, Service)
        .join(Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .join(Service, AssetVulnerability.service_id == Service.id, isouter=True)
        .where(AssetVulnerability.org_id == org_id)
    )
    if filters.get("severity"):
        stmt = stmt.where(Vulnerability.severity == filters["severity"])
    if filters.get("status"):
        stmt = stmt.where(AssetVulnerability.status == filters["status"])
    rows = db.execute(stmt.order_by(Vulnerability.cvss.desc())).all()
    out = []
    for av, vuln, asset, svc in rows:
        out.append(
            FindingOut(
                id=av.id,
                status=av.status,
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
                detected_at=av.detected_at.isoformat() if av.detected_at else None,
            )
        )
    return out


def _path_summary(db: Session, p: AttackPath) -> PathSummary:
    target = db.get(Asset, p.target_asset_id)
    return PathSummary(
        id=p.id,
        entry_label=p.entry_label,
        target_asset_id=p.target_asset_id,
        target_hostname=target.hostname if target else None,
        hop_count=p.hop_count,
        path_risk=float(p.path_risk),
        likelihood=float(p.likelihood),
        impact_usd=float(p.impact_usd),
        narrative=p.narrative,
    )


def list_paths(db: Session, org_id: str, limit: int = 25) -> list[PathSummary]:
    paths = db.scalars(
        select(AttackPath)
        .where(AttackPath.org_id == org_id)
        .order_by(AttackPath.path_risk.desc())
        .limit(limit)
    ).all()
    return [_path_summary(db, p) for p in paths]


def get_path_detail(db: Session, org_id: str, path_id: str) -> PathDetail | None:
    p = db.scalar(select(AttackPath).where(AttackPath.org_id == org_id, AttackPath.id == path_id))
    if p is None:
        return None
    summary = _path_summary(db, p)
    steps: list[PathStepOut] = []
    drivers: list[str] = []
    zones = {z.id: z for z in db.scalars(select(RiskZone).where(RiskZone.org_id == org_id)).all()}
    for step in p.steps:
        asset = db.get(Asset, step.asset_id)
        vuln = db.get(Vulnerability, step.via_vulnerability_id) if step.via_vulnerability_id else None
        zone = zones.get(asset.zone_id) if asset else None
        steps.append(
            PathStepOut(
                step_index=step.step_index,
                asset_id=step.asset_id,
                asset_hostname=asset.hostname if asset else None,
                asset_ip=asset.ip if asset else "",
                asset_type=asset.asset_type if asset else "server",
                zone=zone.name if zone else None,
                via_cve=vuln.cve_id if vuln else None,
                via_title=vuln.title if vuln else None,
                via_severity=vuln.severity if vuln else None,
                via_cvss=float(vuln.cvss) if vuln else None,
                edge_weight=float(step.edge_weight) if step.edge_weight is not None else None,
            )
        )
        if vuln:
            drivers.append(vuln.title)
    return PathDetail(**summary.model_dump(), steps=steps, drivers=drivers[:3])
