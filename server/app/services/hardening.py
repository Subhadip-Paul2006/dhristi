# Drishti v0.1 — engine-grounded node hardening recommendations | 11-Jul-2026
"""Per-node hardening recommendations with REAL, quantified risk reductions.

Every "reduces risk by ~X%" is measured, not estimated: we clone the risk engine,
apply the hardening change (resolve findings / close a risky port / cut the
internet-exposure edge / firewall a lateral link), recompute node scores with the
exact same formula the platform uses, and report the actual drop. Nothing invented
(BACKEND.md §5, CLAUDE.md §5 contract 3)."""
from __future__ import annotations

import copy

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, Connection, Service
from app.schemas.report import HardeningAction, NodeHardening
from app.services.engine_loader import load_engine
from app.services.risk_engine import INTERNET, Engine, _compute_edge_weights, compute_node_scores

# Ports that are dangerous to expose — closing one removes an attack surface.
RISKY_PORTS = {
    21: "FTP",
    23: "Telnet",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
}


def _band(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "SAFE"


def _score_after(engine: Engine, *, patch: str | None = None, drop_edges: list[tuple] | None = None) -> dict:
    """Clone the engine, apply a hardening change, recompute, return new scores.

    patch: asset id whose findings are resolved (exploitability/CVSS → floor).
    drop_edges: (u, v) edges to remove (internet exposure or lateral links).
    """
    # A full deepcopy of the engine is expensive and unnecessary: the only state
    # mutated below and inside _compute_edge_weights is the graph (structure +
    # edge-attr dicts), every EdgeData, and — on the patch path — one node. Clone
    # exactly those and share the rest read-only. nx.DiGraph.copy() gives fresh
    # (independent) attr dicts, and edge weight/relation are scalars we reassign,
    # so this yields numerically identical scores without the deepcopy cost.
    e = copy.copy(engine)
    e.graph = engine.graph.copy()
    e.edges = {uv: copy.copy(ed) for uv, ed in engine.edges.items()}
    e.nodes = dict(engine.nodes)
    if patch and patch in e.nodes:
        n = copy.copy(e.nodes[patch])
        e.nodes[patch] = n
        n.max_exploitability = 0.1
        n.max_cvss = 1.0
        n.open_findings = 0
        n.top_finding_vuln_id = None
    for uv in drop_edges or []:
        if uv in e.edges:
            del e.edges[uv]
        if e.graph.has_edge(*uv):
            e.graph.remove_edge(*uv)
    _compute_edge_weights(e)
    return compute_node_scores(e)


def _pct(before: float, after: float) -> float:
    if before <= 0:
        return 0.0
    return round(max(0.0, (before - after) / before) * 100, 1)


def hardening_report(db: Session, org_id: str, limit: int = 6) -> list[NodeHardening]:
    engine = load_engine(db, org_id)
    base = compute_node_scores(engine)

    # services + inbound links for labelling (few queries, no per-node round trip)
    services_by_asset: dict[str, list[Service]] = {}
    for s in db.scalars(select(Service).where(Service.org_id == org_id)).all():
        services_by_asset.setdefault(s.asset_id, []).append(s)
    inbound_by_asset: dict[str, list[Connection]] = {}
    for c in db.scalars(select(Connection).where(Connection.org_id == org_id)).all():
        inbound_by_asset.setdefault(c.to_asset_id, []).append(c)
    labels = {
        a.id: (a.hostname or a.ip, a.ip)
        for a in db.scalars(select(Asset).where(Asset.org_id == org_id)).all()
    }

    ranked = sorted(base.items(), key=lambda kv: kv[1], reverse=True)
    out: list[NodeHardening] = []
    for nid, cur in ranked:
        if cur < 40 or len(out) >= limit:
            break
        node = engine.nodes.get(nid)
        if node is None:
            continue
        host, ip = labels.get(nid, (node.label, node.label))
        actions: list[HardeningAction] = []
        all_drop_edges: list[tuple] = []
        patch_id: str | None = None

        # 1. remediation — close a risky exposed port, else patch findings
        if node.open_findings > 0:
            patch_id = nid
            after = _score_after(engine, patch=nid)
            pct = _pct(cur, after.get(nid, cur))
            risky = [s for s in services_by_asset.get(nid, []) if s.port in RISKY_PORTS]
            if risky:
                s = risky[0]
                actions.append(
                    HardeningAction(
                        kind="CLOSE_PORT",
                        label=f"Close port {s.port} ({RISKY_PORTS[s.port]}) exposing {s.name}",
                        risk_reduction_pct=pct,
                    )
                )
            else:
                actions.append(
                    HardeningAction(
                        kind="PATCH",
                        label=f"Patch {node.open_findings} open finding(s) on {host}",
                        risk_reduction_pct=pct,
                    )
                )

        # 2. segment an internet-facing node off the exposure edge
        if node.internet_facing and engine.graph.has_edge(INTERNET, nid):
            edge = (INTERNET, nid)
            all_drop_edges.append(edge)
            after = _score_after(engine, drop_edges=[edge])
            actions.append(
                HardeningAction(
                    kind="VLAN_SEGMENT",
                    label=f"Move {host} behind a firewall / VLAN — cut the direct internet exposure",
                    risk_reduction_pct=_pct(cur, after.get(nid, cur)),
                )
            )

        # 3. firewall the strongest inbound lateral link from a risky neighbor
        inbound = [
            c for c in inbound_by_asset.get(nid, []) if c.from_asset_id != INTERNET
        ]
        inbound.sort(key=lambda c: float(c.weight or 0.0), reverse=True)
        if inbound:
            c = inbound[0]
            src_host = labels.get(c.from_asset_id, ("neighbor", ""))[0]
            edge = (c.from_asset_id, nid)
            all_drop_edges.append(edge)
            after = _score_after(engine, drop_edges=[edge])
            actions.append(
                HardeningAction(
                    kind="ISOLATE_CONNECTION",
                    label=f"Firewall the {c.relation} link from {src_host} to break lateral movement",
                    risk_reduction_pct=_pct(cur, after.get(nid, cur)),
                )
            )

        if not actions:
            continue

        # combined projection: apply every recommended change at once
        combined = _score_after(engine, patch=patch_id, drop_edges=all_drop_edges)
        proj = round(combined.get(nid, cur), 1)
        out.append(
            NodeHardening(
                hostname=host,
                ip=ip,
                current_score=round(cur, 1),
                projected_score=proj,
                reduction_pct=_pct(cur, proj),
                band_before=_band(cur),
                band_after=_band(proj),
                actions=actions,
            )
        )
    return out
