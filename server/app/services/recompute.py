# Drishti v0.1 — recompute orchestration | 11-Jul-2026
"""Recompute orchestration: build graph → scores → paths → impact → cache.

Per-org, idempotent. Triggered on ingest, finding resolve, or asset edit
(BACKEND.md §8). For the demo network (≤200 nodes) this runs well under 500 ms.
"""
from __future__ import annotations

import time
from decimal import Decimal

from sqlalchemy import delete, select, text, update
from sqlalchemy.orm import Session

from app.models import Asset, AttackPath, AttackPathStep, Connection
from app.services.attack_paths import blast_radius_value, enumerate_paths
from app.services.engine_loader import load_engine
from app.services.impact import id_key, path_impact_usd
from app.services.risk_engine import INTERNET, Engine, blast_radius, compute_node_scores

# in-memory timing/counters for GET /api/stats and the demo narrative
_LAST_STATS: dict[str, dict] = {}


def recompute_org(db: Session, org_id: str) -> dict:
    start = time.perf_counter()
    if db.bind.dialect.name != "sqlite":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:oid))"), {"oid": org_id})
    engine = load_engine(db, org_id)

    scores = compute_node_scores(engine)
    paths = enumerate_paths(engine)

    # cache node risk scores + blast radius counts
    for node_id, node in engine.nodes.items():
        if node_id == INTERNET:
            continue
        blast = blast_radius(engine, node_id)
        db.execute(
            update(Asset)
            .where(Asset.id == node_id)
            .values(
                risk_score=Decimal(str(scores.get(node_id, 0.0))),
                blast_radius_count=len(blast),
            )
        )

    # persist edge weights back to connections (engine may recompute them)
    conns = db.scalars(select(Connection).where(Connection.org_id == org_id)).all()
    for c in conns:
        edge = engine.edges.get((c.from_asset_id, c.to_asset_id))
        if edge is not None:
            c.weight = Decimal(str(edge.weight))

    # replace cached attack paths + steps
    old_path_ids = db.scalars(select(AttackPath.id).where(AttackPath.org_id == org_id)).all()
    if old_path_ids:
        db.execute(delete(AttackPathStep).where(AttackPathStep.path_id.in_(old_path_ids)))
        db.execute(delete(AttackPath).where(AttackPath.org_id == org_id))
    db.flush()

    impacts: dict[str, float] = {}
    for p in paths:
        impact = path_impact_usd(engine, p)
        impacts[id_key(p)] = impact

        path_row = AttackPath(
            org_id=org_id,
            entry_label=p.entry_label,
            target_asset_id=p.target_asset_id,
            hop_count=p.hop_count,
            path_risk=Decimal(str(p.path_risk)),
            likelihood=Decimal(str(p.likelihood)),
            impact_usd=Decimal(str(impact)),
        )
        db.add(path_row)
        db.flush()
        for idx, step in enumerate(p.steps):
            db.add(
                AttackPathStep(
                    path_id=path_row.id,
                    step_index=idx,
                    asset_id=step.asset_id,
                    via_vulnerability_id=step.via_vuln_id,
                    edge_weight=Decimal(str(step.edge_weight))
                    if step.edge_weight is not None
                    else None,
                )
            )

    db.flush()

    elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
    _LAST_STATS[org_id] = {
        "nodes": engine.graph.number_of_nodes(),
        "edges": engine.graph.number_of_edges(),
        "paths": len(paths),
        "recompute_ms": elapsed_ms,
        "top_path_risk": paths[0].path_risk if paths else 0.0,
    }
    return _LAST_STATS[org_id]


def last_stats(org_id: str) -> dict:
    return _LAST_STATS.get(org_id, {})


def blast_radius_for_asset(engine: Engine, asset_id: str) -> tuple[set[str], float]:
    blast = blast_radius(engine, asset_id)
    return blast, blast_radius_value(engine, asset_id, blast)
