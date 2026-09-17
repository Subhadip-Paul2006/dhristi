# Drishti v0.1 — server-side layered graph layout | 11-Jul-2026
"""Server-side graph layout (BACKEND.md §6): layered by zone, left→right.

INTERNET at far left; DMZ → App Tier → Data Tier as columns so attack flow
reads left→right. Positions are deterministic so the graph doesn't jump.
"""
from __future__ import annotations

from app.services.risk_engine import INTERNET, Engine

# column index by zone kind (attack flows left → right toward crown jewels)
ZONE_COLUMN = {"dmz": 1, "internal": 2, "cloud": 2, "crown_jewel": 3}
COL_X = {0: 40, 1: 320, 2: 620, 3: 940}
COL_GAP_X = 300
ROW_GAP_Y = 120
TOP_Y = 80


def _column_for(engine: Engine, node_id: str) -> int:
    node = engine.nodes[node_id]
    if node.zone_kind in ZONE_COLUMN:
        return ZONE_COLUMN[node.zone_kind]
    # Fall back on asset type when a zone kind is missing.
    if node.internet_facing:
        return 1
    if node.asset_type == "database":
        return 3
    return 2


def compute_positions(engine: Engine) -> dict[str, dict[str, float]]:
    columns: dict[int, list[str]] = {}
    positions: dict[str, dict[str, float]] = {}

    positions[INTERNET] = {"x": float(COL_X[0]), "y": 320.0}

    for node_id in engine.nodes:
        if node_id == INTERNET:
            continue
        col = _column_for(engine, node_id)
        columns.setdefault(col, []).append(node_id)

    for col, node_ids in columns.items():
        # deterministic vertical order within a column
        node_ids.sort(key=lambda nid: (engine.nodes[nid].label or nid))
        x = float(COL_X.get(col, COL_X[0] + col * COL_GAP_X))
        n = len(node_ids)
        total_h = (n - 1) * ROW_GAP_Y
        start_y = max(TOP_Y, 320.0 - total_h / 2)
        for i, node_id in enumerate(node_ids):
            positions[node_id] = {"x": x, "y": start_y + i * ROW_GAP_Y}

    return positions
