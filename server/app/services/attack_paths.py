# Drishti v0.1 — bounded attack path enumeration engine | 11-Jul-2026
"""Bounded attack-path enumeration + path risk/likelihood (BACKEND.md §5.4–5.5).

Never enumerate the unbounded combinatorial set: use Yen's shortest_simple_paths
(paths in increasing weight), cap per target, cap hop length, keep global top-K.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from app.services.risk_engine import (
    CRIT_FACTOR,
    INTERNET,
    Engine,
    NodeData,
    hop_ease,
    value_factor,
)

# Hard ceiling on candidates pulled from shortest_simple_paths per target,
# counted whether or not they're kept: without this a target reachable only
# via long paths forces enumeration of every simple path in the graph.
MAX_CANDIDATES_PER_TARGET = 500


@dataclass
class PathStep:
    asset_id: str
    via_vuln_id: str | None
    edge_weight: float | None


@dataclass
class ScoredPath:
    entry_label: str
    target_asset_id: str
    hop_count: int
    path_risk: float
    likelihood: float
    total_weight: float
    steps: list[PathStep] = field(default_factory=list)
    node_ids: list[str] = field(default_factory=list)
    edge_pairs: list[tuple[str, str]] = field(default_factory=list)


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def find_targets(engine: Engine) -> list[str]:
    """Crown jewels: crown_jewel zone OR critical OR top-decile business value."""
    reals = [n for nid, n in engine.nodes.items() if nid != INTERNET]
    if not reals:
        return []
    values = sorted((n.business_value for n in reals), reverse=True)
    decile_index = max(0, int(len(values) * 0.1) - 1)
    top_decile_threshold = values[decile_index] if values else 0.0

    targets: list[str] = []
    for n in reals:
        if (
            n.zone_kind == "crown_jewel"
            or n.criticality == "critical"
            or n.business_value >= top_decile_threshold
        ):
            targets.append(n.id)
    return targets


def _total_weight(engine: Engine, node_path: list[str]) -> float:
    total = 0.0
    for u, v in zip(node_path, node_path[1:]):
        total += engine.graph[u][v].get("weight", 1.0)
    return total


def _normalize_weight(total_weight: float, all_weights: list[float]) -> float:
    if not all_weights:
        return 0.0
    lo, hi = min(all_weights), max(all_weights)
    if hi <= lo:
        return 0.0
    return _clamp((total_weight - lo) / (hi - lo), 0.0, 1.0)


def _score_path(engine: Engine, node_path: list[str], weight_norm: float) -> ScoredPath:
    cfg = engine.config
    target = engine.nodes[node_path[-1]]

    # likelihood = product of per-hop ease (chained easiness, decays with length)
    likelihood = 1.0
    steps: list[PathStep] = []
    edge_pairs: list[tuple[str, str]] = []
    for u, v in zip(node_path, node_path[1:]):
        dest = engine.nodes[v]
        likelihood *= hop_ease(engine, u, v)
        edge = engine.edges.get((u, v))
        steps.append(
            PathStep(
                asset_id=v,
                via_vuln_id=edge.via_vuln_id if edge else dest.top_finding_vuln_id,
                edge_weight=engine.graph[u][v].get("weight"),
            )
        )
        edge_pairs.append((u, v))
    likelihood = _clamp(likelihood, 0.001, 0.999)

    target_value_f = value_factor(engine, target)
    target_crit_f = CRIT_FACTOR.get(target.criticality, 0.5)

    path_risk = 100.0 * (
        cfg.pw_likelihood * likelihood
        + cfg.pw_value * target_value_f
        + cfg.pw_crit * target_crit_f
        + cfg.pw_weight * (1.0 - weight_norm)
    )

    return ScoredPath(
        entry_label=INTERNET if node_path[0] == INTERNET else engine.nodes[node_path[0]].label,
        target_asset_id=target.id,
        hop_count=len(node_path) - 1,
        path_risk=round(_clamp(path_risk, 0.0, 100.0), 3),
        likelihood=round(likelihood, 3),
        total_weight=round(_total_weight(engine, node_path), 3),
        steps=steps,
        node_ids=list(node_path),
        edge_pairs=edge_pairs,
    )


def enumerate_paths(engine: Engine) -> list[ScoredPath]:
    """Top-K ranked attack paths from INTERNET to crown jewels, bounded."""
    cfg = engine.config
    g = engine.graph
    if INTERNET not in g:
        return []

    targets = find_targets(engine)
    raw_paths: list[list[str]] = []

    for target in targets:
        if target == INTERNET or not nx.has_path(g, INTERNET, target):
            continue
        try:
            gen = nx.shortest_simple_paths(g, INTERNET, target, weight="weight")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        taken = 0
        examined = 0
        for node_path in gen:
            examined += 1
            if examined > MAX_CANDIDATES_PER_TARGET:
                break
            if len(node_path) - 1 > cfg.max_hops:
                # shortest_simple_paths yields by weight, not length; a long path
                # here can still precede shorter ones, so skip rather than break.
                continue
            raw_paths.append(node_path)
            taken += 1
            if taken >= cfg.paths_per_target:
                break

    if not raw_paths:
        return []

    weights = [_total_weight(engine, p) for p in raw_paths]
    scored = [
        _score_path(engine, p, _normalize_weight(w, weights))
        for p, w in zip(raw_paths, weights)
    ]
    # rank by path_risk desc; deterministic tie-break by (hop_count, target id)
    scored.sort(key=lambda s: (-s.path_risk, s.hop_count, s.target_asset_id))
    return scored[: cfg.top_k]


def blast_radius_value(engine: Engine, node_id: str, blast: set[str]) -> float:
    total = 0.0
    for nid in blast:
        node: NodeData | None = engine.nodes.get(nid)
        if node:
            total += max(0.0, float(node.business_value))
    return round(total, 2)
