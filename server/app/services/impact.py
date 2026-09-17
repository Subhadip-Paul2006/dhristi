# Drishti v0.1 — business impact dollar model | 11-Jul-2026
"""Business-impact ($) model (BACKEND.md §7.1). Transparent, one-sentence-explainable.

    impact = likelihood * asset_value * impact_multiplier + likelihood * breach_cost_base
"""
from __future__ import annotations

from app.config import get_settings
from app.services.attack_paths import ScoredPath
from app.services.risk_engine import IMPACT_MULTIPLIER, Engine


def path_impact_usd(engine: Engine, path: ScoredPath, breach_cost_base: float | None = None) -> float:
    if breach_cost_base is None:
        breach_cost_base = get_settings().breach_cost_base
    target = engine.nodes[path.target_asset_id]
    asset_value = max(0.0, float(target.business_value))
    likelihood = max(0.0, min(1.0, path.likelihood))
    multiplier = IMPACT_MULTIPLIER.get(target.asset_type, 0.5)
    impact = likelihood * asset_value * multiplier + likelihood * breach_cost_base
    return round(max(0.0, impact), 2)


def total_exposure(paths: list[ScoredPath], impacts: dict[str, float]) -> float:
    """Sum over top paths, deduped to the max path per unique target."""
    best_per_target: dict[str, float] = {}
    for p in paths:
        val = impacts.get(id_key(p), 0.0)
        if val > best_per_target.get(p.target_asset_id, 0.0):
            best_per_target[p.target_asset_id] = val
    return round(sum(best_per_target.values()), 2)


def id_key(path: ScoredPath) -> str:
    """Stable per-path key (entry→…→target with hop count) for impact lookup."""
    return f"{path.target_asset_id}:{path.hop_count}:{'>'.join(path.node_ids)}"
