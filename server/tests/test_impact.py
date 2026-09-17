# Drishti v0.1 — dollar model monotonicity tests | 11-Jul-2026
"""Dollar model monotonicity + safety (TESTING.md §3.5)."""

from app.services.attack_paths import ScoredPath
from app.services.impact import path_impact_usd, total_exposure, id_key
from app.services.risk_engine import NodeData, build_engine


def _engine_with_target(value, asset_type="database"):
    target = NodeData(
        id="t",
        label="t",
        asset_type=asset_type,
        zone="z",
        zone_kind="crown_jewel",
        criticality="critical",
        business_value=value,
        internet_facing=False,
        open_findings=1,
        max_exploitability=0.7,
        max_cvss=8.0,
    )
    return build_engine([target], [])


def _path(likelihood, target_id="t"):
    return ScoredPath(
        entry_label="INTERNET",
        target_asset_id=target_id,
        hop_count=2,
        path_risk=50.0,
        likelihood=likelihood,
        total_weight=1.0,
        node_ids=["INTERNET", target_id],
    )


def test_impact_monotonic_in_likelihood():
    engine = _engine_with_target(1_000_000)
    low = path_impact_usd(engine, _path(0.1), breach_cost_base=100_000)
    high = path_impact_usd(engine, _path(0.9), breach_cost_base=100_000)
    assert high > low


def test_impact_monotonic_in_value():
    small = path_impact_usd(_engine_with_target(100_000), _path(0.5), breach_cost_base=0)
    big = path_impact_usd(_engine_with_target(5_000_000), _path(0.5), breach_cost_base=0)
    assert big > small


def test_impact_non_negative():
    engine = _engine_with_target(0)
    assert path_impact_usd(engine, _path(0.0), breach_cost_base=0) >= 0.0


def test_total_exposure_dedupes_targets():
    engine = _engine_with_target(1_000_000)
    p1 = _path(0.3)
    p2 = _path(0.7)  # same target, higher impact
    impacts = {id_key(p1): path_impact_usd(engine, p1), id_key(p2): path_impact_usd(engine, p2)}
    total = total_exposure([p1, p2], impacts)
    # only the max path per target counts
    assert total == max(impacts.values())
