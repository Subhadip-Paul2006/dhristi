# Drishti v0.1 — risk scoring model tests | 11-Jul-2026
"""Risk model (TESTING.md §3.2). The product thesis must hold."""
from app.services.risk_engine import EdgeData, NodeData, build_engine, compute_node_scores


def _node(nid, **kw):
    base = dict(
        id=nid,
        label=nid,
        asset_type="server",
        zone="z",
        zone_kind="internal",
        criticality="medium",
        business_value=100_000,
        internet_facing=False,
        open_findings=1,
        max_exploitability=0.5,
        max_cvss=6.0,
        top_finding_vuln_id=None,
    )
    base.update(kw)
    return NodeData(**base)


def test_reachable_valuable_outranks_isolated_critical():
    """A medium-CVSS, internet-reachable, high-value node beats an isolated
    critical-CVSS node. This is the product thesis."""
    reachable = _node(
        "reachable",
        asset_type="database",
        criticality="high",
        business_value=3_000_000,
        internet_facing=True,
        max_exploitability=0.5,
        max_cvss=5.5,
    )
    isolated = _node(
        "isolated",
        criticality="critical",
        business_value=50_000,
        internet_facing=False,
        max_exploitability=0.9,
        max_cvss=9.8,
    )
    engine = build_engine([reachable, isolated], [])
    scores = compute_node_scores(engine)
    assert scores["reachable"] > scores["isolated"]


def test_risk_score_bounds():
    nodes = [_node(f"n{i}", business_value=10_000 * (i + 1)) for i in range(5)]
    engine = build_engine(nodes, [EdgeData("n0", "n1", "network")])
    scores = compute_node_scores(engine)
    assert all(0.0 <= s <= 100.0 for s in scores.values())


def test_score_monotonic_in_exploitability():
    low = _node("t", max_exploitability=0.2, max_cvss=6.0, internet_facing=True)
    high = _node("t", max_exploitability=0.9, max_cvss=6.0, internet_facing=True)
    s_low = compute_node_scores(build_engine([low], []))["t"]
    s_high = compute_node_scores(build_engine([high], []))["t"]
    assert s_high > s_low


def test_isolated_node_low_reachability():
    exposed = _node("exposed", internet_facing=True)
    isolated = _node("isolated", internet_facing=False)
    engine = build_engine([exposed, isolated], [])  # no edges to isolated
    scores = compute_node_scores(engine)
    # isolated has no path from INTERNET → lower reachability contribution
    assert scores["exposed"] > scores["isolated"]
