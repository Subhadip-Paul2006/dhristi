# Drishti v0.1 — attack path enumeration tests | 11-Jul-2026
"""Attack-path enumeration bounds + hero path (TESTING.md §3.3)."""
import time

from app.services.attack_paths import enumerate_paths
from app.services.engine_loader import load_engine
from app.services.risk_engine import EdgeData, NodeData, RiskConfig, build_engine


def _n(nid, **kw):
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
        max_exploitability=0.6,
        max_cvss=7.0,
    )
    base.update(kw)
    return NodeData(**base)


def test_hero_path_found(db_session, seed_acme_org):
    from app.services.recompute import recompute_org

    recompute_org(db_session, seed_acme_org.id)
    engine = load_engine(db_session, seed_acme_org.id)
    paths = enumerate_paths(engine)
    assert paths, "no paths enumerated"

    top = paths[0]
    labels = [engine.nodes[nid].label for nid in top.node_ids]
    assert labels == [
        "INTERNET",
        "web-app-01",
        "api-gw-01",
        "app-svc-01",
        "jump-01",
        "db-prod-01",
    ], labels


def test_max_hop_cap():
    nodes = [_n("entry", internet_facing=True)] + [_n(f"n{i}") for i in range(10)]
    edges = [EdgeData("entry", "n0", "network")]
    for i in range(9):
        edges.append(EdgeData(f"n{i}", f"n{i+1}", "network"))
    nodes[-1] = _n("n9", criticality="critical", business_value=5_000_000)
    engine = build_engine(nodes, edges, RiskConfig(max_hops=6))
    paths = enumerate_paths(engine)
    assert all(p.hop_count <= 6 for p in paths)


def test_top_k_cap():
    # dense: entry → 40 targets each critical
    nodes = [_n("entry", internet_facing=True)]
    edges = []
    for i in range(40):
        nodes.append(_n(f"t{i}", criticality="critical", business_value=1_000_000))
        edges.append(EdgeData("entry", f"t{i}", "network"))
    engine = build_engine(nodes, edges, RiskConfig(top_k=25))
    paths = enumerate_paths(engine)
    assert len(paths) <= 25


def test_no_unbounded_enumeration():
    # 30 fully-connected nodes: must complete fast and stay bounded
    nodes = [_n("entry", internet_facing=True)]
    for i in range(30):
        crit = "critical" if i == 29 else "medium"
        nodes.append(_n(f"n{i}", criticality=crit, business_value=1_000_000 if i == 29 else 50_000))
    edges = [EdgeData("entry", "n0", "network")]
    ids = [f"n{i}" for i in range(30)]
    for a in ids:
        for b in ids:
            if a != b:
                edges.append(EdgeData(a, b, "network"))
    engine = build_engine(nodes, edges, RiskConfig())
    start = time.perf_counter()
    paths = enumerate_paths(engine)
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, f"enumeration too slow: {elapsed:.2f}s"
    assert len(paths) <= 25
    assert all(p.hop_count <= 6 for p in paths)


def test_examined_candidates_capped_when_all_exceed_max_hops():
    # target only reachable via >=2 hops, but max_hops=1: every candidate that
    # shortest_simple_paths yields gets skipped, so `taken` never reaches
    # paths_per_target — must not enumerate the graph's full path space.
    mid = [f"m{i}" for i in range(12)]
    nodes = (
        [_n("entry", internet_facing=True)]
        + [_n(m) for m in mid]
        + [_n("target", criticality="critical", business_value=5_000_000)]
    )
    edges = [EdgeData("entry", m, "network") for m in mid]
    edges += [EdgeData(a, b, "network") for a in mid for b in mid if a != b]
    edges += [EdgeData(m, "target", "network") for m in mid]
    engine = build_engine(nodes, edges, RiskConfig(max_hops=1))

    start = time.perf_counter()
    paths = enumerate_paths(engine)
    elapsed = time.perf_counter() - start

    assert elapsed < 3.0, f"unbounded candidate examination: {elapsed:.2f}s"
    assert paths == []


def test_path_risk_ranking(db_session, seed_acme_org):
    engine = load_engine(db_session, seed_acme_org.id)
    paths = enumerate_paths(engine)
    risks = [p.path_risk for p in paths]
    assert risks == sorted(risks, reverse=True)
