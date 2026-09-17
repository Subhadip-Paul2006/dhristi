# Drishti v0.1 — risk intelligence scoring engine | 11-Jul-2026
"""Risk Intelligence Engine — graph construction, edge weights, node risk scores.

All formulas live here with coefficients in one RiskConfig so the demo can
explain them in a sentence (BACKEND.md §5). Pure functions over a NetworkX
DiGraph; no HTTP, no ORM writes (recompute.py persists results).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

INTERNET = "INTERNET"

CRIT_FACTOR = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
RELATION_BASE = {"exposure": 0.1, "network": 0.2, "trust": 0.25, "admin": 0.15}
# Minimum per-hop ease from the relationship alone: once an attacker has a
# foothold, moving over a link has a baseline traversal ease even without a
# fresh vulnerability. Blended as max(node_ease, relation_ease). These floors
# sit *below* a typical vuln-driven node ease so a present vulnerability
# dominates — and resolving it drops the hop back to the floor, which is what
# makes "mark resolved → exposure drops" work on the demo.
RELATION_EASE = {"exposure": 0.5, "network": 0.4, "trust": 0.45, "admin": 0.5}
IMPACT_MULTIPLIER = {
    "database": 1.0,
    "webapp": 0.7,
    "server": 0.6,
    "workstation": 0.3,
    "firewall": 0.5,
    "router": 0.5,
    "iot": 0.4,
    "cloud": 0.8,
}


@dataclass
class RiskConfig:
    # node risk weights (sum = 1.0)
    w_exploit: float = 0.30
    w_reachability: float = 0.25
    w_centrality: float = 0.20
    w_value: float = 0.15
    w_crit: float = 0.10
    # path risk weights (sum = 1.0)
    pw_likelihood: float = 0.45
    pw_value: float = 0.30
    pw_crit: float = 0.15
    pw_weight: float = 0.10
    # enumeration bounds
    max_hops: int = 6
    paths_per_target: int = 5
    top_k: int = 25
    # edge-ease blend
    ease_exploit: float = 0.6
    ease_severity: float = 0.4


@dataclass
class NodeData:
    id: str
    label: str
    asset_type: str
    zone: str | None
    zone_kind: str | None
    criticality: str
    business_value: float
    internet_facing: bool
    open_findings: int
    # most exploitable open finding on this node (for edge weight + risk)
    max_exploitability: float = 0.1
    max_cvss: float = 1.0
    top_finding_vuln_id: str | None = None


@dataclass
class EdgeData:
    source: str
    target: str
    relation: str
    weight: float = 0.0
    via_vuln_id: str | None = None


@dataclass
class Engine:
    graph: nx.DiGraph
    nodes: dict[str, NodeData]
    edges: dict[tuple[str, str], EdgeData]
    config: RiskConfig = field(default_factory=RiskConfig)
    _value_min: float = 0.0
    _value_max: float = 1.0


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def ease_of_compromise(node: NodeData, cfg: RiskConfig) -> float:
    """0..1, higher = easier to exploit (BACKEND.md §5.2)."""
    dest_exploit = node.max_exploitability
    dest_sev = node.max_cvss / 10.0
    return _clamp(cfg.ease_exploit * dest_exploit + cfg.ease_severity * dest_sev)


def hop_ease(engine: "Engine", u: str, v: str) -> float:
    """Per-hop traversal ease for likelihood: exploit the destination OR abuse
    the relationship (trust/admin) — whichever is easier."""
    node_ease = ease_of_compromise(engine.nodes[v], engine.config)
    edge = engine.edges.get((u, v))
    relation_ease = RELATION_EASE.get(edge.relation, 0.4) if edge else 0.4
    return _clamp(max(node_ease, relation_ease))


def build_engine(
    nodes: list[NodeData],
    edges: list[EdgeData],
    config: RiskConfig | None = None,
) -> Engine:
    cfg = config or RiskConfig()
    g = nx.DiGraph()
    node_map = {n.id: n for n in nodes}

    # Synthetic INTERNET entry node (BACKEND.md §5.1 step 3).
    g.add_node(INTERNET)
    internet_node = NodeData(
        id=INTERNET,
        label=INTERNET,
        asset_type="cloud",
        zone="Internet",
        zone_kind=None,
        criticality="low",
        business_value=0.0,
        internet_facing=True,
        open_findings=0,
    )
    node_map[INTERNET] = internet_node

    for n in nodes:
        g.add_node(n.id)

    edge_map: dict[tuple[str, str], EdgeData] = {}

    # exposure edges from INTERNET to internet-facing assets
    for n in nodes:
        if n.internet_facing:
            e = EdgeData(source=INTERNET, target=n.id, relation="exposure")
            edge_map[(INTERNET, n.id)] = e
            g.add_edge(INTERNET, n.id)

    for e in edges:
        if e.source not in node_map or e.target not in node_map:
            continue
        edge_map[(e.source, e.target)] = e
        g.add_edge(e.source, e.target)

    # normalize business value across real assets (0..1)
    values = [n.business_value for n in nodes] or [0.0]
    vmin, vmax = min(values), max(values)

    engine = Engine(
        graph=g,
        nodes=node_map,
        edges=edge_map,
        config=cfg,
        _value_min=vmin,
        _value_max=vmax,
    )
    _compute_edge_weights(engine)
    return engine


def _compute_edge_weights(engine: Engine) -> None:
    cfg = engine.config
    for (u, v), edge in engine.edges.items():
        dest = engine.nodes[v]
        ease = ease_of_compromise(dest, cfg)
        base = RELATION_BASE.get(edge.relation, 0.2)
        edge.weight = round(base + (1.0 - ease), 3)
        edge.via_vuln_id = dest.top_finding_vuln_id
        engine.graph[u][v]["weight"] = edge.weight
        engine.graph[u][v]["relation"] = edge.relation


def value_factor(engine: Engine, node: NodeData) -> float:
    if engine._value_max <= engine._value_min:
        return 0.0
    return _clamp(
        (node.business_value - engine._value_min) / (engine._value_max - engine._value_min)
    )


def reachability_factor(engine: Engine, node_id: str, shortest: dict[str, float]) -> float:
    """1.0 if reachable from INTERNET; else decays with shortest-path weight."""
    if node_id == INTERNET:
        return 0.0
    dist = shortest.get(node_id)
    if dist is None:
        return 0.0  # unreachable from the internet
    # nearer to the internet (smaller weight) → closer to 1.0
    return _clamp(1.0 / (1.0 + dist))


def compute_node_scores(engine: Engine) -> dict[str, float]:
    """Return {asset_id: risk_score 0..100} for real assets (excludes INTERNET)."""
    cfg = engine.config
    g = engine.graph

    try:
        shortest = nx.single_source_dijkstra_path_length(g, INTERNET, weight="weight")
    except nx.NodeNotFound:
        shortest = {}

    # betweenness centrality on the whole directed graph (0..1 already)
    if g.number_of_nodes() > 2:
        centrality = nx.betweenness_centrality(g, weight="weight", normalized=True)
    else:
        centrality = {n: 0.0 for n in g.nodes}
    cmax = max(centrality.values()) if centrality else 0.0

    scores: dict[str, float] = {}
    for node_id, node in engine.nodes.items():
        if node_id == INTERNET:
            continue
        exploit = ease_of_compromise(node, cfg)
        # A path from INTERNET means the node is reachable; blend the distance
        # decay for nuance but floor reachable nodes at 0.5 (BACKEND.md §5.3).
        reach = reachability_factor(engine, node_id, shortest)
        if node_id in shortest:
            reach = max(reach, 0.5)
        cent = (centrality.get(node_id, 0.0) / cmax) if cmax > 0 else 0.0
        val = value_factor(engine, node)
        crit = CRIT_FACTOR.get(node.criticality, 0.5)

        risk = 100.0 * (
            cfg.w_exploit * exploit
            + cfg.w_reachability * reach
            + cfg.w_centrality * cent
            + cfg.w_value * val
            + cfg.w_crit * crit
        )
        scores[node_id] = round(_clamp(risk, 0.0, 100.0), 3)
    return scores


def blast_radius(engine: Engine, node_id: str) -> set[str]:
    """All assets reachable if node_id is compromised (BACKEND.md §5.6)."""
    if node_id not in engine.graph:
        return set()
    reachable = nx.descendants(engine.graph, node_id)
    reachable.discard(INTERNET)
    return reachable
