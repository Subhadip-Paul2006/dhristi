# Drishti v0.1 — blast radius computation tests | 11-Jul-2026
"""Blast radius = descendants in the directed graph (TESTING.md §3.4)."""
from app.services.attack_paths import blast_radius_value
from app.services.risk_engine import INTERNET, EdgeData, NodeData, blast_radius, build_engine


def _n(nid, exposed=False):
    return NodeData(
        id=nid,
        label=nid,
        asset_type="server",
        zone="z",
        zone_kind="internal",
        criticality="medium",
        business_value=100_000,
        internet_facing=exposed,
        open_findings=0,
        max_exploitability=0.5,
        max_cvss=6.0,
    )


def _tiny():
    # a → b → c ; a → d ; e isolated
    nodes = [_n("a", exposed=True), _n("b"), _n("c"), _n("d"), _n("e")]
    edges = [
        EdgeData("a", "b", "network"),
        EdgeData("b", "c", "network"),
        EdgeData("a", "d", "network"),
    ]
    return build_engine(nodes, edges)


def test_descendants_match_hand_computed():
    engine = _tiny()
    assert blast_radius(engine, "a") == {"b", "c", "d"}
    assert blast_radius(engine, "b") == {"c"}


def test_leaf_node_empty_blast():
    engine = _tiny()
    assert blast_radius(engine, "c") == set()
    assert blast_radius(engine, "e") == set()


def test_internet_injected():
    engine = _tiny()
    # INTERNET → a (exposed); blast from INTERNET reaches the entry + downstream
    assert "a" in blast_radius(engine, INTERNET)
    assert blast_radius(engine, INTERNET) == {"a", "b", "c", "d"}


def test_blast_radius_value_floors_negative_business_value():
    engine = _tiny()
    engine.nodes["b"] = NodeData(
        id="b",
        label="b",
        asset_type="server",
        zone="z",
        zone_kind="internal",
        criticality="medium",
        business_value=-5_000_000,
        internet_facing=False,
        open_findings=0,
        max_exploitability=0.5,
        max_cvss=6.0,
    )
    blast = blast_radius(engine, "a")
    value = blast_radius_value(engine, "a", blast)
    assert value == 200_000.0
    assert value >= 0.0


def test_blast_radius_count_cached(db_session, seed_acme_org):
    from sqlalchemy import select

    from app.models import Asset
    from app.services.recompute import recompute_org

    recompute_org(db_session, seed_acme_org.id)
    engine = load_from_db(db_session, seed_acme_org.id)
    for a in db_session.scalars(select(Asset).where(Asset.org_id == seed_acme_org.id)):
        expected = len(blast_radius(engine, a.id))
        assert a.blast_radius_count == expected


def load_from_db(db, org_id):
    from app.services.engine_loader import load_engine

    return load_engine(db, org_id)
