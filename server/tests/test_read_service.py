# Drishti v0.1 — graph read service tests | 11-Jul-2026
"""build_graph is the primary demo screen (CLAUDE.md hero flow) — it must not
N+1 on cached AttackPath.steps when rendering top-path edges."""
from sqlalchemy import event

from app.services.read_service import build_graph


def test_build_graph_does_not_n_plus_one_on_path_steps(db_session, seed_acme_org):
    queries = []
    engine = db_session.get_bind()

    def _capture(conn, cursor, statement, parameters, context, executemany):
        queries.append(statement)

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        build_graph(db_session, seed_acme_org.id)
    finally:
        event.remove(engine, "before_cursor_execute", _capture)

    step_queries = [q for q in queries if "attack_path_steps" in q]
    assert len(step_queries) <= 1, (
        "expected a single batched (selectinload) query for AttackPath.steps, "
        f"got {len(step_queries)}: {step_queries}"
    )


def test_build_graph_top_edges_unaffected_by_eager_load(db_session, seed_acme_org):
    graph = build_graph(db_session, seed_acme_org.id)
    on_top = [e for e in graph.edges if e.data.on_top_path]
    assert on_top, "expected at least one edge flagged on_top_path"
    assert all(e.data.path_id for e in on_top)
