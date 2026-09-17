# Drishti v0.1 — recompute advisory lock tests | 11-Jul-2026
"""recompute_org per-org advisory lock guard (BACKEND.md §8)."""
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.services.recompute import recompute_org
from app.services.risk_engine import NodeData, build_engine


def _n(nid):
    return NodeData(
        id=nid,
        label=nid,
        asset_type="server",
        zone="z",
        zone_kind="internal",
        criticality="medium",
        business_value=100_000,
        internet_facing=False,
        open_findings=0,
        max_exploitability=0.3,
        max_cvss=5.0,
    )


def _mock_db(dialect_name):
    db = MagicMock()
    db.bind = SimpleNamespace(dialect=SimpleNamespace(name=dialect_name))
    db.scalars.return_value.all.return_value = []
    return db


def _lock_calls(db):
    return [
        call for call in db.execute.call_args_list
        if "pg_advisory_xact_lock" in str(call.args[0])
    ]


def test_advisory_lock_taken_for_postgres(monkeypatch):
    engine = build_engine([_n("a")], [])
    monkeypatch.setattr("app.services.recompute.load_engine", lambda db, org_id: engine)

    db = _mock_db("postgresql")
    recompute_org(db, "org-1")

    calls = _lock_calls(db)
    assert len(calls) == 1
    assert calls[0].args[1] == {"oid": "org-1"}


def test_advisory_lock_skipped_for_sqlite(monkeypatch):
    engine = build_engine([_n("a")], [])
    monkeypatch.setattr("app.services.recompute.load_engine", lambda db, org_id: engine)

    db = _mock_db("sqlite")
    recompute_org(db, "org-1")

    assert _lock_calls(db) == []
