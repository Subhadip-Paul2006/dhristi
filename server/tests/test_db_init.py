# Drishti v0.1 — schema reconciliation tests | 11-Jul-2026
"""reconcile_columns: additive NOT NULL columns must backfill, not 500 (see
db_init.py module docstring + CLAUDE.md AI layer / schema-safety notes)."""
import pytest
from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, create_engine, func, text

import app.db_init as db_init


def _fake_base(metadata):
    return type("FakeBase", (), {"metadata": metadata})


def test_reconcile_backfills_not_null_client_default(monkeypatch):
    meta = MetaData()
    Table(
        "widgets",
        meta,
        Column("id", Integer, primary_key=True),
        Column("kind", String(20), nullable=False, default="basic"),
    )

    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE widgets (id INTEGER PRIMARY KEY)"))
        conn.execute(text("INSERT INTO widgets (id) VALUES (1)"))
        conn.execute(text("INSERT INTO widgets (id) VALUES (2)"))

    monkeypatch.setattr(db_init, "Base", _fake_base(meta))

    db_init.reconcile_columns(engine)

    with engine.connect() as conn:
        rows = conn.execute(text("SELECT id, kind FROM widgets ORDER BY id")).all()
    assert rows == [(1, "basic"), (2, "basic")]


def test_reconcile_skips_set_not_null_on_sqlite(monkeypatch):
    """sqlite can't ALTER COLUMN SET NOT NULL, so the backfilled column stays
    nullable there — the important thing is that it doesn't raise."""
    meta = MetaData()
    Table(
        "gadgets",
        meta,
        Column("id", Integer, primary_key=True),
        Column("count", Integer, nullable=False, default=0),
    )

    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE gadgets (id INTEGER PRIMARY KEY)"))
        conn.execute(text("INSERT INTO gadgets (id) VALUES (1)"))

    monkeypatch.setattr(db_init, "Base", _fake_base(meta))
    db_init.reconcile_columns(engine)

    with engine.connect() as conn:
        row = conn.execute(text("SELECT count FROM gadgets WHERE id = 1")).one()
    assert row.count == 0


def test_reconcile_wraps_db_errors_as_schema_reconcile_error(monkeypatch):
    meta = MetaData()
    Table(
        "broken",
        meta,
        Column("id", Integer, primary_key=True),
        Column("count", Integer, nullable=False, default=lambda: object()),
    )

    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE broken (id INTEGER PRIMARY KEY)"))
        conn.execute(text("INSERT INTO broken (id) VALUES (1)"))

    monkeypatch.setattr(db_init, "Base", _fake_base(meta))

    with pytest.raises(db_init.SchemaReconcileError):
        db_init.reconcile_columns(engine)


def test_client_default_value_rejects_unsupported_default():
    meta = MetaData()
    table = Table(
        "t",
        meta,
        Column("id", Integer, primary_key=True),
        Column("ts", DateTime, default=func.now()),
    )
    with pytest.raises(db_init.SchemaReconcileError):
        db_init._client_default_value(table.c.ts)
