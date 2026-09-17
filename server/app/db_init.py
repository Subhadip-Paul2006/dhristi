# Drishti v0.1 — schema bootstrap and migration | 11-Jul-2026
"""Create tables (and wait for the DB in Docker). Run as `python -m app.db_init`.

The project uses `create_all` rather than Alembic (see DATABASE.md §7 — a known
gap). `create_all` creates missing *tables* but never alters existing ones, so
an additive column added to a model would 500 on any pre-existing dev DB or
Docker volume. `reconcile_columns` closes that gap for the additive case: it
ALTERs in any mapped column that's missing from a live table, as long as the
column is safe to add to populated rows (nullable, or has a default). This is
not a migration system — it only ever adds columns; it never drops, renames, or
retypes. Destructive schema changes still require recreating the DB.
"""
import logging
import time

from sqlalchemy import bindparam, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.schema import Column, CreateColumn

from app.db import Base, engine

logger = logging.getLogger("drishti")


class SchemaReconcileError(RuntimeError):
    """Raised when reconcile_columns cannot safely evolve the live schema."""


def _client_default_value(column: Column):
    default = column.default
    if default is None:
        return None
    if getattr(default, "is_scalar", False):
        return default.arg
    if getattr(default, "is_callable", False):
        return default.arg(None)  # SQLAlchemy always wraps callables to take a context arg
    raise SchemaReconcileError(
        f"column {column.table.name}.{column.name} has an unsupported "
        "client-side default and cannot be safely backfilled"
    )


def reconcile_columns(bound_engine: Engine) -> None:
    """Add any mapped columns missing from existing tables (additive only)."""
    inspector = inspect(bound_engine)
    existing_tables = set(inspector.get_table_names())

    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue  # create_all handles brand-new tables
        live_cols = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in live_cols:
                continue
            # Only safe to backfill a column onto existing rows when it can be
            # NULL or carries a default. NOT NULL without a default would fail.
            has_default = column.default is not None or column.server_default is not None
            if not (column.nullable or has_default):
                logger.warning(
                    "skipping non-nullable column %s.%s with no default — "
                    "recreate the DB to pick it up",
                    table.name,
                    column.name,
                )
                continue
            # A client-side (Python) default is never emitted into the ALTER
            # TABLE DDL — only server_default is. Adding straight to NOT NULL
            # would fail on any table with existing rows, so: add the column
            # nullable, backfill existing rows via UPDATE, then (where the
            # dialect supports it — not sqlite) tighten it to NOT NULL.
            needs_backfill = (
                not column.nullable
                and column.server_default is None
                and column.default is not None
            )
            default_value = _client_default_value(column) if needs_backfill else None
            ddl = str(CreateColumn(column).compile(dialect=bound_engine.dialect))
            if needs_backfill:
                ddl = ddl.replace(" NOT NULL", "")
            try:
                with bound_engine.begin() as conn:
                    conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN {ddl}'))
                    if needs_backfill:
                        conn.execute(
                            text(f'UPDATE "{table.name}" SET "{column.name}" = :value').bindparams(
                                bindparam("value", type_=column.type)
                            ),
                            {"value": default_value},
                        )
                        if bound_engine.dialect.name != "sqlite":
                            conn.execute(
                                text(
                                    f'ALTER TABLE "{table.name}" '
                                    f'ALTER COLUMN "{column.name}" SET NOT NULL'
                                )
                            )
            except Exception as exc:
                logger.error(
                    "reconcile: failed adding column %s.%s",
                    table.name,
                    column.name,
                    exc_info=True,
                )
                raise SchemaReconcileError(
                    f"failed to reconcile column {table.name}.{column.name}"
                ) from exc
            logger.info(
                "reconcile: added column %s.%s", table.name, column.name
            )


def init(retries: int = 20, delay: float = 1.0) -> None:
    import app.models  # noqa: F401  (register all mappers)

    for attempt in range(retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            break
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(delay)
    Base.metadata.create_all(engine)
    reconcile_columns(engine)


if __name__ == "__main__":
    init()
    print("database ready")
