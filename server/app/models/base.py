# Drishti v0.1 — shared column mixins | 11-Jul-2026
"""Shared column helpers. UUIDs stored as 36-char strings (Postgres + SQLite portable)."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String
from sqlalchemy.orm import mapped_column


def uuid_pk():
    return mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))


def uuid_fk(target: str, **kw):
    from sqlalchemy import ForeignKey

    return mapped_column(String(36), ForeignKey(target, **kw.pop("fk_kw", {})), **kw)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ts_col(**kw):
    return mapped_column(DateTime(timezone=True), default=utcnow, **kw)
