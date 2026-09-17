# Drishti v0.1 — tenant organization model | 11-Jul-2026
"""Tenant root aggregate: organizations, users, agents."""
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import ts_col, utcnow, uuid_fk, uuid_pk


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    created_at: Mapped[datetime] = ts_col()
    updated_at: Mapped[datetime] = ts_col(onupdate=utcnow)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('admin','analyst','viewer')"),)

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="analyst")
    # Nullable (not NOT-NULL-with-default) so reconcile_columns.py can ALTER it
    # onto a live table — a plain column default has no DDL DEFAULT clause, so
    # existing rows would fail a NOT NULL backfill. Treat NULL as 0 in code.
    # Bumped on password change; embedded in issued JWTs so old tokens can be
    # told apart from current ones (see core/security.py, api/auth.py refresh).
    token_version: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    created_at: Mapped[datetime] = ts_col()
    updated_at: Mapped[datetime] = ts_col(onupdate=utcnow)


class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint("org_id", "agent_key"),
        CheckConstraint("status IN ('active','disabled')"),
    )

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    agent_key: Mapped[str] = mapped_column(String(64))
    token_hash: Mapped[str] = mapped_column(String(255))
    label: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = ts_col()
