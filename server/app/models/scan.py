# Drishti v0.1 — scan session history model | 11-Jul-2026
"""Scan/ingest sessions (history + trend) and the future Web3 threat-intel stub."""
from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import ts_col, uuid_fk, uuid_pk


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (CheckConstraint("status IN ('running','complete','failed')"),)

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    agent_id: Mapped[str | None] = uuid_fk("agents.id", nullable=True)
    started_at: Mapped[datetime] = ts_col()
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)
    vuln_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="running")


class ThreatIntel(Base):
    """Future / Web3 vision (ROADMAP.md §7.2). Stubbed, not used in v1 flows."""

    __tablename__ = "threat_intel"
    __table_args__ = (CheckConstraint("source IN ('local','network')"),)

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str | None] = uuid_fk("organizations.id", nullable=True)
    indicator_hash: Mapped[str] = mapped_column(String(128))
    ttp_tags: Mapped[list | None] = mapped_column(JSON, nullable=True)
    shared_at: Mapped[datetime] = ts_col()
    source: Mapped[str] = mapped_column(String(20), default="local")
