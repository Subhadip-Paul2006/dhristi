# Drishti v0.1 — Endpoint Agent & Pairing Models | Phase 01
from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import CheckConstraint, DateTime, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import ts_col, utcnow, uuid_fk, uuid_pk

ONLINE_THRESHOLD_SECONDS = 60
STALE_THRESHOLD_SECONDS = 180


class EndpointAgent(Base):
    """An authorized endpoint device running the Drishti Endpoint Agent."""

    __tablename__ = "endpoint_agents"
    __table_args__ = (
        UniqueConstraint("org_id", "agent_id", name="uq_endpoint_agent_org_agent"),
        CheckConstraint("status IN ('ONLINE','STALE','OFFLINE','UNPAIRED','REVOKED')", name="ck_endpoint_agent_status"),
    )

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    device_id: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    os: Mapped[str] = mapped_column(String(50))
    os_version: Mapped[str] = mapped_column(String(100))
    mac: Mapped[str | None] = mapped_column(String(32), nullable=True)
    current_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(50), default="0.1.0")
    status: Mapped[str] = mapped_column(String(20), default="ONLINE")
    agent_token_hash: Mapped[str] = mapped_column(String(255), index=True)
    paired_at: Mapped[datetime] = ts_col()
    registered_at: Mapped[datetime] = ts_col()
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = ts_col()
    updated_at: Mapped[datetime] = ts_col(onupdate=utcnow)

    def calculate_status(self, now: datetime | None = None) -> str:
        """Derive authoritative live status from actual last heartbeat."""
        if not self.last_heartbeat:
            return "OFFLINE"
        current_time = now or datetime.now(timezone.utc)
        if self.last_heartbeat.tzinfo is None:
            hb = self.last_heartbeat.replace(tzinfo=timezone.utc)
        else:
            hb = self.last_heartbeat
        diff = (current_time - hb).total_seconds()
        if diff <= ONLINE_THRESHOLD_SECONDS:
            return "ONLINE"
        if diff <= STALE_THRESHOLD_SECONDS:
            return "STALE"
        return "OFFLINE"


class EndpointPairingSession(Base):
    """Temporary one-time session for pairing an Endpoint Agent with an Organization."""

    __tablename__ = "endpoint_pairing_sessions"
    __table_args__ = (
        Index("ix_endpoint_pairing_code_hash", "pairing_code_hash"),
    )

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    pairing_code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    os: Mapped[str] = mapped_column(String(50), nullable=False)
    os_version: Mapped[str] = mapped_column(String(100), nullable=False)
    mac: Mapped[str | None] = mapped_column(String(32), nullable=True)
    current_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(50), default="0.1.0")
    status: Mapped[str] = mapped_column(String(20), default="WAITING_FOR_PAIR")  # WAITING_FOR_PAIR, PAIRED, CONSUMED, EXPIRED, REJECTED
    agent_token: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = ts_col()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def is_expired(self, now: datetime | None = None) -> bool:
        current_time = now or datetime.now(timezone.utc)
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return current_time > exp
