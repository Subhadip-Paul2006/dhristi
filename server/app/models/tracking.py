# Drishti v0.1 — per-device live network traffic tracking session model | Phase 01
from __future__ import annotations

from datetime import datetime
from sqlalchemy import BigInteger, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import ts_col, utcnow, uuid_fk, uuid_pk


class LiveTrackingSession(Base):
    """Represents an active or historical per-device live network traffic tracking session.

    Enforces strict device isolation: each session tracks exactly one target device
    identified by (org_id, device_id, target_ip). Never pools cross-device flows.
    """

    __tablename__ = "live_tracking_sessions"

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    device_id: Mapped[str] = mapped_column(String(64), index=True)
    target_ip: Mapped[str] = mapped_column(String(45), index=True)
    target_mac: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Status: STARTING | LIVE | STOPPED | ERROR | UNAVAILABLE
    status: Mapped[str] = mapped_column(String(24), default="STARTING")
    # Capture source: MONITORED INTERFACE | ENDPOINT AGENT | SCAPY | UNAVAILABLE
    capture_source: Mapped[str] = mapped_column(String(32), default="SCAPY")
    status_message: Mapped[str | None] = mapped_column(String(255), nullable=True)

    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    flow_count: Mapped[int] = mapped_column(Integer, default=0)
    byte_count: Mapped[int] = mapped_column(BigInteger, default=0)

    started_at: Mapped[datetime] = ts_col()
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
