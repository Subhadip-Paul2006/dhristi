# Drishti v0.1 — vulnerability catalog model | 11-Jul-2026
"""Vulnerability catalog + per-asset findings."""
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.base import ts_col, uuid_fk, uuid_pk

SEVERITIES = ("low", "medium", "high", "critical")
FINDING_STATUSES = ("open", "remediating", "resolved", "accepted")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (CheckConstraint("severity IN ('low','medium','high','critical')"),)

    id: Mapped[str] = uuid_pk()
    cve_id: Mapped[str | None] = mapped_column(String(30), nullable=True, unique=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss: Mapped[Decimal] = mapped_column(Numeric(3, 1), default=Decimal("5.0"))
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    exploitability: Mapped[Decimal] = mapped_column(Numeric(3, 2), default=Decimal("0.30"))
    cwe: Mapped[str | None] = mapped_column(String(30), nullable=True)

    findings: Mapped[list["AssetVulnerability"]] = relationship(back_populates="vulnerability")


class AssetVulnerability(Base):
    """A finding: this asset is affected by this vulnerability."""

    __tablename__ = "asset_vulnerabilities"
    __table_args__ = (
        UniqueConstraint("asset_id", "vulnerability_id"),
        CheckConstraint("status IN ('open','remediating','resolved','accepted')"),
        Index("ix_findings_org_status", "org_id", "status"),
    )

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    asset_id: Mapped[str] = uuid_fk("assets.id", fk_kw={"ondelete": "CASCADE"}, index=True)
    vulnerability_id: Mapped[str] = uuid_fk("vulnerabilities.id", index=True)
    service_id: Mapped[str | None] = uuid_fk(
        "services.id", fk_kw={"ondelete": "SET NULL"}, nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), default="open")
    detected_at: Mapped[datetime] = ts_col()
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="findings")  # noqa: F821
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="findings")
