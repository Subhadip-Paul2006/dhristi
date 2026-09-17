# Drishti v0.1 — attack path persistence model | 11-Jul-2026
"""Cached engine output: ranked attack paths + ordered steps."""
from datetime import datetime
from decimal import Decimal

from sqlalchemy import Index, Integer, Numeric, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.base import ts_col, uuid_fk, uuid_pk


class AttackPath(Base):
    __tablename__ = "attack_paths"
    __table_args__ = (Index("ix_paths_org_risk", "org_id", "path_risk"),)

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    entry_label: Mapped[str] = mapped_column(String(120), default="INTERNET")
    target_asset_id: Mapped[str] = uuid_fk("assets.id", fk_kw={"ondelete": "CASCADE"})
    hop_count: Mapped[int] = mapped_column(Integer)
    path_risk: Mapped[Decimal] = mapped_column(Numeric(6, 3))
    likelihood: Mapped[Decimal] = mapped_column(Numeric(4, 3))
    impact_usd: Mapped[Decimal] = mapped_column(Numeric(14, 2), default=Decimal("0"))
    narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    computed_at: Mapped[datetime] = ts_col()

    steps: Mapped[list["AttackPathStep"]] = relationship(
        back_populates="path", cascade="all, delete-orphan", order_by="AttackPathStep.step_index"
    )


class AttackPathStep(Base):
    __tablename__ = "attack_path_steps"
    __table_args__ = (UniqueConstraint("path_id", "step_index"),)

    id: Mapped[str] = uuid_pk()
    path_id: Mapped[str] = uuid_fk("attack_paths.id", fk_kw={"ondelete": "CASCADE"}, index=True)
    step_index: Mapped[int] = mapped_column(Integer)
    asset_id: Mapped[str] = uuid_fk("assets.id", fk_kw={"ondelete": "CASCADE"})
    via_vulnerability_id: Mapped[str | None] = uuid_fk("vulnerabilities.id", nullable=True)
    edge_weight: Mapped[Decimal | None] = mapped_column(Numeric(6, 3), nullable=True)

    path: Mapped[AttackPath] = relationship(back_populates="steps")
