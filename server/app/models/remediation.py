# Drishti v0.1 — AI-generated remediation records | 11-Jul-2026
"""AI-generated (or manual) fixes attached to a finding."""
from datetime import datetime
from decimal import Decimal

from sqlalchemy import JSON, Boolean, CheckConstraint, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import ts_col, uuid_fk, uuid_pk

REMEDIATION_KINDS = ("ansible", "shell", "cloud_cli", "manual")


class Remediation(Base):
    __tablename__ = "remediations"
    __table_args__ = (
        CheckConstraint("kind IN ('ansible','shell','cloud_cli','manual')"),
        CheckConstraint("generated_by IN ('ai','human')"),
    )

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    asset_vulnerability_id: Mapped[str] = uuid_fk(
        "asset_vulnerabilities.id", fk_kw={"ondelete": "CASCADE"}, index=True
    )
    kind: Mapped[str] = mapped_column(String(20), default="ansible")
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(Text, default="")
    script: Mapped[str] = mapped_column(Text, default="")
    risk_reduction: Mapped[Decimal | None] = mapped_column(Numeric(5, 2), nullable=True)
    generated_by: Mapped[str] = mapped_column(String(20), default="ai")
    model: Mapped[str | None] = mapped_column(String(60), nullable=True)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    # steps / requires_restart / disclaimer — so a cache hit reconstructs the
    # exact same response shape as the first (uncached) generation.
    details_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = ts_col()
