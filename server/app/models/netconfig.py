# Drishti v0.1 — network-config analysis persistence | 12-Jul-2026
"""One row per network-configuration analysis run. Stores the full findings
result (JSON) so the report/live views can re-display the last analysis without
re-running detectors. Findings themselves are also mapped into the engine as
Vulnerability + AssetVulnerability rows (see services/netconfig/integration.py);
this row is the human-facing snapshot + provenance."""
from datetime import datetime

from sqlalchemy import JSON, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import ts_col, uuid_fk, uuid_pk


class NetconfigAnalysis(Base):
    __tablename__ = "netconfig_analyses"

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    used_declared_config: Mapped[bool] = mapped_column(Boolean, default=False)
    real_findings: Mapped[int] = mapped_column(Integer, default=0)
    result_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = ts_col()
