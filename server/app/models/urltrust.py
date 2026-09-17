# Drishti v0.1 — URL trust analysis persistence | 11-Jul-2026
"""URL Trust Analyzer persistence. One row per analysis, org-scoped like the
rest of the app. The full computed result is stored as JSON so history can
re-render exactly what was shown, without re-probing the network."""
from datetime import datetime

from sqlalchemy import JSON, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import ts_col, uuid_fk, uuid_pk


class UrlAnalysis(Base):
    __tablename__ = "url_analyses"

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    url: Mapped[str] = mapped_column(String(2048))
    score: Mapped[float] = mapped_column(Numeric(5, 1))
    band: Mapped[str] = mapped_column(String(20))
    # full UrlAnalysisResult (JSON) — portable across SQLite + Postgres
    result_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = ts_col(index=True)
