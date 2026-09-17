# Drishti v0.1 — liveness and readiness probes | 11-Jul-2026
"""Liveness + readiness probes."""
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db

router = APIRouter(tags=["health"])


@router.get("/")
@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/health/ready")
def ready(db: Session = Depends(get_db)) -> dict:
    settings = get_settings()
    checks: dict[str, str] = {}
    try:
        db.execute(text("SELECT 1"))
        checks["db"] = "ok"
    except Exception:
        checks["db"] = "unreachable"
    _ai_key = (
        settings.anthropic_api_key
        if settings.ai_provider == "anthropic"
        else settings.groq_api_key
    )
    checks["ai"] = (
        "mocked" if settings.ai_mock else ("configured" if _ai_key else "missing_key")
    )
    status = "ok" if checks["db"] == "ok" else "degraded"
    return {"status": status, "checks": checks}
