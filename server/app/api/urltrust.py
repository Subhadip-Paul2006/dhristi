# Drishti v0.1 — URL trust analysis endpoint | 11-Jul-2026
"""URL Trust Analyzer API — authed + org-scoped like the rest of the app."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_org, rate_limit_ai
from app.db import get_db
from app.models import Organization
from app.schemas.urltrust import AnalyzeRequest, HistoryItem, UrlAnalysisResult
from app.services.urltrust import analyzer

router = APIRouter()


@router.post("/url-analyzer/analyze", response_model=UrlAnalysisResult,
             dependencies=[Depends(rate_limit_ai)])
def analyze_url(
    body: AnalyzeRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> UrlAnalysisResult:
    return analyzer.analyze(db, org.id, body.url)


@router.get("/url-analyzer/history", response_model=list[HistoryItem])
def analyze_history(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[HistoryItem]:
    return analyzer.history(db, org.id)
