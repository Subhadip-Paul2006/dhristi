"""URL Trust analysis routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, HttpUrl
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.services.urltrust.analyzer import analyze_url

router = APIRouter(prefix="/urltrust", tags=["urltrust"])


class URLAnalysisRequest(BaseModel):
 url: str


@router.post("/analyze")
def analyze(
 payload: URLAnalysisRequest,
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 result = analyze_url(payload.url)
 return {
 "url": result.get("url"),
 "hostname": result.get("hostname"),
 "score": result.get("score"),
 "band": result.get("band"),
 "summary": result.get("summary", {}),
 }
