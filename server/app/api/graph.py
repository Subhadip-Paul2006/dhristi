# Drishti v0.1 — attack graph visualization endpoint | 11-Jul-2026
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.deps import get_current_org
from app.db import get_db
from app.models import Organization
from app.schemas.graph import GraphResponse
from app.services.read_service import build_graph

router = APIRouter()


@router.get("/graph", response_model=GraphResponse)
def get_graph(
    focus: str | None = Query(default=None),
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> GraphResponse:
    return build_graph(db, org.id, focus)
