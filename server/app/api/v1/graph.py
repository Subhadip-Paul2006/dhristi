"""Graph data endpoint — single source of truth for UI."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.services.read_service import build_graph

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("")
def get_graph(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 return build_graph(db, org_id)
