# Drishti v0.1 — edge agent data ingestion | 11-Jul-2026
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import rate_limit_ingest, reject_oversized
from app.db import get_db
from app.models import Agent
from app.schemas.ingest import IngestPayload, IngestResponse
from app.services.ingest import ingest_payload

router = APIRouter()


@router.post(
    "/ingest",
    response_model=IngestResponse,
    status_code=202,
    dependencies=[Depends(reject_oversized)],
)
def ingest(
    payload: IngestPayload,
    agent: Agent = Depends(rate_limit_ingest),
    db: Session = Depends(get_db),
) -> IngestResponse:
    return ingest_payload(db, agent, payload)
