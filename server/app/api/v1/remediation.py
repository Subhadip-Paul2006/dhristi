"""Remediation recommendations API."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.api.deps import get_current_user, org_header
from app.services.ai.ai_remediate import generate_remediation
from app.services.hardening import get_hardening_templates, get_hardening_changelog

router = APIRouter(prefix="/remediation", tags=["remediation"])

@router.get("/actions")
def list_actions(
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 """List all remediation actions for the organization."""
 from app.models.remediation import Remediation
 actions = (
 db.query(Remediation)
 .filter(Remediation.org_id == org_id)
 .order_by(Remediation.created_at.desc())
 .limit(100)
 .all()
 )
 return [
 {
 "id": a.id,
 "title": a.title,
 "description": a.summary,
 "priority": a.kind,
 "status": "reviewed" if a.reviewed else "pending",
 "category": a.generated_by,
 }
 for a in actions
 ]

@router.post("/generate/{finding_id}")
def generate_for_finding(
 finding_id: str,
 db: Session = Depends(get_db),
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 actions = generate_remediation(db, org_id, finding_id)
 return {"actions": actions}

@router.get("/templates")
def templates(
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 return get_hardening_templates()

@router.get("/changelog")
def changelog(
 current = Depends(get_current_user),
 org_id: str = Depends(org_header),
):
 return get_hardening_changelog()
