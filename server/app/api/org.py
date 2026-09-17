# Drishti v0.1 — organization management endpoint | 11-Jul-2026
"""Organization self-service: overview, members, sample data, agent token."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_org, require_role
from app.db import get_db
from app.models import Organization
from app.schemas.auth import AgentTokenOut, MemberOut, OrgInfoOut
from app.services.accounts import (
    list_members,
    load_sample_network,
    org_overview,
    reset_org_network,
    rotate_agent_token,
)

router = APIRouter()


@router.get("/org", response_model=OrgInfoOut)
def get_org(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> OrgInfoOut:
    return org_overview(db, org)


@router.get("/org/members", response_model=list[MemberOut])
def get_members(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[MemberOut]:
    return [
        MemberOut(id=u.id, name=u.name, email=u.email, role=u.role)
        for u in list_members(db, org.id)
    ]


@router.post("/org/load-sample", response_model=OrgInfoOut)
def load_sample(
    org: Organization = Depends(get_current_org),
    _user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> OrgInfoOut:
    load_sample_network(db, org)
    return org_overview(db, org)


@router.post("/org/reset", response_model=OrgInfoOut)
def reset_org_data(
    org: Organization = Depends(get_current_org),
    _user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> OrgInfoOut:
    reset_org_network(db, org)
    return org_overview(db, org)


@router.post("/org/agent-token", response_model=AgentTokenOut)
def new_agent_token(
    org: Organization = Depends(get_current_org),
    _user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> AgentTokenOut:
    agent, token = rotate_agent_token(db, org)
    return AgentTokenOut(agent_key=agent.agent_key, token=token, org_slug=org.slug)
