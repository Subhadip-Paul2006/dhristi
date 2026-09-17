# Drishti v0.1 — account and org self-service logic | 11-Jul-2026
"""Account + organization self-service: register, profile, org overview,
sample-network loading. Routers stay thin (CLAUDE.md §4); everything here.
"""
from __future__ import annotations

import re
import secrets

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, UnauthorizedError
from app.core.security import hash_agent_token, hash_password, normalize_email, verify_password
from app.models import (
    Agent,
    Asset,
    AssetVulnerability,
    AttackPath,
    Organization,
    User,
)
from app.schemas.auth import MePatch, OrgInfoOut
from app.seed.acme import reset_network, seed_network
from app.services.recompute import recompute_org

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", name.lower()).strip("-")
    return slug or "org"


def _unique_slug(db: Session, base: str) -> str:
    slug = base
    n = 2
    while db.scalar(select(Organization).where(Organization.slug == slug)) is not None:
        slug = f"{base}-{n}"
        n += 1
    return slug


def register_account(
    db: Session, name: str, email: str, password: str, org_name: str
) -> tuple[User, Organization]:
    """Create a new empty organization with its first (admin) user."""
    email = normalize_email(email)
    if db.scalar(select(User).where(User.email == email)) is not None:
        raise ConflictError("An account with this email already exists")

    org = Organization(name=org_name, slug=_unique_slug(db, _slugify(org_name)))
    db.add(org)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ConflictError("An organization with a matching name was just created") from None
    user = User(
        org_id=org.id,
        name=name,
        email=email,
        password_hash=hash_password(password),
        role="admin",
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ConflictError("An account with this email already exists") from None
    return user, org


def update_me(db: Session, user: User, patch: MePatch) -> User:
    if patch.name is not None:
        user.name = patch.name
    if patch.new_password is not None:
        if not patch.current_password or not verify_password(
            patch.current_password, user.password_hash
        ):
            raise UnauthorizedError("Current password is incorrect")
        user.password_hash = hash_password(patch.new_password)
        user.token_version = (user.token_version or 0) + 1
    db.commit()
    return user


def org_overview(db: Session, org: Organization) -> OrgInfoOut:
    def count(model, *where) -> int:
        return int(db.scalar(select(func.count()).select_from(model).where(*where)) or 0)

    return OrgInfoOut(
        id=org.id,
        name=org.name,
        slug=org.slug,
        asset_count=count(Asset, Asset.org_id == org.id),
        open_findings=count(
            AssetVulnerability,
            AssetVulnerability.org_id == org.id,
            AssetVulnerability.status == "open",
        ),
        path_count=count(AttackPath, AttackPath.org_id == org.id),
        member_count=count(User, User.org_id == org.id),
    )


def list_members(db: Session, org_id: str) -> list[User]:
    return list(db.scalars(select(User).where(User.org_id == org_id).order_by(User.created_at)))


def load_sample_network(db: Session, org: Organization) -> None:
    """Seed the caller's org with the Acme sample network + recompute. Idempotent."""
    reset_network(db, org)
    seed_network(db, org)
    recompute_org(db, org.id)
    db.commit()


def reset_org_network(db: Session, org: Organization) -> None:
    """Clear the caller's org network data (assets/findings/paths). Keeps users/agents."""
    reset_network(db, org)
    db.commit()


def rotate_agent_token(db: Session, org: Organization) -> tuple[Agent, str]:
    """Create (or rotate) the org's default edge-agent token.

    The plaintext token is returned exactly once; only its hash is stored.
    """
    token = f"drishti_{secrets.token_urlsafe(24)}"
    agent = db.scalar(
        select(Agent).where(Agent.org_id == org.id, Agent.agent_key == "default")
    )
    if agent is None:
        agent = Agent(
            org_id=org.id,
            agent_key="default",
            token_hash=hash_agent_token(token),
            label="Default edge agent",
            status="active",
        )
        db.add(agent)
    else:
        agent.token_hash = hash_agent_token(token)
        agent.status = "active"
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ConflictError("Agent token was just rotated by another request") from None
    return agent, token
