# Drishti v0.1 — authentication and session management | 11-Jul-2026
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import TokenBucket, get_current_org, get_current_user
from app.core.errors import UnauthorizedError
from app.core.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    create_refresh_token,
    decode_token,
    normalize_email,
    verify_password,
)
from app.db import get_db
from app.models import Organization, User
from app.schemas.auth import (
    LoginRequest,
    MeOut,
    MePatch,
    OrgOut,
    RefreshRequest,
    RegisterOut,
    RegisterRequest,
    TokenPair,
    UserOut,
)
from app.services.accounts import register_account, update_me

router = APIRouter()

# Shared across register/login/refresh: brute-forcing passwords, spamming
# account creation, and hammering /refresh are all the same "unauthenticated
# endpoint abuse" shape. Keyed by client IP and (when known) by the target
# email, since either a single IP hitting many accounts or many IPs hitting
# one account is an attack. Burst is generous because, pre-auth, IP is the
# only key available and many legitimate clients can share one (NAT/proxy/
# test harness) — the slow sustained refill is what actually stops scripted
# guessing.
auth_bucket = TokenBucket(rate_per_minute=90, burst=60)


def _rate_limit_auth(request: Request, email: str | None = None) -> None:
    client_host = request.client.host if request.client else "unknown"
    auth_bucket.check(f"ip:{client_host}")
    if email:
        auth_bucket.check(f"email:{email}")


@router.post("/register", response_model=RegisterOut, status_code=201)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> RegisterOut:
    _rate_limit_auth(request, normalize_email(body.email))
    user, org = register_account(db, body.name, body.email, body.password, body.org_name)
    return RegisterOut(
        access_token=create_access_token(user.id, org.id, user.token_version or 0),
        refresh_token=create_refresh_token(user.id, org.id, user.token_version or 0),
        user=UserOut(id=user.id, name=user.name, email=user.email, role=user.role),
        org=OrgOut(id=org.id, name=org.name, slug=org.slug),
    )


@router.post("/login", response_model=TokenPair)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    email = normalize_email(body.email)
    _rate_limit_auth(request, email)
    user = db.scalar(select(User).where(User.email == email))
    password_hash = user.password_hash if user is not None else DUMMY_PASSWORD_HASH
    # Always run verify_password, even for a nonexistent email, so response
    # time doesn't leak whether the account exists (timing side-channel).
    password_ok = verify_password(body.password, password_hash)
    if user is None or not password_ok:
        raise UnauthorizedError("Invalid email or password")
    return TokenPair(
        access_token=create_access_token(user.id, user.org_id, user.token_version or 0),
        refresh_token=create_refresh_token(user.id, user.org_id, user.token_version or 0),
    )


@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshRequest, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    _rate_limit_auth(request)
    payload = decode_token(body.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise UnauthorizedError("Invalid refresh token")
    user = db.get(User, payload.get("sub"))
    if user is None:
        raise UnauthorizedError("Unknown user")
    if payload.get("token_version", 0) != (user.token_version or 0):
        raise UnauthorizedError("Invalid refresh token")
    return TokenPair(
        access_token=create_access_token(user.id, user.org_id, user.token_version or 0),
        refresh_token=create_refresh_token(user.id, user.org_id, user.token_version or 0),
    )


@router.get("/me", response_model=MeOut)
def me(
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
) -> MeOut:
    return _me_out(user, org)


@router.patch("/me", response_model=MeOut)
def patch_me(
    body: MePatch,
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> MeOut:
    return _me_out(update_me(db, user, body), org)


def _me_out(user: User, org: Organization) -> MeOut:
    return MeOut(
        id=user.id,
        name=user.name,
        email=user.email,
        role=user.role,
        org_id=org.id,
        org_name=org.name,
        org_slug=org.slug,
    )
