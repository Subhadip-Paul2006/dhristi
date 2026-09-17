# Drishti v0.1 — FastAPI dependency injection layer | 11-Jul-2026
"""FastAPI dependencies: user/agent auth, role gates, rate limiting."""
import time
from collections import defaultdict
from dataclasses import dataclass

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenError, RateLimitedError, UnauthorizedError
from app.core.security import decode_token, hash_agent_token
from app.db import get_db
from app.models import Agent, Organization, User
from app.models.base import utcnow


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise UnauthorizedError("Missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    token = _bearer(authorization)
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise UnauthorizedError("Invalid or expired token")
    user = db.get(User, payload.get("sub"))
    if user is None:
        raise UnauthorizedError("Unknown user")
    # token_version is bumped on password change (see accounts.update_me) so
    # that change invalidates every previously issued token, not just
    # refresh tokens — without this check a stolen access token issued
    # before the change stays valid until it naturally expires.
    if payload.get("token_version", 0) != (user.token_version or 0):
        raise UnauthorizedError("Invalid or expired token")
    return user


def get_current_org(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Organization:
    org = db.get(Organization, user.org_id)
    if org is None:
        raise UnauthorizedError("Organization not found")
    return org


def require_role(*roles: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise ForbiddenError("Insufficient role")
        return user

    return checker


def get_current_agent(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Agent:
    token = _bearer(authorization)
    agent = db.scalar(
        select(Agent).where(
            Agent.token_hash == hash_agent_token(token), Agent.status == "active"
        )
    )
    if agent is None:
        raise UnauthorizedError("Unknown or disabled agent")
    agent.last_seen_at = utcnow()
    return agent


@dataclass
class _Bucket:
    tokens: float
    last: float


class TokenBucket:
    """Simple in-memory per-key limiter (TRD security: ingest + AI endpoints)."""

    _EVICT_THRESHOLD = 10_000  # only sweep once the dict has grown this large
    _EVICT_TTL_SECONDS = 3600.0  # prune buckets idle longer than this

    def __init__(self, rate_per_minute: float, burst: int):
        self.rate = rate_per_minute / 60.0
        self.burst = burst
        self.buckets: dict[str, _Bucket] = defaultdict(
            lambda: _Bucket(tokens=float(burst), last=time.monotonic())
        )

    def _evict_stale(self, now: float) -> None:
        if len(self.buckets) <= self._EVICT_THRESHOLD:
            return
        stale = [k for k, b in self.buckets.items() if now - b.last > self._EVICT_TTL_SECONDS]
        for k in stale:
            del self.buckets[k]

    def check(self, key: str) -> None:
        now = time.monotonic()
        self._evict_stale(now)
        b = self.buckets[key]
        b.tokens = min(self.burst, b.tokens + (now - b.last) * self.rate)
        b.last = now
        if b.tokens < 1:
            raise RateLimitedError("Too many requests — slow down")
        b.tokens -= 1


ingest_bucket = TokenBucket(rate_per_minute=60, burst=20)
ai_bucket = TokenBucket(rate_per_minute=20, burst=6)


def rate_limit_ingest(agent: Agent = Depends(get_current_agent)) -> Agent:
    ingest_bucket.check(f"agent:{agent.id}")
    return agent


def rate_limit_ai(user: User = Depends(get_current_user)) -> User:
    ai_bucket.check(f"user:{user.id}")
    return user


async def reject_oversized(request: Request) -> None:
    from app.config import get_settings

    length = request.headers.get("content-length")
    if length and int(length) > get_settings().ingest_max_bytes:
        from app.core.errors import DomainError

        err = DomainError("Payload too large")
        err.status = 413
        err.code = "validation_error"
        raise err
