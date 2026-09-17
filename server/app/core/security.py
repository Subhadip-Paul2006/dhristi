# Drishti v0.1 — JWT, password hashing, agent tokens | 11-Jul-2026
"""Password hashing, JWT issuance/verification, agent-token hashing."""
import hashlib
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from jwt.exceptions import PyJWTError

from app.config import get_settings

ALGORITHM = "HS256"


def normalize_email(email: str) -> str:
    """Canonical form for every email read from user input (register/login lookups)."""
    return email.strip().lower()


def _prehash(password: str) -> bytes:
    # bcrypt silently ignores/rejects bytes past 72; a hex sha256 digest (64
    # ASCII bytes) is always under that limit regardless of input length or
    # multi-byte UTF-8 characters, so hashing/verifying never raises.
    return hashlib.sha256(password.encode()).hexdigest().encode()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), password_hash.encode())
    except ValueError:
        return False


# Precomputed at import time so login always pays the same bcrypt cost whether
# or not the email exists — avoids a timing side-channel that leaks account
# existence (see app/api/auth.py login).
DUMMY_PASSWORD_HASH = hash_password("drishti-timing-safety-placeholder")


def hash_agent_token(token: str) -> str:
    """Agent tokens are looked up by hash equality, so a deterministic digest."""
    return hashlib.sha256(token.encode()).hexdigest()


def _create_token(
    sub: str, org_id: str, token_type: str, expires_delta: timedelta, token_version: int
) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "org_id": org_id,
        "type": token_type,
        "token_version": token_version,
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def create_access_token(user_id: str, org_id: str, token_version: int = 0) -> str:
    settings = get_settings()
    return _create_token(
        user_id, org_id, "access", timedelta(minutes=settings.jwt_access_minutes), token_version
    )


def create_refresh_token(user_id: str, org_id: str, token_version: int = 0) -> str:
    settings = get_settings()
    return _create_token(
        user_id, org_id, "refresh", timedelta(days=settings.jwt_refresh_days), token_version
    )


def decode_token(token: str) -> dict | None:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    except PyJWTError:
        return None
