# Drishti v0.1 — auth security hardening tests | 11-Jul-2026
"""Auth security fixes: rate limiting, timing-safe login, email normalization,
registration races, bcrypt long-password safety, and refresh-token revocation
via token_version (app/api/auth.py, app/services/accounts.py, app/core/security.py).
"""
import app.api.auth as auth_module
from app.core.deps import TokenBucket
from app.core.security import hash_password, verify_password


def test_login_unknown_email_is_unauthorized(client, db_session):
    resp = client.post(
        "/api/auth/login", json={"email": "ghost@nowhere.dev", "password": "whatever123"}
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


def test_login_email_is_case_insensitive(client, db_session):
    body = {
        "name": "Case Test",
        "email": "MixedCase@Example.com",
        "password": "s3cure-pass!",
        "org_name": "Case Co",
    }
    assert client.post("/api/auth/register", json=body).status_code == 201

    resp = client.post(
        "/api/auth/login",
        json={"email": "mixedcase@example.com", "password": body["password"]},
    )
    assert resp.status_code == 200, resp.text


def test_register_duplicate_email_different_case_is_conflict(client, db_session):
    body = {
        "name": "Dup Test",
        "email": "dup@example.com",
        "password": "s3cure-pass!",
        "org_name": "Dup Co",
    }
    assert client.post("/api/auth/register", json=body).status_code == 201

    dup = dict(body, email="DUP@EXAMPLE.COM", org_name="Dup Co Two")
    resp = client.post("/api/auth/register", json=dup)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "conflict"


def test_login_rate_limited_returns_429(client, db_session, monkeypatch):
    # Swap in a tiny dedicated bucket for this test only, so we don't burn
    # through the real app.api.auth.auth_bucket shared by the rest of the suite.
    monkeypatch.setattr(auth_module, "auth_bucket", TokenBucket(rate_per_minute=1, burst=2))
    body = {"email": "nobody@example.com", "password": "whatever123"}
    assert client.post("/api/auth/login", json=body).status_code == 401
    assert client.post("/api/auth/login", json=body).status_code == 401
    resp = client.post("/api/auth/login", json=body)
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "rate_limited"


def test_register_rate_limited_returns_429(client, db_session, monkeypatch):
    monkeypatch.setattr(auth_module, "auth_bucket", TokenBucket(rate_per_minute=1, burst=2))

    def body(n: int) -> dict:
        return {
            "name": "Flood",
            "email": f"flood{n}@example.com",
            "password": "s3cure-pass!",
            "org_name": f"Flood {n}",
        }

    assert client.post("/api/auth/register", json=body(1)).status_code == 201
    assert client.post("/api/auth/register", json=body(2)).status_code == 201
    resp = client.post("/api/auth/register", json=body(3))
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "rate_limited"


def test_password_over_72_bytes_hashes_and_verifies():
    long_password = "p" * 128
    hashed = hash_password(long_password)
    assert verify_password(long_password, hashed)
    assert not verify_password("wrong", hashed)


def test_password_with_multibyte_utf8_hashes_and_verifies():
    password = "pw-é" * 40  # well over 72 raw UTF-8 bytes
    hashed = hash_password(password)
    assert verify_password(password, hashed)


def test_password_change_revokes_old_refresh_token(client, db_session):
    body = {
        "name": "Rotate Test",
        "email": "rotate@example.com",
        "password": "s3cure-pass!",
        "org_name": "Rotate Co",
    }
    reg = client.post("/api/auth/register", json=body).json()
    old_refresh = reg["refresh_token"]
    headers = {"Authorization": f"Bearer {reg['access_token']}"}

    resp = client.patch(
        "/api/auth/me",
        json={"current_password": body["password"], "new_password": "brand-new-pass1"},
        headers=headers,
    )
    assert resp.status_code == 200

    stale = client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
    assert stale.status_code == 401

    fresh_login = client.post(
        "/api/auth/login", json={"email": body["email"], "password": "brand-new-pass1"}
    )
    assert fresh_login.status_code == 200
    fresh_refresh = client.post(
        "/api/auth/refresh", json={"refresh_token": fresh_login.json()["refresh_token"]}
    )
    assert fresh_refresh.status_code == 200


def test_password_change_revokes_old_access_token(client, db_session):
    """A stolen access token issued before a password change must stop
    working immediately, not linger until its natural expiry."""
    body = {
        "name": "Access Revoke Test",
        "email": "access-revoke@example.com",
        "password": "s3cure-pass!",
        "org_name": "Access Revoke Co",
    }
    reg = client.post("/api/auth/register", json=body).json()
    old_headers = {"Authorization": f"Bearer {reg['access_token']}"}

    resp = client.patch(
        "/api/auth/me",
        json={"current_password": body["password"], "new_password": "brand-new-pass1"},
        headers=old_headers,
    )
    assert resp.status_code == 200

    stale = client.get("/api/auth/me", headers=old_headers)
    assert stale.status_code == 401

    fresh_login = client.post(
        "/api/auth/login", json={"email": body["email"], "password": "brand-new-pass1"}
    )
    assert fresh_login.status_code == 200
    fresh_headers = {"Authorization": f"Bearer {fresh_login.json()['access_token']}"}
    assert client.get("/api/auth/me", headers=fresh_headers).status_code == 200
