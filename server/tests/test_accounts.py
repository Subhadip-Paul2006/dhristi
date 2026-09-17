# Drishti v0.1 — multi-user auth tests | 11-Jul-2026
"""Multi-user auth: register, profile, org isolation, sample loading."""
import json
from pathlib import Path

from sqlalchemy import select

from app.models import Asset

FIXTURE = json.loads(
    (Path(__file__).parent.parent / "app/seed/fixtures/db-prod-01.json").read_text()
)

REGISTER_BODY = {
    "name": "Ada Lovelace",
    "email": "ada@newco.dev",
    "password": "s3cure-pass!",
    "org_name": "NewCo Security",
}


def _register(client, **overrides):
    body = {**REGISTER_BODY, **overrides}
    return client.post("/api/auth/register", json=body)


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_register_creates_user_and_empty_org(client, db_session):
    resp = _register(client)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["access_token"] and body["refresh_token"]
    assert body["user"]["email"] == "ada@newco.dev"
    assert body["user"]["role"] == "admin"
    assert body["org"]["slug"] == "newco-security"

    # the new org starts EMPTY — no seeded assets or findings
    headers = _auth(body["access_token"])
    org = client.get("/api/org", headers=headers).json()
    assert org["asset_count"] == 0
    assert org["open_findings"] == 0
    assert org["member_count"] == 1
    dash = client.get("/api/dashboard", headers=headers).json()
    assert dash["total_exposure_usd"] == 0
    assert dash["open_findings"] == 0


def test_register_duplicate_email_conflict(client, db_session):
    assert _register(client).status_code == 201
    resp = _register(client, org_name="Another Org")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "conflict"


def test_login_works_after_register(client, db_session):
    _register(client)
    resp = client.post(
        "/api/auth/login",
        json={"email": REGISTER_BODY["email"], "password": REGISTER_BODY["password"]},
    )
    assert resp.status_code == 200, resp.text
    me = client.get("/api/auth/me", headers=_auth(resp.json()["access_token"])).json()
    assert me["email"] == REGISTER_BODY["email"]
    assert me["name"] == "Ada Lovelace"


def test_protected_route_requires_token(client, db_session):
    for path in ("/api/dashboard", "/api/org", "/api/assets"):
        resp = client.get(path)
        assert resp.status_code == 401, path
        assert resp.json()["error"]["code"] == "unauthorized"


def test_org_isolation(client, db_session, seed_acme_org):
    """A user in org B must not see org A's assets or dollars."""
    token = _register(client).json()["access_token"]
    headers = _auth(token)

    # org B sees no assets, an empty graph, zeroed dashboard
    assert client.get("/api/assets", headers=headers).json() == []
    dash = client.get("/api/dashboard", headers=headers).json()
    assert dash["total_exposure_usd"] == 0 and dash["open_findings"] == 0

    # org A's asset ids are invisible to org B (404, not leaked)
    acme_asset = db_session.scalar(select(Asset).where(Asset.org_id == seed_acme_org.id))
    resp = client.get(f"/api/assets/{acme_asset.id}", headers=headers)
    assert resp.status_code == 404


def test_load_sample_and_reset(client, db_session):
    token = _register(client).json()["access_token"]
    headers = _auth(token)

    # load the sample network → real engine-computed numbers appear
    resp = client.post("/api/org/load-sample", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["asset_count"] == 10
    dash = client.get("/api/dashboard", headers=headers).json()
    assert dash["total_exposure_usd"] > 0
    assert len(dash["top_paths"]) >= 1

    # idempotent — loading twice keeps exactly one sample network
    assert client.post("/api/org/load-sample", headers=headers).json()["asset_count"] == 10

    # reset clears the network but keeps the account
    resp = client.post("/api/org/reset", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["asset_count"] == 0
    assert client.get("/api/dashboard", headers=headers).json()["total_exposure_usd"] == 0


def test_patch_me_name_and_password(client, db_session):
    token = _register(client).json()["access_token"]
    headers = _auth(token)

    resp = client.patch("/api/auth/me", json={"name": "Ada L."}, headers=headers)
    assert resp.status_code == 200 and resp.json()["name"] == "Ada L."

    # wrong current password → 401; nothing changes
    resp = client.patch(
        "/api/auth/me",
        json={"current_password": "wrong", "new_password": "brand-new-pass1"},
        headers=headers,
    )
    assert resp.status_code == 401

    # correct current password → new password works on login
    resp = client.patch(
        "/api/auth/me",
        json={"current_password": REGISTER_BODY["password"], "new_password": "brand-new-pass1"},
        headers=headers,
    )
    assert resp.status_code == 200
    login = client.post(
        "/api/auth/login",
        json={"email": REGISTER_BODY["email"], "password": "brand-new-pass1"},
    )
    assert login.status_code == 200


def test_reconcile_adds_missing_column(db_session):
    """A pre-existing table missing an additive column self-heals on boot
    (no Alembic — see db_init.reconcile_columns). Guards the register 500."""
    from sqlalchemy import text

    from app.db_init import reconcile_columns

    engine = db_session.get_bind()
    # mimic a stale DB: drop the additive users.name column
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users DROP COLUMN name"))
    cols = {c[1] for c in engine.raw_connection().cursor().execute("PRAGMA table_info(users)")}
    assert "name" not in cols

    reconcile_columns(engine)

    cols = {c[1] for c in engine.raw_connection().cursor().execute("PRAGMA table_info(users)")}
    assert "name" in cols
    # idempotent — running again is a no-op, not an error
    reconcile_columns(engine)


def test_agent_token_connects_new_org(client, db_session):
    """The onboarding 'connect your network' path: rotate a token, ingest with it."""
    reg = _register(client).json()
    headers = _auth(reg["access_token"])

    tok = client.post("/api/org/agent-token", headers=headers)
    assert tok.status_code == 200, tok.text
    body = tok.json()
    assert body["token"].startswith("drishti_")
    assert body["org_slug"] == reg["org"]["slug"]

    payload = dict(FIXTURE, org_slug=body["org_slug"])
    resp = client.post(
        "/api/ingest", json=payload, headers={"Authorization": f"Bearer {body['token']}"}
    )
    assert resp.status_code == 202, resp.text
    assert client.get("/api/org", headers=headers).json()["asset_count"] == 1
