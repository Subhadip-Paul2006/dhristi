# Drishti v0.1 — test fixtures and shared setup | 11-Jul-2026
import os

os.environ["AI_MOCK"] = "true"
os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  (register mappers)
from app.db import Base, get_db
from app.main import app as fastapi_app
from app.seed.acme import DEMO_AGENT_TOKEN, DEMO_USER_EMAIL, DEMO_USER_PASSWORD, seed_acme


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def seed_acme_org(db_session):
    org = seed_acme(db_session)
    # Prime engine caches so API reads have data (mirrors app/seed/load.py).
    from app.services.recompute import recompute_org

    recompute_org(db_session, org.id)
    db_session.commit()
    return org


@pytest.fixture()
def client(db_session):
    def _get_db():
        yield db_session

    fastapi_app.dependency_overrides[get_db] = _get_db
    try:
        yield TestClient(fastapi_app)
    finally:
        fastapi_app.dependency_overrides.clear()


@pytest.fixture()
def agent_headers():
    return {"Authorization": f"Bearer {DEMO_AGENT_TOKEN}"}


@pytest.fixture()
def user_headers(client, seed_acme_org):
    resp = client.post(
        "/api/auth/login",
        json={"email": DEMO_USER_EMAIL, "password": DEMO_USER_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}
