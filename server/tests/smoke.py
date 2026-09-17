# Drishti v0.1 — end-to-end smoke test runner | 11-Jul-2026
"""End-to-end smoke test (TESTING.md §5). Run: python tests/smoke.py

Seeds Acme Retail in a fresh in-memory DB, drives the hero flow through the API,
and asserts the load-bearing invariants. Exit non-zero on any failure.
"""
import os
import sys

os.environ.setdefault("AI_MOCK", "true")
os.environ.setdefault("DATABASE_URL", "sqlite://")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import app.models  # noqa: E402,F401
from app.db import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.seed.acme import DEMO_USER_EMAIL, DEMO_USER_PASSWORD, seed_acme  # noqa: E402
from app.services.recompute import recompute_org  # noqa: E402


def _fail(msg):
    print(f"SMOKE FAIL: {msg}")
    sys.exit(1)


def main():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = Session()

    org = seed_acme(session)
    recompute_org(session, org.id)
    session.commit()

    app.dependency_overrides[get_db] = lambda: (yield session)
    client = TestClient(app)

    # 1. login
    r = client.post(
        "/api/auth/login", json={"email": DEMO_USER_EMAIL, "password": DEMO_USER_PASSWORD}
    )
    if r.status_code != 200:
        _fail(f"login {r.status_code}")
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}

    # 2. graph is React-Flow shaped, positions present
    g = client.get("/api/graph", headers=h).json()
    if not g["nodes"] or not g["edges"]:
        _fail("empty graph")
    if not all("x" in n["position"] for n in g["nodes"]):
        _fail("missing positions")
    if "INTERNET" not in {n["id"] for n in g["nodes"]}:
        _fail("no INTERNET node")

    # 3. hero path present + ranked #1
    paths = client.get("/api/paths", headers=h).json()
    if not paths:
        _fail("no paths")
    top = paths[0]
    detail = client.get(f"/api/paths/{top['id']}", headers=h).json()
    labels = [top["entry_label"]] + [s["asset_hostname"] for s in detail["steps"]]
    if labels != ["INTERNET", "web-app-01", "api-gw-01", "app-svc-01", "jump-01", "db-prod-01"]:
        _fail(f"hero path not #1: {labels}")

    # 4. dashboard total exposure > 0
    dash = client.get("/api/dashboard", headers=h).json()
    if dash["total_exposure_usd"] <= 0:
        _fail("total exposure not positive")

    # 5. AI impact (mock) echoes the number
    impact = client.post("/api/ai/impact", json={"path_id": top["id"]}, headers=h).json()
    if abs(impact["impact_usd"] - top["impact_usd"]) > 1:
        _fail(f"impact echo mismatch: {impact['impact_usd']} vs {top['impact_usd']}")

    # 6. resolve the db-prod finding → recompute changes ranking
    findings = client.get("/api/findings?status=open", headers=h).json()
    db_finding = next(
        f for f in findings if f["asset_hostname"] == "db-prod-01" and f["cve_id"] == "CVE-2024-0005"
    )
    before_total = dash["total_exposure_usd"]
    client.patch(f"/api/findings/{db_finding['id']}", json={"status": "resolved"}, headers=h)
    after = client.get("/api/dashboard", headers=h).json()
    if after["total_exposure_usd"] >= before_total:
        _fail(f"exposure did not drop after resolve: {before_total} -> {after['total_exposure_usd']}")

    print(f"SMOKE PASS: hero path #1, exposure ${before_total:,.0f} -> ${after['total_exposure_usd']:,.0f}")
    app.dependency_overrides.clear()


if __name__ == "__main__":
    main()
