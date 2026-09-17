# Drishti v0.1 — ingestion idempotency tests | 11-Jul-2026
"""Ingestion + idempotency (TESTING.md §3.6)."""
import json
from pathlib import Path

from sqlalchemy import func, select

from app.models import Asset, AssetVulnerability, Service, Vulnerability

FIXTURE = json.loads(
    (Path(__file__).parent.parent / "app/seed/fixtures/db-prod-01.json").read_text()
)


def _count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def test_ingest_creates_asset(client, db_session, seed_acme_org, agent_headers):
    payload = dict(FIXTURE, host={**FIXTURE["host"], "ip": "10.0.9.99", "hostname": "new-host-01"})
    resp = client.post("/api/ingest", json=payload, headers=agent_headers)
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "accepted"
    asset = db_session.scalar(select(Asset).where(Asset.ip == "10.0.9.99"))
    assert asset is not None
    assert asset.hostname == "new-host-01"
    assert body["ingested"]["services"] == 2
    assert body["ingested"]["vulnerabilities"] == 1


def test_ingest_idempotent(client, db_session, seed_acme_org, agent_headers):
    before_assets = _count(db_session, Asset)
    for _ in range(2):
        resp = client.post("/api/ingest", json=FIXTURE, headers=agent_headers)
        assert resp.status_code == 202, resp.text
    assert _count(db_session, Asset) == before_assets  # db-prod-01 already seeded
    db_prod = db_session.scalar(select(Asset).where(Asset.ip == "10.0.3.11"))
    svc_count = db_session.scalar(
        select(func.count()).select_from(Service).where(Service.asset_id == db_prod.id)
    )
    assert svc_count == 2  # replaced snapshot, not appended


def test_ingest_rejects_bad_token(client, seed_acme_org):
    resp = client.post(
        "/api/ingest", json=FIXTURE, headers={"Authorization": "Bearer wrong-token"}
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


def test_ingest_rejects_wrong_org_slug(client, seed_acme_org, agent_headers):
    payload = dict(FIXTURE, org_slug="someone-else")
    resp = client.post("/api/ingest", json=payload, headers=agent_headers)
    assert resp.status_code == 403


def test_ingest_rejects_oversized(client, seed_acme_org, agent_headers):
    huge = dict(FIXTURE)
    huge["vulnerabilities"] = FIXTURE["vulnerabilities"] * 6000  # > 1 MB
    resp = client.post("/api/ingest", json=huge, headers=agent_headers)
    assert resp.status_code == 413


def test_ingest_rejects_bad_payload(client, seed_acme_org, agent_headers):
    resp = client.post("/api/ingest", json={"nope": True}, headers=agent_headers)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


def test_ingest_triggers_recompute(client, db_session, seed_acme_org, agent_headers):
    """TESTING.md §3.6: after ingest, cached paths/scores are (re)populated."""
    from app.models import AttackPath

    # wipe the cached engine output so only an ingest-triggered recompute can restore it
    for p in db_session.scalars(select(AttackPath).where(AttackPath.org_id == seed_acme_org.id)):
        db_session.delete(p)
    db_prod = db_session.scalar(select(Asset).where(Asset.ip == "10.0.3.11"))
    db_prod.risk_score = None
    db_session.commit()

    resp = client.post("/api/ingest", json=FIXTURE, headers=agent_headers)
    assert resp.status_code == 202, resp.text

    paths = db_session.scalars(
        select(AttackPath).where(AttackPath.org_id == seed_acme_org.id)
    ).all()
    assert paths, "ingest should trigger a recompute that repopulates attack paths"
    db_session.refresh(db_prod)
    assert db_prod.risk_score is not None and float(db_prod.risk_score) > 0


def test_ingest_rejects_oversized_field(client, seed_acme_org, agent_headers):
    payload = dict(FIXTURE, host={**FIXTURE["host"], "hostname": "h" * 300})
    resp = client.post("/api/ingest", json=payload, headers=agent_headers)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


def test_ingest_dedupes_non_cve_findings_by_title_and_severity(
    client, db_session, seed_acme_org, agent_headers
):
    finding = {
        "title": "Weak SSH configuration",
        "cvss": 5.0,
        "severity": "medium",
        "exploitability": 0.2,
    }
    payload = dict(
        FIXTURE,
        host={**FIXTURE["host"], "ip": "10.0.9.88", "hostname": "dedupe-host"},
        services=[],
        vulnerabilities=[finding],
        connectivity=[],
    )
    for _ in range(2):
        resp = client.post("/api/ingest", json=payload, headers=agent_headers)
        assert resp.status_code == 202, resp.text
    count = db_session.scalar(
        select(func.count())
        .select_from(Vulnerability)
        .where(Vulnerability.title == "Weak SSH configuration")
    )
    assert count == 1


def test_ingest_new_asset_respects_low_criticality_hint(
    client, db_session, seed_acme_org, agent_headers
):
    payload = dict(
        FIXTURE,
        host={
            **FIXTURE["host"],
            "ip": "10.0.9.77",
            "hostname": "low-crit-host",
            "criticality_hint": "low",
        },
    )
    resp = client.post("/api/ingest", json=payload, headers=agent_headers)
    assert resp.status_code == 202, resp.text
    asset = db_session.scalar(select(Asset).where(Asset.ip == "10.0.9.77"))
    assert asset.criticality == "low"  # not silently upgraded to the ORM default


def test_ingest_asset_race_adopts_existing_row(db_session, seed_acme_org):
    """Concurrent ingest already inserted the (org_id, ip) row before our SELECT
    saw it — the loser must adopt the winner's row instead of crashing."""
    from app.schemas.ingest import IngestPayload
    from app.services.ingest import _upsert_asset

    org = seed_acme_org
    existing = Asset(org_id=org.id, ip="10.0.9.50", hostname="racer")
    db_session.add(existing)
    db_session.commit()

    payload = IngestPayload(
        **dict(
            FIXTURE,
            host={**FIXTURE["host"], "ip": "10.0.9.50", "hostname": "impostor-name"},
        )
    )

    original_scalar = db_session.scalar
    calls = {"n": 0}

    def flaky_scalar(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # simulate the SELECT racing ahead of the other insert
        return original_scalar(*args, **kwargs)

    db_session.scalar = flaky_scalar
    try:
        asset = _upsert_asset(db_session, org.id, payload)
    finally:
        db_session.scalar = original_scalar

    assert asset.id == existing.id
    assert asset.hostname == "impostor-name"  # adopted row still gets updated


def test_ingest_preserves_resolved(client, db_session, seed_acme_org, agent_headers):
    finding = db_session.scalar(
        select(AssetVulnerability)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .where(Asset.ip == "10.0.3.11")
    )
    finding.status = "resolved"
    db_session.commit()

    resp = client.post("/api/ingest", json=FIXTURE, headers=agent_headers)
    assert resp.status_code == 202
    db_session.refresh(finding)
    assert finding.status == "resolved"
