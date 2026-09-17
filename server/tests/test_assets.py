# Drishti v0.1 — asset validation tests | 11-Jul-2026
"""Asset PATCH validation (business_value must stay non-negative)."""
from sqlalchemy import select

from app.models import Asset


def test_patch_asset_rejects_negative_business_value(
    client, db_session, seed_acme_org, user_headers
):
    asset = db_session.scalar(select(Asset).where(Asset.org_id == seed_acme_org.id))
    resp = client.patch(
        f"/api/assets/{asset.id}", json={"business_value": -500}, headers=user_headers
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


def test_patch_asset_accepts_non_negative_business_value(
    client, db_session, seed_acme_org, user_headers
):
    asset = db_session.scalar(select(Asset).where(Asset.org_id == seed_acme_org.id))
    resp = client.patch(
        f"/api/assets/{asset.id}", json={"business_value": 25000}, headers=user_headers
    )
    assert resp.status_code == 200, resp.text
    db_session.refresh(asset)
    assert float(asset.business_value) == 25000
