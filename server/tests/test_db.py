# Drishti v0.1 — database FK enforcement tests | 11-Jul-2026
"""SQLite must enforce declared FKs (ondelete=SET NULL etc.) — otherwise a
service delete leaves dangling AssetVulnerability.service_id references."""
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401  (register mappers)
from app.db import Base, _make_engine
from app.models import Asset, AssetVulnerability, Organization, RiskZone, Service, Vulnerability


def test_sqlite_engine_enables_foreign_keys():
    engine = _make_engine("sqlite://")
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_service_delete_nulls_out_finding_via_fk_ondelete():
    engine = _make_engine("sqlite://")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        org = Organization(name="Test Org", slug="test-org")
        db.add(org)
        db.flush()
        zone = RiskZone(org_id=org.id, name="dmz", kind="dmz")
        db.add(zone)
        db.flush()
        asset = Asset(org_id=org.id, zone_id=zone.id, ip="10.0.0.1")
        db.add(asset)
        db.flush()
        service = Service(asset_id=asset.id, org_id=org.id, port=443, name="https")
        db.add(service)
        db.flush()
        vuln = Vulnerability(title="Some CVE")
        db.add(vuln)
        db.flush()
        finding = AssetVulnerability(
            org_id=org.id, asset_id=asset.id, vulnerability_id=vuln.id, service_id=service.id
        )
        db.add(finding)
        db.commit()

        db.execute(text("DELETE FROM services WHERE id = :id"), {"id": service.id})
        db.commit()

        db.refresh(finding)
        assert finding.service_id is None
    finally:
        db.close()
        engine.dispose()
