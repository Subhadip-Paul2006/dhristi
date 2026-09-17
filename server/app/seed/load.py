"""Seed the demo network and run the first engine compute.

Run: python -m app.seed.load
"""
from app.db import Base, SessionLocal, engine
from app.seed.acme import seed_acme


def main() -> None:
    import app.models  # noqa: F401

    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        org = seed_acme(db)
        # Prime the engine caches so the app is alive on first load.
        from app.services.recompute import recompute_org

        recompute_org(db, org.id)
        db.commit()
        print(f"seeded org '{org.slug}' ({org.id}) and computed initial risk state")
    finally:
        db.close()


if __name__ == "__main__":
    main()
