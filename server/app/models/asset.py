# Drishti v0.1 — network asset and topology models | 11-Jul-2026
"""Network topology aggregate: risk zones, assets, services, connections."""
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.base import ts_col, utcnow, uuid_fk, uuid_pk

if TYPE_CHECKING:
    from app.models.vuln import AssetVulnerability

ASSET_TYPES = ("server", "database", "workstation", "firewall", "router", "webapp", "iot", "cloud")
CRITICALITIES = ("low", "medium", "high", "critical")
ZONE_KINDS = ("dmz", "internal", "crown_jewel", "cloud")
RELATIONS = ("network", "admin", "trust", "exposure")


class RiskZone(Base):
    __tablename__ = "risk_zones"
    __table_args__ = (CheckConstraint("kind IN ('dmz','internal','crown_jewel','cloud')"),)

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(20))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    assets: Mapped[list["Asset"]] = relationship(back_populates="zone")


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("org_id", "ip"),
        CheckConstraint(
            "asset_type IN ('server','database','workstation','firewall','router','webapp','iot','cloud')"
        ),
        CheckConstraint("criticality IN ('low','medium','high','critical')"),
        Index("ix_assets_org_internet", "org_id", "internet_facing"),
    )

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    zone_id: Mapped[str | None] = uuid_fk("risk_zones.id", nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip: Mapped[str] = mapped_column(String(45))
    os: Mapped[str | None] = mapped_column(String(120), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(20), default="server")
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    business_value: Mapped[Decimal] = mapped_column(Numeric(14, 2), default=Decimal("10000"))
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[Decimal | None] = mapped_column(Numeric(6, 3), nullable=True)
    blast_radius_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    meta: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    first_seen_at: Mapped[datetime] = ts_col()
    updated_at: Mapped[datetime] = ts_col(onupdate=utcnow)

    zone: Mapped[RiskZone | None] = relationship(back_populates="assets")
    services: Mapped[list["Service"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    findings: Mapped[list["AssetVulnerability"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol"),
        CheckConstraint("protocol IN ('tcp','udp')"),
    )

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    asset_id: Mapped[str] = uuid_fk("assets.id", fk_kw={"ondelete": "CASCADE"}, index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    name: Mapped[str] = mapped_column(String(120))
    version: Mapped[str | None] = mapped_column(String(80), nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="services")


class Connection(Base):
    __tablename__ = "connections"
    __table_args__ = (
        UniqueConstraint("from_asset_id", "to_asset_id", "relation"),
        CheckConstraint("relation IN ('network','admin','trust','exposure')"),
    )

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    from_asset_id: Mapped[str] = uuid_fk("assets.id", fk_kw={"ondelete": "CASCADE"}, index=True)
    to_asset_id: Mapped[str] = uuid_fk("assets.id", fk_kw={"ondelete": "CASCADE"}, index=True)
    relation: Mapped[str] = mapped_column(String(20), default="network")
    weight: Mapped[Decimal | None] = mapped_column(Numeric(6, 3), nullable=True)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = ts_col()
