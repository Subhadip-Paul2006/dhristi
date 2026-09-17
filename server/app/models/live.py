# Drishti v0.1 — live network watch observation | 11-Jul-2026
"""Live network watch: one row per distinct domain the edge agent observed the
host connecting to, with its real trust verdict. Deduped per (org, domain);
hit_count/last_seen track repeat visits. Feeds the live threat map."""
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import ts_col, utcnow, uuid_fk, uuid_pk


class LiveObservation(Base):
    __tablename__ = "live_observations"
    __table_args__ = (UniqueConstraint("org_id", "domain"),)

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    band: Mapped[str] = mapped_column(String(20))  # Trusted | Caution | High Risk
    score: Mapped[float] = mapped_column(Numeric(5, 1))
    # trimmed UrlAnalysisResult (JSON) so the node card renders without re-probing
    verdict_json: Mapped[dict] = mapped_column(JSON)
    source_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hit_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = ts_col()
    last_seen: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class NetworkDevice(Base):
    """A device discovered on the local network (ARP/ping sweep by the agent).

    Defensive inventory only — IP/MAC/hostname of devices sharing the subnet.
    We never inspect other devices' traffic (that would require MITM). Deduped
    per (org, mac)."""

    __tablename__ = "network_devices"
    __table_args__ = (
        UniqueConstraint("org_id", "mac"),
        # off-link (L3) devices have no MAC; dedupe them per (org, subnet, ip)
        Index(
            "ux_network_devices_org_subnet_ip_nomac",
            "org_id", "subnet", "ip",
            unique=True,
            sqlite_where=text("mac IS NULL"),
            postgresql_where=text("mac IS NULL"),
        ),
    )

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    # null for off-link (routed) devices — ARP can't see their MAC; never invented
    mac: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    ip: Mapped[str] = mapped_column(String(45))
    # the actual observed CIDR (e.g. "10.0.5.0/24"); subnet_inferred=True marks
    # legacy /24 guesses (backfill / old agents) vs a netmask the agent observed
    subnet: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    subnet_inferred: Mapped[bool] = mapped_column(Boolean, default=False)
    source_agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    label: Mapped[str | None] = mapped_column(String(120), nullable=True)
    discovery: Mapped[str] = mapped_column(String(8), default="arp")  # arp | l3
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    is_self: Mapped[bool] = mapped_column(Boolean, default=False)
    is_gateway: Mapped[bool] = mapped_column(Boolean, default=False)
    online: Mapped[bool] = mapped_column(Boolean, default=True)
    # when the autonomous scanner last deep-scanned this device (null = never)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen: Mapped[datetime] = ts_col()
    last_seen: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class NetworkCoverage(Base):
    """One row per network known to exist for an org — whether or not we have
    inventoried it. The gap between "seen" and "inventoried" is the finding.

    Evidence-driven (mirrors netconfig): every row says why we believe the
    network exists (beacon / route / interface / ARP). Never fabricated."""

    __tablename__ = "network_coverage"

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    ssid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subnet: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    gateway_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    label: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # inventoried | reachable_not_scanned | seen_not_joined | unreachable
    status: Mapped[str] = mapped_column(String(24))
    evidence: Mapped[str] = mapped_column(String(255))
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class AutoScanConfig(Base):
    """Per-org autonomous deep-scan schedule. One row per org.

    Defensive scope: the scheduler always scans this host itself; it scans the
    REST of the subnet's devices only when `scan_subnet` is explicitly enabled
    (the user has affirmed authorization to test the whole network)."""

    __tablename__ = "autoscan_configs"
    __table_args__ = (UniqueConstraint("org_id"),)

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=420)  # 7 min
    scan_subnet: Mapped[bool] = mapped_column(Boolean, default=False)  # authorized?
    cursor: Mapped[int] = mapped_column(Integer, default=0)  # round-robin position
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DeepScan(Base):
    """One consented deep scan of a device on the local network.

    Records the REAL nmap + CVE result (or a truthful available:false when the
    scan/lookup couldn't run) so the UI can re-fetch the last result per asset.
    Defensive only: the user explicitly consents to scan a device they own or
    are authorized to test."""

    __tablename__ = "deep_scans"

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    # the asset created/updated from this scan (null when the scan was unavailable)
    asset_id: Mapped[str | None] = uuid_fk("assets.id", fk_kw={"ondelete": "CASCADE"}, nullable=True, index=True)
    target_ip: Mapped[str] = mapped_column(String(45), index=True)
    available: Mapped[bool] = mapped_column(Boolean, default=False)
    unavailable_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # full DeepScanResult (JSON) so GET can replay the exact last result
    result_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = ts_col()


class DevicePresenceSession(Base):
    """Historical observation and continuous presence session for a network node.

    Maintains append/update-safe presence sessions scoped to (org, network, device).
    A continuous session represents unbroken observations where consecutive hits
    arrive within MAX_OBSERVATION_GAP. When a gap exceeds the threshold, the session
    closes at its last confirmed observation and a new session begins.
    """

    __tablename__ = "device_sessions"
    __table_args__ = (
        Index("ix_device_sessions_lookup", "org_id", "network_key", "device_key", "is_current"),
        Index("ix_device_sessions_org_device", "org_id", "device_key"),
        Index("ix_device_sessions_org_network", "org_id", "network_key"),
    )

    id: Mapped[str] = uuid_pk()
    org_id: Mapped[str] = uuid_fk("organizations.id", index=True)
    # device_key follows existing repo identity: MAC for on-link, or L3 subnet:ip
    device_key: Mapped[str] = mapped_column(String(64))
    # network_key scopes history to the environment (e.g. subnet CIDR)
    network_key: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = ts_col()
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_current: Mapped[bool] = mapped_column(Boolean, default=True)
    observation_count: Mapped[int] = mapped_column(Integer, default=1)
    observation_source: Mapped[str | None] = mapped_column(String(32), nullable=True)

