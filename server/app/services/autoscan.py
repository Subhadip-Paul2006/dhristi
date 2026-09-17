# Drishti v0.1 — autonomous deep-scan scheduler | 12-Jul-2026
"""Runs the EXISTING deep-scan across discovered devices automatically, on an
interval, round-robin — instead of the manual per-device "Rescan".

Defensive scope, enforced here:
  • the scheduler always scans THIS host (the is_self device);
  • it scans the rest of the subnet's devices ONLY when `scan_subnet` is enabled
    (the user affirmed authorization to test the whole network).
One device per tick, at most one org scan at a time → naturally rate-limited and
concurrency-capped. Nothing is fabricated: ports/CVEs come from the real deep
scan; a device that hasn't been scanned yet stays "not scanned"."""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import AutoScanConfig, NetworkDevice
from app.models.base import utcnow
from app.schemas.live import AutoScanConfigOut

logger = logging.getLogger("drishti")

_TICK_SECONDS = 20  # how often the loop wakes to check for due orgs
_running = False


# ── config ───────────────────────────────────────────────────────────────────
def get_config(db: Session, org_id: str) -> AutoScanConfig:
    cfg = db.scalar(select(AutoScanConfig).where(AutoScanConfig.org_id == org_id))
    if cfg is None:
        cfg = AutoScanConfig(org_id=org_id)
        try:
            with db.begin_nested():
                db.add(cfg)
        except IntegrityError:
            # Lost the (org_id) race to a concurrent first-use — adopt its row.
            cfg = db.scalar(select(AutoScanConfig).where(AutoScanConfig.org_id == org_id))
            if cfg is None:
                raise
        db.commit()
    return cfg


def update_config(
    db: Session, org_id: str,
    enabled: bool | None = None,
    interval_seconds: int | None = None,
    scan_subnet: bool | None = None,
) -> AutoScanConfig:
    cfg = get_config(db, org_id)
    if enabled is not None:
        cfg.enabled = enabled
    if interval_seconds is not None:
        cfg.interval_seconds = interval_seconds
    if scan_subnet is not None:
        cfg.scan_subnet = scan_subnet
    db.commit()
    return cfg


def config_out(db: Session, org_id: str, cfg: AutoScanConfig | None = None) -> AutoScanConfigOut:
    cfg = cfg or get_config(db, org_id)
    eligible = eligible_devices(db, org_id, cfg)
    scanned = db.scalars(
        select(NetworkDevice).where(
            NetworkDevice.org_id == org_id, NetworkDevice.last_scanned_at.isnot(None)
        )
    ).all()
    return AutoScanConfigOut(
        enabled=cfg.enabled,
        interval_seconds=cfg.interval_seconds,
        scan_subnet=cfg.scan_subnet,
        last_run_at=cfg.last_run_at,
        running=is_running(),
        eligible_count=len(eligible),
        scanned_count=len(scanned),
    )


# ── scope + round-robin ──────────────────────────────────────────────────────
def eligible_devices(db: Session, org_id: str, cfg: AutoScanConfig) -> list[NetworkDevice]:
    """Devices in scope for autonomous scanning, deterministically ordered.

    Default scope is THIS host only; the whole subnet is in scope only when
    `scan_subnet` (authorization) is enabled."""
    rows = db.scalars(
        select(NetworkDevice).where(
            NetworkDevice.org_id == org_id, NetworkDevice.online.is_(True)
        )
    ).all()
    if not cfg.scan_subnet:
        rows = [d for d in rows if d.is_self]  # host/localhost only, unauthorized subnet
    return sorted(rows, key=lambda d: d.ip)


def pick_next(devices: list[NetworkDevice], cursor: int) -> tuple[NetworkDevice, int]:
    idx = cursor % len(devices)
    return devices[idx], idx + 1


def run_once(db: Session, org_id: str, deep_scan_fn=None) -> dict:
    """Scan the next eligible device (round-robin). Returns a small summary.
    `deep_scan_fn` defaults to the real deep-scan service (mockable in tests)."""
    cfg = get_config(db, org_id)
    if not cfg.enabled:
        return {"scanned": False, "reason": "autoscan disabled"}
    devices = eligible_devices(db, org_id, cfg)
    if not devices:
        return {"scanned": False, "reason": "no eligible devices"}

    device, new_cursor = pick_next(devices, cfg.cursor)
    if deep_scan_fn is None:
        from app.services.deepscan import service as deepscan

        deep_scan_fn = deepscan.deep_scan

    available = None
    try:
        result = deep_scan_fn(db, org_id, device.ip, True)  # authorized in-scope device
        available = getattr(result, "available", None)
    except Exception as exc:  # a single device failing must not wedge the loop
        logger.warning("autoscan device %s failed: %s", device.ip, exc)

    device.last_scanned_at = utcnow()
    cfg.cursor = new_cursor
    cfg.last_run_at = utcnow()
    db.commit()
    return {"scanned": True, "ip": device.ip, "available": available, "cursor": new_cursor}


# ── background loop ──────────────────────────────────────────────────────────
def is_running() -> bool:
    return _running


def start() -> None:
    """Start the background scheduler task (idempotent). Called from app startup;
    skipped under pytest so tests never trigger a real nmap subprocess."""
    global _running
    if _running:
        return
    _running = True
    try:
        asyncio.get_event_loop().create_task(_loop())
    except RuntimeError:
        # no running loop yet (e.g. sync context) — schedule best-effort
        asyncio.ensure_future(_loop())
    logger.info("autoscan scheduler started (tick=%ss)", _TICK_SECONDS)


async def _loop() -> None:
    while _running:
        await asyncio.sleep(_TICK_SECONDS)
        try:
            await asyncio.to_thread(_run_due_orgs)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("autoscan tick failed: %s", exc)


def _run_due_orgs() -> None:
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        cfgs = db.scalars(select(AutoScanConfig).where(AutoScanConfig.enabled.is_(True))).all()
        now = utcnow()
        for cfg in cfgs:
            last_run = cfg.last_run_at
            if last_run and last_run.tzinfo is None:
                last_run = last_run.replace(tzinfo=now.tzinfo)
            due = last_run is None or (now - last_run).total_seconds() >= cfg.interval_seconds
            if due:
                run_once(db, cfg.org_id)
    finally:
        db.close()
