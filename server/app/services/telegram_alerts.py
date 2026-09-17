# Drishti v0.1 — Telegram alert dispatcher | 12-Aug-2026
"""Background service: every N seconds scan for high/critical findings and
active network threats, then fire a Telegram message for each new one.

Defensive scope: outbound NOTIFICATION only. No inbound listener, no webhook.
All secrets come from env vars via Settings.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

import urllib.error
import urllib.parse
import urllib.request

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AssetVulnerability, LiveObservation, NetworkDevice, Vulnerability
from app.services.live_threats import detect_threats, DeviceView, DomainView
from app.db import SessionLocal

logger = logging.getLogger("drishti")

_TICK_SECONDS = 30
_running = False
_thread: threading.Thread | None = None

# dedup: track (type, id) pairs we have already alerted about
_alerted: set[tuple[str, str]] = set()


# — Telegram helpers —
def _send_telegram(bot_token: str, chat_id: str, text: str) -> None:
    """Fire a message via the Telegram Bot API (sendMessage)."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = (
        f"chat_id={chat_id}&text={urllib.parse.quote(text)}"
        "&parse_mode=Markdown&disable_web_page_preview=true"
    ).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.HTTPError as exc:
        logger.error("telegram HTTP %s: %s", exc.code, exc.read().decode()[:200])
    except (urllib.error.URLError, OSError) as exc:
        logger.error("telegram send failed: %s", exc)


def _ist_timestamp(dt: datetime | None = None) -> str:
    """Format datetime in Indian Standard Time (Asia/Kolkata, UTC+5:30)."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        from zoneinfo import ZoneInfo
        ist_dt = dt.astimezone(ZoneInfo("Asia/Kolkata"))
    except Exception:
        ist_dt = dt.astimezone(timezone(timedelta(hours=5, minutes=30)))
    return ist_dt.strftime("%d-%b-%Y %I:%M:%S %p IST")


def _format_finding_alert(f) -> str:
    sev = f.vulnerability.severity.upper() if f.vulnerability and f.vulnerability.severity else "HIGH"
    title = f.vulnerability.title if f.vulnerability else "Unknown vulnerability"
    asset = f.asset.hostname if f.asset and f.asset.hostname else (f.asset.ip if f.asset else f.asset_id[:8])
    cve = f.vulnerability.cve_id if f.vulnerability and f.vulnerability.cve_id else "N/A"
    detected_time = _ist_timestamp(getattr(f, "detected_at", None))
    return (
        f"🚨 *[DRISHTI ALERT — {sev}]*\n"
        f"*{title}*\n\n"
        f"• *Asset:* `{asset}`\n"
        f"• *CVE:* `{cve}`\n"
        f"• *Status:* `{f.status}`\n"
        f"• *Time:* `{detected_time}`\n\n"
        f"🛡️ _Drishti Cyber Threat Intelligence_"
    )


def _format_threat_alert(t) -> str:
    emoji = "🚨" if t.severity in ("critical", "high") else "⚠️"
    kind = t.kind.replace("_", " ").title()
    alert_time = _ist_timestamp(getattr(t, "last_seen", None))
    return (
        f"{emoji} *[DRISHTI NETWORK THREAT — {t.severity.upper()}]*\n"
        f"*{kind}: {t.title}*\n\n"
        f"• *Detail:* {t.detail}\n"
        f"• *MITRE ATT&CK:* `{t.mitre or 'N/A'}`\n"
        f"• *Time:* `{alert_time}`\n\n"
        f"🛡️ _Drishti Live Watcher_"
    )


# — scan cycle —
def _scan(db: Session, bot_token: str, chat_id: str) -> None:
    """One scan tick: query open high/critical findings + active threats,
    send Telegram alerts for anything new."""
    org_ids: list[str] = [
        r[0] for r in db.execute(select(AssetVulnerability.org_id).distinct()).all()
    ]
    if not org_ids:
        return

    now = datetime.now(timezone.utc)

    for org_id in org_ids:
        # 1. Open high / critical findings
        findings = db.scalars(
            select(AssetVulnerability)
            .join(Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
            .where(
                AssetVulnerability.org_id == org_id,
                AssetVulnerability.status == "open",
                Vulnerability.severity.in_(["high", "critical"]),
            )
            .order_by(AssetVulnerability.detected_at.desc())
        ).all()

        for f in findings:
            key = ("finding", f.id)
            if key in _alerted:
                continue
            try:
                _send_telegram(bot_token, chat_id, _format_finding_alert(f))
                _alerted.add(key)
            except Exception:
                logger.exception("failed to alert finding %s", f.id)

        # 2. Active network threats
        since = now - timedelta(minutes=5)
        rows = db.scalars(
            select(NetworkDevice).where(
                NetworkDevice.org_id == org_id,
                NetworkDevice.last_seen >= since,
            )
        ).all()

        ports_by_ip: dict[str, list[int]] = {}
        from app.services.live import _deepscan_ports_by_ip, _scan_status

        scanned_ips, _ = _scan_status(db, org_id)
        ports_by_ip = _deepscan_ports_by_ip(db, org_id)

        devices = []
        for r in rows:
            scanned = r.ip in scanned_ips or r.last_scanned_at is not None
            devices.append(
                DeviceView(
                    ip=r.ip,
                    mac=r.mac,
                    hostname=r.hostname,
                    is_gateway=r.is_gateway,
                    is_self=r.is_self,
                    online=r.online,
                    first_seen=r.first_seen,
                    last_seen=r.last_seen,
                    scanned=scanned,
                    vuln_count=None,
                    worst_severity=None,
                    open_ports=ports_by_ip.get(r.ip, []),
                )
            )

        threat_rows = db.scalars(
            select(LiveObservation).where(
                LiveObservation.org_id == org_id,
                LiveObservation.last_seen >= since,
            )
        ).all()
        
        domains = [
            DomainView(
                id=t.id,
                domain=t.domain,
                band=t.band,
                score=float(t.score),
                source_host=t.source_host,
                reasons=(
                    t.verdict_json.get("reasons", [])
                    if isinstance(t.verdict_json, dict)
                    else []
                ),
            )
            for t in threat_rows
        ]

        threats = detect_threats(devices, domains, now)

        for t in threats:
            key = ("threat", t.id)
            if key in _alerted:
                continue
            try:
                _send_telegram(bot_token, chat_id, _format_threat_alert(t))
                _alerted.add(key)
            except Exception:
                logger.exception("failed to alert threat %s", t.id)


# — public control —
def is_running() -> bool:
    return _running


def start() -> None:
    """Start the background ticker (called from app lifespan)."""
    global _running, _thread
    if _running:
        return

    from app.config import get_settings

    s = get_settings()
    if not s.telegram_bot_token or not s.telegram_chat_id:
        logger.info(
            "Telegram alerts disabled (no bot token / chat id configured)"
        )
        return

    _running = True

    def _loop() -> None:
        # wait a few seconds so the DB is fully ready after boot
        time.sleep(5)
        bot_token = s.telegram_bot_token
        chat_id = s.telegram_chat_id
        while _running:
            try:
                db = SessionLocal()
                try:
                    _scan(db, bot_token, chat_id)
                finally:
                    db.close()
            except Exception:
                logger.exception("telegram scan cycle failed")
            time.sleep(_TICK_SECONDS)

    _thread = threading.Thread(target=_loop, daemon=True, name="telegram-alerts")
    _thread.start()
    logger.info("Telegram alert service started (tick=%ds)", _TICK_SECONDS)


def stop() -> None:
    """Stop the background ticker."""
    global _running
    _running = False
