# Drishti v0.1 — Telegram alert dispatcher | 12-Aug-2026
"""Background service: every N seconds scan for high/critical findings and
active network threats, then fire a Telegram message for each new one.

Defensive scope: outbound NOTIFICATION only. No inbound listener, no webhook.
All secrets come from env vars via Settings.
"""
from __future__ import annotations

import html
import json
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
_initial_scan_done = False

# dedup: track (type, id) pairs we have already alerted about
_alerted: set[tuple[str, str]] = set()


# — Telegram helpers —
def _get_chat_ids(chat_id_conf: str) -> list[str]:
    """Parse single or comma-separated chat IDs."""
    if not chat_id_conf:
        return []
    return [c.strip() for c in chat_id_conf.split(",") if c.strip()]


import subprocess
import httpx


def _send_telegram(bot_token: str, chat_id: str, html_text: str, plain_text: str | None = None) -> bool:
    """Fire a message via the Telegram Bot API (sendMessage).
    Uses curl.exe on Windows for native SChannel TLS renegotiation support,
    with httpx as fallback. Returns True if successfully delivered, False otherwise.
    """
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": html_text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    # 1. Primary: Windows native curl.exe with SChannel TLS via stdin pipe
    try:
        data_json = json.dumps(payload)
        proc = subprocess.run(
            ["curl.exe", "-sS", "--max-time", "12", "-X", "POST", url, "-H", "Content-Type: application/json", "-d", "@-"],
            input=data_json,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode == 0 and proc.stdout:
            res = json.loads(proc.stdout)
            if res.get("ok"):
                return True
            if res.get("error_code") == 400 and plain_text:
                fb_payload = json.dumps({
                    "chat_id": chat_id,
                    "text": plain_text,
                    "disable_web_page_preview": True,
                })
                fb_proc = subprocess.run(
                    ["curl.exe", "-sS", "--max-time", "12", "-X", "POST", url, "-H", "Content-Type: application/json", "-d", "@-"],
                    input=fb_payload,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if fb_proc.returncode == 0 and fb_proc.stdout:
                    fb_res = json.loads(fb_proc.stdout)
                    return bool(fb_res.get("ok"))
    except Exception as exc:
        logger.debug("curl dispatch attempt failed: %s, falling back to httpx", exc)

    # 2. Fallback: httpx
    try:
        resp = httpx.post(url, json=payload, timeout=12.0)
        data = resp.json()
        if resp.status_code == 200 and data.get("ok"):
            return True

        if resp.status_code == 429:
            retry_after = data.get("parameters", {}).get("retry_after", 5)
            logger.warning("telegram rate limited, retry after %ds", retry_after)
            time.sleep(min(retry_after, 30))
            return False

        if resp.status_code == 400 and plain_text:
            fb_payload = {
                "chat_id": chat_id,
                "text": plain_text,
                "disable_web_page_preview": True,
            }
            fb_resp = httpx.post(url, json=fb_payload, timeout=12.0)
            fb_data = fb_resp.json()
            return bool(fb_resp.status_code == 200 and fb_data.get("ok"))

        logger.error("telegram HTTP %s: %s", resp.status_code, resp.text[:200])
        return False
    except Exception as exc:
        logger.error("telegram send failed: %s", exc)
        return False


def _dispatch_alert(bot_token: str, chat_id_conf: str, html_text: str, plain_text: str | None = None) -> bool:
    """Send alert to all configured chat IDs. Returns True if delivered to at least one."""
    chat_ids = _get_chat_ids(chat_id_conf)
    if not chat_ids:
        return False
    any_success = False
    for cid in chat_ids:
        ok = _send_telegram(bot_token, cid, html_text, plain_text)
        if ok:
            any_success = True
        time.sleep(0.5)  # Telegram per-chat rate safety
    return any_success


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


def _format_finding_alert(f) -> tuple[str, str]:
    """Returns (html_message, plain_text_fallback)."""
    sev = f.vulnerability.severity.upper() if f.vulnerability and f.vulnerability.severity else "HIGH"
    title = f.vulnerability.title if f.vulnerability else "Unknown vulnerability"
    asset = f.asset.hostname if f.asset and f.asset.hostname else (f.asset.ip if f.asset else f.asset_id[:8])
    cve = f.vulnerability.cve_id if f.vulnerability and f.vulnerability.cve_id else "N/A"
    detected_time = _ist_timestamp(getattr(f, "detected_at", None))
    status_str = str(f.status)

    html_msg = (
        f"🚨 <b>[DRISHTI ALERT — {html.escape(sev)}]</b>\n"
        f"<b>{html.escape(title)}</b>\n\n"
        f"• <b>Asset:</b> <code>{html.escape(asset)}</code>\n"
        f"• <b>CVE:</b> <code>{html.escape(cve)}</code>\n"
        f"• <b>Status:</b> <code>{html.escape(status_str)}</code>\n"
        f"• <b>Time:</b> <code>{html.escape(detected_time)}</code>\n\n"
        f"🛡️ <i>Drishti Cyber Threat Intelligence</i>"
    )

    plain_msg = (
        f"[DRISHTI ALERT — {sev}]\n"
        f"{title}\n\n"
        f"• Asset: {asset}\n"
        f"• CVE: {cve}\n"
        f"• Status: {status_str}\n"
        f"• Time: {detected_time}\n\n"
        f"Drishti Cyber Threat Intelligence"
    )
    return html_msg, plain_msg


def _format_threat_alert(t) -> tuple[str, str]:
    """Returns (html_message, plain_text_fallback)."""
    emoji = "🚨" if t.severity in ("critical", "high") else "⚠️"
    kind = t.kind.replace("_", " ").title()
    alert_time = _ist_timestamp(getattr(t, "last_seen", None))
    mitre = t.mitre or "N/A"
    sev = t.severity.upper()

    html_msg = (
        f"{emoji} <b>[DRISHTI NETWORK THREAT — {html.escape(sev)}]</b>\n"
        f"<b>{html.escape(kind)}: {html.escape(t.title)}</b>\n\n"
        f"• <b>Detail:</b> {html.escape(t.detail)}\n"
        f"• <b>MITRE ATT&CK:</b> <code>{html.escape(mitre)}</code>\n"
        f"• <b>Time:</b> <code>{html.escape(alert_time)}</code>\n\n"
        f"🛡️ <i>Drishti Live Watcher</i>"
    )

    plain_msg = (
        f"[DRISHTI NETWORK THREAT — {sev}]\n"
        f"{kind}: {t.title}\n\n"
        f"• Detail: {t.detail}\n"
        f"• MITRE ATT&CK: {mitre}\n"
        f"• Time: {alert_time}\n\n"
        f"Drishti Live Watcher"
    )
    return html_msg, plain_msg


# — scan cycle —
def _scan(db: Session, bot_token: str, chat_id_conf: str) -> None:
    """One scan tick: query open high/critical findings + active threats,
    send Telegram alerts for anything new."""
    global _initial_scan_done
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

        # On initial boot tick, mark pre-existing findings older than 15 mins
        # as already acknowledged so dev server reloads don't blast 90+ old alerts
        if not _initial_scan_done:
            recent_cutoff = now - timedelta(minutes=15)
            for f in findings:
                f_time = f.detected_at.replace(tzinfo=timezone.utc) if f.detected_at and f.detected_at.tzinfo is None else f.detected_at
                if f_time and f_time < recent_cutoff:
                    _alerted.add(("finding", f.id))

        for f in findings:
            key = ("finding", f.id)
            if key in _alerted:
                continue
            try:
                html_msg, plain_msg = _format_finding_alert(f)
                if _dispatch_alert(bot_token, chat_id_conf, html_msg, plain_msg):
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
                html_msg, plain_msg = _format_threat_alert(t)
                if _dispatch_alert(bot_token, chat_id_conf, html_msg, plain_msg):
                    _alerted.add(key)
            except Exception:
                logger.exception("failed to alert threat %s", t.id)

    _initial_scan_done = True


# — public control & diagnostics —
def is_running() -> bool:
    return _running


def get_status() -> dict:
    from app.config import get_settings
    s = get_settings()
    configured = bool(s.telegram_bot_token and s.telegram_chat_id)
    chat_ids = _get_chat_ids(s.telegram_chat_id)
    return {
        "configured": configured,
        "running": _running,
        "chat_ids_count": len(chat_ids),
        "chat_ids_masked": [f"{cid[:3]}***{cid[-2:]}" if len(cid) > 5 else cid for cid in chat_ids],
        "alerted_count": len(_alerted),
    }


def send_test_alert(custom_text: str | None = None) -> dict:
    from app.config import get_settings
    s = get_settings()
    if not s.telegram_bot_token or not s.telegram_chat_id:
        return {"success": False, "error": "Telegram bot token or chat ID is not configured."}

    chat_ids = _get_chat_ids(s.telegram_chat_id)
    ts = _ist_timestamp()
    html_msg = (
        f"🧪 <b>[DRISHTI SYSTEM DIAGNOSTIC]</b>\n"
        f"<b>Telegram Alert Subsystem Test</b>\n\n"
        f"• <b>Status:</b> <code>Active & Operational</code>\n"
        f"• <b>Time:</b> <code>{html.escape(ts)}</code>\n"
        f"• <b>Notes:</b> <code>{html.escape(custom_text or 'Manual verification triggered successfully.')}</code>\n\n"
        f"🛡️ <i>Drishti Security Engine</i>"
    )
    plain_msg = (
        f"[DRISHTI SYSTEM DIAGNOSTIC]\n"
        f"Telegram Alert Subsystem Test\n\n"
        f"• Status: Active & Operational\n"
        f"• Time: {ts}\n"
        f"• Notes: {custom_text or 'Manual verification triggered successfully.'}\n\n"
        f"Drishti Security Engine"
    )

    results = []
    for cid in chat_ids:
        ok = _send_telegram(s.telegram_bot_token, cid, html_msg, plain_msg)
        results.append({"chat_id": cid, "delivered": ok})
        time.sleep(0.5)

    any_ok = any(r["delivered"] for r in results)
    return {"success": any_ok, "results": results}


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
