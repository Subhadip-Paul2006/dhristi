# Drishti v0.1 — WHOIS domain lookup | 11-Jul-2026
"""Best-effort WHOIS domain facts via the optional `python-whois` library.

Guarded on every axis: if the library isn't installed, or the network is
blocked, or the registry returns nothing usable, this returns None and the
caller marks domain age "unknown" — it never guesses an age or registrar.
"""
from __future__ import annotations

from datetime import datetime, timezone


def _first(value, latest=False):
    """WHOIS fields are often a list of dates. Take the earliest real datetime
    (creation dates), or the latest one when latest=True (expiration dates —
    the furthest-out expiry is the domain's real end-of-life, not the nearest)."""
    if isinstance(value, (list, tuple)):
        dates = [v for v in value if isinstance(v, datetime)]
        if not dates:
            return None
        return max(dates) if latest else min(dates)
    return value if isinstance(value, datetime) else None


def domain_facts(host: str) -> dict | None:
    try:
        import whois  # python-whois
    except Exception:
        return None

    try:
        # python-whois enables WHOIS_RECURSE by default and blindly follows a
        # "Whois Server:" referral from the reply to a second raw socket
        # connection with no host validation — an independent SSRF path.
        # WHOIS_QUICK suppresses that auto-recursion (see
        # NICClient.whois_lookup), so pass it explicitly rather than relying
        # on the library's default.
        record = whois.whois(host, flags=whois.NICClient.WHOIS_QUICK)
    except Exception:
        return None

    if not record:
        return None

    created = _first(record.get("creation_date") if hasattr(record, "get") else record.creation_date)
    expires = _first(record.get("expiration_date") if hasattr(record, "get") else record.expiration_date, latest=True)
    registrar = record.get("registrar") if hasattr(record, "get") else getattr(record, "registrar", None)
    if isinstance(registrar, (list, tuple)):
        registrar = registrar[0] if registrar else None

    age_days = None
    if isinstance(created, datetime):
        created_utc = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created_utc).days
        if age_days < 0:
            age_days = None

    if age_days is None and not registrar:
        return None  # nothing usable — treat as unknown
    return {
        "age_days": age_days,
        "registrar": str(registrar) if registrar else None,
        "created": created.date().isoformat() if isinstance(created, datetime) else None,
        "expires": expires.date().isoformat() if isinstance(expires, datetime) else None,
    }
