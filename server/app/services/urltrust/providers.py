# Drishti v0.1 — pluggable reputation providers | 11-Jul-2026
"""Pluggable reputation providers. Each is OPTIONAL and only runs if its key is
configured. A not-configured or unreachable provider returns a shape that the
analyzer turns into a signal that contributes NOTHING to the score — never a
fabricated verdict.
"""
from __future__ import annotations

import base64
import time
from collections import OrderedDict

from app.config import get_settings

_SB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_VT_URL = "https://www.virustotal.com/api/v3/urls/{id}"


def safe_browsing_configured() -> bool:
    return bool(get_settings().google_safe_browsing_key)


def virustotal_configured() -> bool:
    return bool(get_settings().virustotal_key)

# Hard cap on cached entries so a stream of distinct URLs can't grow the cache
# without bound; least-recently-used keys are evicted past this size.
_CACHE_MAX_ENTRIES = 2048


def _is_cacheable(val) -> bool:
    """Only definitive successes are safe to memoize: a configured provider that
    returned an actual verdict. Everything transient — {configured:False} (key
    may be added later), rate limits (429), timeouts, 5xx, and "no report yet"
    (404) — carries an "error" key or configured:False and must be re-tried on
    the next call rather than served stale from the cache."""
    return isinstance(val, dict) and val.get("configured") is True and not val.get("error")


def ttl_cache(ttl_seconds=3600, max_entries=_CACHE_MAX_ENTRIES):
    cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
    def decorator(func):
        def wrapper(url: str):
            now = time.time()
            hit = cache.get(url)
            if hit is not None:
                cached_time, cached_val = hit
                if now - cached_time < ttl_seconds:
                    cache.move_to_end(url)  # mark most-recently-used
                    return cached_val
                del cache[url]  # expired — drop and re-fetch
            val = func(url)
            if _is_cacheable(val):
                cache[url] = (now, val)
                cache.move_to_end(url)
                while len(cache) > max_entries:
                    cache.popitem(last=False)  # evict least-recently-used
            return val
        return wrapper
    return decorator


@ttl_cache(ttl_seconds=3600)
def safe_browsing(url: str) -> dict:
    """Google Safe Browsing v4 threatMatches lookup.

    Returns {configured:false} with no key. With a key:
    {configured:true, verdict:"clean"|"flagged", threats:[...]} or
    {configured:true, error:"..."} if the call could not complete.
    """
    settings = get_settings()
    if not settings.google_safe_browsing_key:
        return {"configured": False}

    body = {
        "client": {"clientId": "drishti", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        import httpx

        with httpx.Client(timeout=settings.urltrust_timeout_seconds) as client:
            resp = client.post(
                _SB_URL, params={"key": settings.google_safe_browsing_key}, json=body
            )
        if resp.status_code != 200:
            return {"configured": True, "error": f"HTTP {resp.status_code}"}
        matches = resp.json().get("matches") or []
    except Exception as exc:
        return {"configured": True, "error": _short(str(exc))}

    if not matches:
        return {"configured": True, "verdict": "clean", "threats": []}
    threats = sorted({m.get("threatType", "THREAT") for m in matches})
    return {"configured": True, "verdict": "flagged", "threats": threats}


@ttl_cache(ttl_seconds=3600)
def virustotal(url: str) -> dict:
    """VirusTotal v3 URL report.

    Returns {configured:false} with no key. With a key:
    {configured:true, malicious, suspicious, harmless, reputation} or
    {configured:true, error:"..."} if there is no report / the call failed.
    """
    settings = get_settings()
    if not settings.virustotal_key:
        return {"configured": False}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        import httpx

        with httpx.Client(timeout=settings.urltrust_timeout_seconds) as client:
            resp = client.get(
                _VT_URL.format(id=url_id),
                headers={"x-apikey": settings.virustotal_key},
            )
        if resp.status_code == 404:
            return {"configured": True, "error": "No VirusTotal report yet for this URL"}
        if resp.status_code != 200:
            return {"configured": True, "error": f"HTTP {resp.status_code}"}
        attrs = resp.json().get("data", {}).get("attributes", {})
    except Exception as exc:
        return {"configured": True, "error": _short(str(exc))}

    stats = attrs.get("last_analysis_stats") or {}
    return {
        "configured": True,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "reputation": attrs.get("reputation"),
    }


def _short(msg: str, limit: int = 120) -> str:
    return " ".join(msg.split())[:limit]
