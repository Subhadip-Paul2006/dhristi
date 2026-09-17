# Drishti v0.1 — real CVE lookup (NVD / Vulners) | 12-Jul-2026
"""Match real detected services against a REAL CVE source.

Default source is the free NVD REST API (no key required, just rate-limited);
Vulners is used instead when VULNERS_KEY is set. Every CVE returned here comes
from the live source — id, CVSS, severity and summary are the source's own
values. If the source can't be reached (offline, 403/429, timeout) the lookup
returns available:false and NO cves — it NEVER invents a CVE.

`fetch_nvd` / `fetch_vulners` are the HTTP seams; tests monkeypatch them so the
whole suite runs offline. Results are cached per (product, version) in-process
and calls are spaced out to respect NVD's free-tier rate limit."""
from __future__ import annotations

import logging
import threading
import time

from app.config import get_settings

logger = logging.getLogger("drishti")

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_VULNERS_URL = "https://vulners.com/api/v3/burp/software/"

# bound the work: distinct software lookups per scan, CVEs kept per service
_MAX_LOOKUPS = 8
_MAX_CVES_PER_SERVICE = 6

# in-process cache + polite spacing (module-level; not used inside the risk engine).
# `_state_lock` guards the cache / rate-limit / outage state so concurrent scans
# (e.g. a range sweep across threads) can't race past the NVD spacing or double
# up on a source that's already known to be down.
_cache: dict[tuple[str, str], list[dict]] = {}
_last_call_at = 0.0
_MIN_SPACING_S = 0.7  # NVD free tier: ~5 req / 30s → space calls out
_state_lock = threading.Lock()

# short-circuit a sustained source outage: after the first hard failure we cache
# the reason for a brief TTL so every remaining host doesn't re-hit (and re-wait
# on) a dead source sequentially.
_FAIL_TTL_S = 30.0
_fail_until = 0.0
_fail_reason: str | None = None


def _record_failure(reason: str) -> None:
    """Remember the first hard failure so subsequent lookups short-circuit."""
    global _fail_until, _fail_reason
    with _state_lock:
        _fail_until = time.monotonic() + _FAIL_TTL_S
        _fail_reason = reason


def _clear_failure() -> None:
    """A successful reach clears the outage short-circuit."""
    global _fail_until, _fail_reason
    with _state_lock:
        _fail_until = 0.0
        _fail_reason = None


def _severity_from_cvss(cvss: float) -> str:
    """CVSS v3 band mapping — only a FALLBACK when the source omits baseSeverity."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _exploitability_from(cvss: float, exploitability_score: float | None, score_max: float = 3.9) -> float:
    """Normalize the source's real exploitability to 0..1.

    NVD's `exploitabilityScore` sub-score ranges 0..3.9 for CVSS v3 but 0..10 for
    CVSS v2 — `score_max` carries the right denominator so a v2 sub-score isn't
    inflated. When absent, fall back to a scaled CVSS proxy. Rounded to 2dp to
    fit Numeric(3,2)."""
    if exploitability_score is not None and score_max > 0:
        return round(min(max(exploitability_score / score_max, 0.0), 1.0), 2)
    return round(min(max(cvss / 12.0, 0.05), 0.95), 2)


# ── HTTP seams (monkeypatched in tests) ──────────────────────────────────────
def fetch_nvd(product: str, version: str, timeout: float, api_key: str) -> tuple[dict | None, str | None]:
    """GET the NVD REST API. Returns (json, None) or (None, reason)."""
    keyword = f"{product} {version}".strip()
    params = {"keywordSearch": keyword, "resultsPerPage": 20}
    headers = {"apiKey": api_key} if api_key else {}
    try:
        import httpx

        with httpx.Client(timeout=timeout) as client:
            resp = client.get(_NVD_URL, params=params, headers=headers)
        if resp.status_code in (403, 429):
            return None, f"NVD rate-limited (HTTP {resp.status_code})"
        if resp.status_code != 200:
            return None, f"NVD HTTP {resp.status_code}"
        return resp.json(), None
    except Exception as exc:
        return None, f"NVD unreachable: {str(exc)[:120]}"


def fetch_nvd_cpe(cpe23: str, timeout: float, api_key: str) -> tuple[dict | None, str | None]:
    """GET NVD by CPE match string — precise product/version matching (no keyword
    noise). Returns (json, None) or (None, reason)."""
    params = {"virtualMatchString": cpe23, "resultsPerPage": 40}
    headers = {"apiKey": api_key} if api_key else {}
    try:
        import httpx

        with httpx.Client(timeout=timeout) as client:
            resp = client.get(_NVD_URL, params=params, headers=headers)
        if resp.status_code in (403, 429):
            return None, f"NVD rate-limited (HTTP {resp.status_code})"
        if resp.status_code != 200:
            return None, f"NVD HTTP {resp.status_code}"
        return resp.json(), None
    except Exception as exc:
        return None, f"NVD unreachable: {str(exc)[:120]}"


def fetch_vulners(product: str, version: str, timeout: float, api_key: str) -> tuple[dict | None, str | None]:
    """POST the Vulners software-match API. Returns (json, None) or (None, reason)."""
    body = {"software": product, "version": version, "type": "software", "apiKey": api_key}
    try:
        import httpx

        with httpx.Client(timeout=timeout) as client:
            resp = client.post(_VULNERS_URL, json=body)
        if resp.status_code in (403, 429):
            return None, f"Vulners rate-limited (HTTP {resp.status_code})"
        if resp.status_code != 200:
            return None, f"Vulners HTTP {resp.status_code}"
        return resp.json(), None
    except Exception as exc:
        return None, f"Vulners unreachable: {str(exc)[:120]}"


# ── parsers (pure) ───────────────────────────────────────────────────────────
def parse_nvd(payload: dict, affected: str, must_contain: str | None = None) -> list[dict]:
    """Extract structured CVEs from a real NVD 2.0 response — source values only.

    `must_contain` (used on the keyword fallback path) drops CVEs whose text
    doesn't mention the product token, cutting the noise a broad keyword search
    returns. CPE-matched results pass it as None (already precise)."""
    out: list[dict] = []
    token = (must_contain or "").lower().strip()
    for item in payload.get("vulnerabilities", []) or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        summary = ""
        for d in cve.get("descriptions", []) or []:
            if d.get("lang") == "en":
                summary = d.get("value", "")
                break
        if token and token not in summary.lower() and token not in cve_id.lower():
            continue  # keyword hit unrelated to this product → drop
        cvss, severity, expl_score, expl_max = _nvd_metrics(cve.get("metrics") or {})
        if cvss is None:
            continue  # no scored metric → don't guess a number
        out.append(
            {
                "id": cve_id,
                "cvss": round(float(cvss), 1),
                "severity": (severity or _severity_from_cvss(cvss)).lower(),
                "summary": summary[:600],
                "exploitability": _exploitability_from(cvss, expl_score, expl_max),
                "affected_service": affected,
            }
        )
    out.sort(key=lambda c: c["cvss"], reverse=True)
    return out[:_MAX_CVES_PER_SERVICE]


def _nvd_metrics(metrics: dict) -> tuple[float | None, str | None, float | None, float]:
    """Pull baseScore / baseSeverity / exploitabilityScore, preferring CVSS v3.1.

    Also returns the exploitability sub-score's max for the matched CVSS version
    (3.9 for v3, 10.0 for v2) so it can be normalized to 0..1 correctly."""
    for key, expl_max in (("cvssMetricV31", 3.9), ("cvssMetricV30", 3.9), ("cvssMetricV2", 10.0)):
        arr = metrics.get(key)
        if not arr:
            continue
        m = arr[0]
        data = m.get("cvssData") or {}
        base = data.get("baseScore")
        if base is None:
            continue
        severity = data.get("baseSeverity") or m.get("baseSeverity")
        return float(base), severity, m.get("exploitabilityScore"), expl_max
    return None, None, None, 3.9


def parse_vulners(payload: dict, affected: str) -> list[dict]:
    """Extract structured CVEs from a real Vulners response — source values only."""
    if payload.get("result") != "OK":
        return []
    out: list[dict] = []
    for entry in (payload.get("data") or {}).get("search", []) or []:
        src = entry.get("_source") or {}
        cve_id = src.get("id") or ""
        if not cve_id.upper().startswith("CVE-"):
            continue
        cvss = ((src.get("cvss") or {}).get("score")) or 0.0
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            continue
        if cvss <= 0:
            continue
        out.append(
            {
                "id": cve_id,
                "cvss": round(cvss, 1),
                "severity": _severity_from_cvss(cvss),
                "summary": (src.get("description") or "")[:600],
                "exploitability": _exploitability_from(cvss, None),
                "affected_service": affected,
            }
        )
    # dedupe by id, worst-first
    seen: set[str] = set()
    uniq = []
    for c in sorted(out, key=lambda c: c["cvss"], reverse=True):
        if c["id"] in seen:
            continue
        seen.add(c["id"])
        uniq.append(c)
    return uniq[:_MAX_CVES_PER_SERVICE]


# ── CPE helpers ──────────────────────────────────────────────────────────────
_GENERIC_TOKENS = {"db", "server", "http", "https", "public", "service", "daemon", "httpd"}


def _cpe23(cpe: str | None, version: str | None) -> str | None:
    """Build an NVD 2.3 match string from nmap's CPE (+ detected version).

    cpe:/a:postgresql:postgresql + 14.2 → cpe:2.3:a:postgresql:postgresql:14.2:*:*:*:*:*:*:*
    Returns None if the CPE has no concrete product to match on."""
    if not cpe:
        return None
    if cpe.startswith("cpe:/"):
        parts = cpe[len("cpe:/"):].split(":")
    elif cpe.startswith("cpe:2.3:"):
        parts = cpe[len("cpe:2.3:"):].split(":")
    else:
        return None
    part = parts[0] if parts and parts[0] else "a"
    vendor = parts[1] if len(parts) > 1 and parts[1] else "*"
    product = parts[2] if len(parts) > 2 and parts[2] else "*"
    if product == "*":
        return None  # nothing precise to match
    ver = "*"
    if version:
        v = version.strip().split(" ")[0]
        if v and all(ch.isalnum() or ch in ".-_+" for ch in v):
            ver = v
    return f"cpe:2.3:{part}:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"


def _product_token(product: str) -> str | None:
    """A single meaningful keyword from a product name, for noise-filtering the
    keyword fallback (e.g. 'PostgreSQL DB' → 'postgresql')."""
    for w in (product or "").replace("/", " ").split():
        t = "".join(ch for ch in w if ch.isalnum()).lower()
        if len(t) >= 3 and t not in _GENERIC_TOKENS:
            return t
    return None


# ── orchestration ────────────────────────────────────────────────────────────
def _lookup_one(product: str, version: str, cpe: str | None = None) -> tuple[list[dict] | None, str | None]:
    """One cached, rate-limited source lookup. Prefers precise CPE matching over
    a noisy keyword search. (cves, None) or (None, reason)."""
    key = (product.lower(), (version or "").lower(), (cpe or "").lower())
    with _state_lock:
        if key in _cache:
            return _cache[key], None
        # a recent hard failure short-circuits so a sustained outage doesn't
        # re-block every remaining host on the source timeout.
        if _fail_until and time.monotonic() < _fail_until:
            return None, _fail_reason or "CVE source unreachable"

    settings = get_settings()
    timeout = settings.deepscan_cve_timeout_seconds
    affected = f"{product} {version}".strip()

    def _space():
        # serialize the spacing gate across threads so concurrent scans still
        # respect NVD's minimum inter-call spacing.
        global _last_call_at
        with _state_lock:
            elapsed = time.monotonic() - _last_call_at
            if elapsed < _MIN_SPACING_S:
                time.sleep(_MIN_SPACING_S - elapsed)
            _last_call_at = time.monotonic()

    def _store(cves: list[dict]) -> None:
        with _state_lock:
            _cache[key] = cves

    if settings.vulners_key:
        _space()
        payload, err = fetch_vulners(product, version, timeout, settings.vulners_key)
        if err is not None:
            _record_failure(err)
            return None, err
        _clear_failure()
        cves = parse_vulners(payload or {}, affected)
        _store(cves)
        return cves, None

    cpe23 = _cpe23(cpe, version)
    if cpe23:
        # precise: match the exact product (+ version if known) by CPE
        _space()
        payload, err = fetch_nvd_cpe(cpe23, timeout, settings.nvd_api_key)
        if err is not None:
            _record_failure(err)
            return None, err
        _clear_failure()
        cves = parse_nvd(payload or {}, affected)
        # version-pinned CPE found nothing → widen to the product across all versions
        if not cves and version:
            wide = _cpe23(cpe, None)
            if wide and wide != cpe23:
                _space()
                payload2, err2 = fetch_nvd_cpe(wide, timeout, settings.nvd_api_key)
                if err2 is None:
                    cves = parse_nvd(payload2 or {}, affected)
        _store(cves)
        return cves, None

    # no CPE → keyword search, filtered to the product token to cut noise
    _space()
    payload, err = fetch_nvd(product, version, timeout, settings.nvd_api_key)
    if err is not None:
        _record_failure(err)
        return None, err
    _clear_failure()
    cves = parse_nvd(payload or {}, affected, must_contain=_product_token(product))
    _store(cves)
    return cves, None


def lookup_for_services(services: list[dict]) -> dict:
    """Match a list of detected services to real CVEs.

    Returns {available, reason, cves}. available is False only when NO lookup
    could reach the source at all (offline / rate-limited) — an empty `cves`
    with available:true truthfully means 'no known CVEs matched', which the UI
    renders differently from 'lookup unavailable'."""
    # software we can identify by a CPE or a product name
    candidates = [
        s for s in services if (s.get("cpe") or "").strip() or (s.get("product") or "").strip()
    ][:_MAX_LOOKUPS]
    if not candidates:
        return {"available": True, "reason": None, "cves": []}

    all_cves: list[dict] = []
    reached_any = False
    last_reason: str | None = None
    seen_ids: set[str] = set()
    for s in candidates:
        cves, reason = _lookup_one(s.get("product") or "", s.get("version") or "", s.get("cpe"))
        if reason is not None:
            last_reason = reason
            continue
        reached_any = True
        for c in cves or []:
            if c["id"] in seen_ids:
                continue
            seen_ids.add(c["id"])
            # remember which detected port/service this came from
            c = {**c, "port": s.get("port"), "protocol": s.get("protocol")}
            all_cves.append(c)

    if not reached_any:
        return {"available": False, "reason": last_reason or "CVE source unreachable", "cves": []}
    all_cves.sort(key=lambda c: c["cvss"], reverse=True)
    return {"available": True, "reason": None, "cves": all_cves}


def _reset_cache() -> None:
    """Test helper — clear the module cache/rate-limit state between cases."""
    global _last_call_at, _fail_until, _fail_reason
    with _state_lock:
        _cache.clear()
        _last_call_at = 0.0
        _fail_until = 0.0
        _fail_reason = None
