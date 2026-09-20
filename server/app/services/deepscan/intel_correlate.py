# Drishti v0.1 — defensive vuln-intel correlation | 20-Sep-2026
"""Correlate version-matched CVEs against CISA KEV, OSV, GHSA, and NVIDIA
product applicability.

This module NEVER invents a vulnerability. It only annotates CVE IDs that
already have sufficient product/version (or CPE+version) evidence from the
primary lookup. A KEV/OSV/GHSA outage degrades to "unannotated", not to a
fabricated finding.

HTTP seams (`fetch_kev_catalog`, `fetch_osv_vuln`) are monkeypatched in tests."""
from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger("drishti")

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"

_state_lock = threading.Lock()
_kev_ids: set[str] | None = None
_kev_fetched_at = 0.0
_KEV_TTL_S = 6 * 3600
_osv_cache: dict[str, dict] = {}


def fetch_kev_catalog(timeout: float) -> tuple[dict | None, str | None]:
    """GET the CISA Known Exploited Vulnerabilities catalog."""
    try:
        import httpx

        with httpx.Client(timeout=timeout) as client:
            resp = client.get(_KEV_URL)
        if resp.status_code != 200:
            return None, f"CISA KEV HTTP {resp.status_code}"
        return resp.json(), None
    except Exception as exc:
        return None, f"CISA KEV unreachable: {str(exc)[:120]}"


def fetch_osv_vuln(cve_id: str, timeout: float) -> tuple[dict | None, str | None]:
    """GET OSV's record for a CVE (aliases include GHSA ids when present)."""
    try:
        import httpx

        with httpx.Client(timeout=timeout) as client:
            resp = client.get(_OSV_VULN_URL.format(id=cve_id))
        if resp.status_code == 404:
            return {}, None  # OSV has no record — not an error, just no alias
        if resp.status_code != 200:
            return None, f"OSV HTTP {resp.status_code}"
        return resp.json(), None
    except Exception as exc:
        return None, f"OSV unreachable: {str(exc)[:120]}"


def _kev_set(timeout: float) -> set[str]:
    """Cached CISA KEV CVE-ID set. Empty on fetch failure (never guessed)."""
    global _kev_ids, _kev_fetched_at
    now = time.monotonic()
    with _state_lock:
        if _kev_ids is not None and (now - _kev_fetched_at) < _KEV_TTL_S:
            return _kev_ids
    payload, err = fetch_kev_catalog(timeout)
    ids: set[str] = set()
    if err is None:
        for item in (payload or {}).get("vulnerabilities") or []:
            cve_id = (item.get("cveID") or "").strip().upper()
            if cve_id.startswith("CVE-"):
                ids.add(cve_id)
    with _state_lock:
        _kev_ids = ids
        _kev_fetched_at = time.monotonic()
    return ids


def _osv_record(cve_id: str, timeout: float) -> dict:
    key = cve_id.upper()
    with _state_lock:
        if key in _osv_cache:
            return _osv_cache[key]
    payload, err = fetch_osv_vuln(key, timeout)
    rec = payload or {} if err is None else {}
    with _state_lock:
        _osv_cache[key] = rec
    return rec


def _ghsa_aliases(osv_rec: dict) -> list[str]:
    aliases = list(osv_rec.get("aliases") or [])
    if isinstance(osv_rec.get("id"), str):
        aliases.append(osv_rec["id"])
    out: list[str] = []
    seen: set[str] = set()
    for a in aliases:
        u = str(a).strip().upper()
        if u.startswith("GHSA-") and u not in seen:
            seen.add(u)
            out.append(str(a).strip())
    return out


def _nvidia_applicable(cve: dict, services: list[dict]) -> bool:
    """True only when the matched service itself is an NVIDIA product (CPE or
    product name). A random CVE is never tagged NVIDIA."""
    blob = " ".join(
        [
            (cve.get("affected_service") or ""),
            (cve.get("summary") or ""),
        ]
    ).lower()
    port = cve.get("port")
    for s in services:
        if port is not None and s.get("port") != port:
            continue
        cpe = (s.get("cpe") or "").lower()
        product = (s.get("product") or "").lower()
        if ":nvidia:" in cpe or "nvidia" in product:
            return True
    return "nvidia" in blob and any(
        ":nvidia:" in (s.get("cpe") or "").lower() or "nvidia" in (s.get("product") or "").lower()
        for s in services
    )


def enrich(cves: list[dict], services: list[dict], timeout: float = 8.0) -> list[dict]:
    """Annotate already-evidenced CVEs with KEV / OSV / GHSA / NVIDIA sources.

    Input CVEs must already be version-matched. This function does not add new
    CVE IDs from KEV (being on the KEV list without a product/version hit is
    not sufficient evidence that THIS device is affected)."""
    if not cves:
        return []
    kev = _kev_set(timeout)
    out: list[dict] = []
    for c in cves:
        cve_id = (c.get("id") or "").upper()
        sources = list(c.get("intel_sources") or ["nvd"])
        if "nvd" not in sources and not str(c.get("id") or "").upper().startswith("GHSA-"):
            sources.insert(0, "nvd")
        in_kev = cve_id in kev
        if in_kev and "cisa_kev" not in sources:
            sources.append("cisa_kev")
        osv_rec = _osv_record(cve_id, timeout) if cve_id.startswith("CVE-") else {}
        ghsa_ids = _ghsa_aliases(osv_rec)
        if osv_rec and "osv" not in sources:
            sources.append("osv")
        if ghsa_ids and "ghsa" not in sources:
            sources.append("ghsa")
        if _nvidia_applicable(c, services) and "nvidia" not in sources:
            sources.append("nvidia")
        out.append(
            {
                **c,
                "intel_sources": sources,
                "in_kev": in_kev,
                "ghsa_ids": ghsa_ids,
                "evidence_basis": c.get("evidence_basis") or "product_version",
            }
        )
    return out


def _reset_cache() -> None:
    """Test helper — clear KEV/OSV caches between cases."""
    global _kev_ids, _kev_fetched_at
    with _state_lock:
        _kev_ids = None
        _kev_fetched_at = 0.0
        _osv_cache.clear()
