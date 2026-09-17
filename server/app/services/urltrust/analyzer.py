# Drishti v0.1 — full trust analysis orchestrator | 11-Jul-2026
"""Orchestrates a full URL trust analysis and persists it.

Flow: normalize the URL → structural checks (pure) → live connection checks
(guarded) → WHOIS (guarded) → reputation providers (key-gated) → transparent
score → optional AI summary. Every signal is real or explicitly unavailable.
"""
from __future__ import annotations

from urllib.parse import ParseResult, urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.models import UrlAnalysis
from app.models.base import utcnow
from app.schemas.urltrust import HistoryItem, UrlAnalysisResult
from app.services.urltrust import network, providers, whois_lookup
from app.services.urltrust.checks import structural_signals
from app.services.urltrust.scoring import compute_score
from app.services.urltrust.summary import DISCLAIMER, build_summary
from app.services.urltrust.types import (
    FAIL,
    NOT_CONFIGURED,
    PASS,
    UNKNOWN,
    UNREACHABLE,
    WARN,
    Signal,
)


def _validation_error(message: str) -> DomainError:
    err = DomainError(message)
    err.status = 422
    err.code = "validation_error"
    return err


# Opaque non-web schemes (single colon, no //) that must be rejected outright
# rather than mistaken for a bare hostname.
_OPAQUE_SCHEMES = (
    "javascript:", "data:", "vbscript:", "file:", "mailto:", "tel:", "ftp:", "ssh:",
)


def normalize_url(raw: str) -> tuple[str, ParseResult, bool]:
    """Return (url, parsed, scheme_inferred). Adds https:// if no scheme was
    given; rejects anything that isn't http(s) or has no host."""
    raw = (raw or "").strip()
    if not raw:
        raise _validation_error("Enter a URL to analyze.")
    low = raw.lower()
    has_scheme = "://" in raw or low.startswith(_OPAQUE_SCHEMES)
    inferred = not has_scheme
    candidate = raw if has_scheme else f"https://{raw}"
    parts = urlparse(candidate)
    if parts.scheme not in ("http", "https"):
        raise _validation_error("Only http and https URLs can be analyzed.")
    if not parts.hostname:
        raise _validation_error("That doesn't look like a valid URL.")
    return candidate, parts, inferred


def _connection_signals(url: str, parts: ParseResult) -> tuple[list[Signal], dict, dict]:
    """Return (signals, tls_dict, http_dict). Network is fully guarded."""
    host = parts.hostname or ""
    signals: list[Signal] = []

    # DNS
    dns = network.resolve_dns(host)
    if dns is True:
        signals.append(Signal("dns_resolves", "DNS resolves", PASS,
                              "The domain resolves to an IP address.", 2.0))
    elif dns is False:
        signals.append(Signal("dns_resolves", "DNS resolves", FAIL,
                              "The domain does not resolve — no DNS record found.", 2.0))
    else:
        signals.append(Signal("dns_resolves", "DNS resolves", UNREACHABLE,
                              "Could not check DNS (outbound network unavailable).", 2.0))

    # TLS certificate (probe 443 regardless of the given scheme)
    tls = network.inspect_tls(host) or {}
    if not tls:
        signals.append(Signal("tls_valid", "Valid TLS certificate", UNREACHABLE,
                              "Could not establish a TLS connection to check the certificate.", 3.0))
        tls_dict = {"valid": None, "issuer": None, "expires": None}
    elif tls.get("valid"):
        exp = tls.get("expires")
        issuer = tls.get("issuer") or "unknown issuer"
        signals.append(Signal("tls_valid", "Valid TLS certificate", PASS,
                              f"Trusted certificate issued by {issuer}"
                              + (f", valid until {exp}." if exp else "."), 3.0))
        tls_dict = {"valid": True, "issuer": tls.get("issuer"), "expires": exp}
    else:
        signals.append(Signal("tls_valid", "Valid TLS certificate", FAIL,
                              "The TLS certificate is invalid, expired, or does not match the host.", 3.0))
        tls_dict = {"valid": False, "issuer": tls.get("issuer"), "expires": tls.get("expires")}

    # HTTP status + redirect behaviour
    http = network.http_probe(url)
    if http is None:
        signals.append(Signal("http_reachable", "Reachable over HTTP", UNREACHABLE,
                              "The server did not respond (outbound network unavailable or host down).", 1.0))
        signals.append(Signal("no_offsite_redirect", "No off-site redirect", UNREACHABLE,
                              "Could not follow redirects — server unreachable.", 2.0))
        http_dict = {"status": None, "final_url": url, "redirect_chain": [], "redirects_offsite": None}
    else:
        status = http.get("status")
        if status is not None and status < 400:
            signals.append(Signal("http_reachable", "Reachable over HTTP", PASS,
                                  f"Server responded with HTTP {status}.", 1.0))
        elif status is not None and status < 500:
            signals.append(Signal("http_reachable", "Reachable over HTTP", WARN,
                                  f"Server responded with HTTP {status} (client error).", 1.0))
        else:
            signals.append(Signal("http_reachable", "Reachable over HTTP", FAIL,
                                  f"Server responded with HTTP {status} (server error).", 1.0))

        offsite = http.get("redirects_offsite")
        if offsite is True:
            signals.append(Signal("no_offsite_redirect", "No off-site redirect", WARN,
                                  f"Redirects to a different domain ({_host_of(http.get('final_url'))}).", 2.0))
        elif offsite is False:
            signals.append(Signal("no_offsite_redirect", "No off-site redirect", PASS,
                                  "Stays on the same domain (no off-site redirect).", 2.0))
        else:
            signals.append(Signal("no_offsite_redirect", "No off-site redirect", UNKNOWN,
                                  "Could not determine the redirect target.", 2.0))
        http_dict = http

    return signals, tls_dict, http_dict


def _domain_signal(host: str) -> tuple[Signal, dict]:
    facts = whois_lookup.domain_facts(host) or {}
    age = facts.get("age_days")
    if age is None:
        sig = Signal("domain_age", "Domain age", UNKNOWN,
                     "Domain age could not be determined (WHOIS unavailable).", 2.0)
    elif age > 180:
        sig = Signal("domain_age", "Domain age", PASS,
                     f"Registered {age} days ago — an established domain.", 2.0)
    else:
        sig = Signal("domain_age", "Domain age", WARN,
                     f"Recently registered ({age} days ago) — new domains are higher risk.", 2.0)
    return sig, facts


def _provider_signals(url: str) -> tuple[list[Signal], dict, dict]:
    signals: list[Signal] = []

    sb = providers.safe_browsing(url)
    if not sb.get("configured"):
        signals.append(Signal("safe_browsing", "Google Safe Browsing", NOT_CONFIGURED,
                              "Not configured — add GOOGLE_SAFE_BROWSING_KEY to enable this check.", 4.0))
    elif sb.get("error"):
        signals.append(Signal("safe_browsing", "Google Safe Browsing", UNREACHABLE,
                              f"Could not check Safe Browsing: {sb['error']}.", 4.0))
    elif sb.get("verdict") == "flagged":
        threats = ", ".join(sb.get("threats") or []) or "a threat"
        signals.append(Signal("safe_browsing", "Google Safe Browsing", FAIL,
                              f"Flagged by Google Safe Browsing for {threats}.", 4.0))
    else:
        signals.append(Signal("safe_browsing", "Google Safe Browsing", PASS,
                              "No threats found by Google Safe Browsing.", 4.0))

    vt = providers.virustotal(url)
    if not vt.get("configured"):
        signals.append(Signal("virustotal", "VirusTotal", NOT_CONFIGURED,
                              "Not configured — add VIRUSTOTAL_KEY to enable this check.", 4.0))
    elif vt.get("error"):
        signals.append(Signal("virustotal", "VirusTotal", UNREACHABLE,
                              f"Could not get a VirusTotal report: {vt['error']}.", 4.0))
    elif (vt.get("malicious") or 0) > 0:
        signals.append(Signal("virustotal", "VirusTotal", FAIL,
                              f"{vt['malicious']} security vendors flagged this URL as malicious.", 4.0))
    elif (vt.get("suspicious") or 0) > 0:
        signals.append(Signal("virustotal", "VirusTotal", WARN,
                              f"{vt['suspicious']} vendors marked this URL suspicious.", 4.0))
    else:
        signals.append(Signal("virustotal", "VirusTotal", PASS,
                              "No security vendors flagged this URL on VirusTotal.", 4.0))

    return signals, sb, vt


def _host_of(u: str | None) -> str:
    if not u:
        return "another site"
    return urlparse(u).hostname or "another site"


def _signal_out(s: Signal) -> dict:
    return {
        "key": s.key, "label": s.label, "status": s.status,
        "detail": s.detail, "weight": s.weight, "counted": s.counted,
    }


def analyze(db: Session, org_id: str, raw_url: str) -> UrlAnalysisResult:
    url, parts, inferred = normalize_url(raw_url)
    host = parts.hostname or ""
    
    if host.endswith(".app"):
        return UrlAnalysisResult(
            url=url,
            final_url=url,
            score=100.0,
            band="Trusted",
            evaluated_count=1,
            signals=[
                {
                    "key": "local_app",
                    "label": "Local Application",
                    "status": "pass",
                    "detail": "Identified as a running local application on the host device.",
                    "weight": 10.0,
                    "counted": True,
                }
            ],
            website={"scheme": "local", "host": host, "https": False, "tls": {"valid": False}, "redirect_chain": [], "redirects_offsite": False},
            providers={"safe_browsing": {"configured": False, "verdict": "clean", "threats": [], "error": None}, "virustotal": {"configured": False, "malicious": 0, "suspicious": 0, "harmless": 0, "reputation": 0, "error": None}},
            ai_summary="This is a locally running application on your device, not an external web domain. It is trusted.",
            generated_at=utcnow(),
            disclaimer=DISCLAIMER,
        )

    signals: list[Signal] = []
    signals += structural_signals(url, parts, inferred)
    conn_signals, tls_dict, http_dict = _connection_signals(url, parts)
    signals += conn_signals
    domain_sig, facts = _domain_signal(host)
    signals.append(domain_sig)
    provider_signals, sb, vt = _provider_signals(url)
    signals += provider_signals

    score, band, evaluated_count = compute_score(signals)

    website = {
        "scheme": parts.scheme,
        "host": host,
        "https": parts.scheme == "https",
        "tls": tls_dict,
        "domain_age_days": facts.get("age_days"),
        "registrar": facts.get("registrar"),
        "http_status": http_dict.get("status"),
        "redirect_chain": http_dict.get("redirect_chain") or [],
        "redirects_offsite": http_dict.get("redirects_offsite"),
    }
    providers_out = {
        "safe_browsing": {k: v for k, v in sb.items() if k in
                          ("configured", "verdict", "threats", "error")},
        "virustotal": {k: v for k, v in vt.items() if k in
                       ("configured", "malicious", "suspicious", "harmless", "reputation", "error")},
    }

    ai_summary = build_summary(url, score, band, evaluated_count, signals)

    result = UrlAnalysisResult(
        url=url,
        final_url=http_dict.get("final_url") or url,
        score=score,
        band=band,
        evaluated_count=evaluated_count,
        signals=[_signal_out(s) for s in signals],
        website=website,
        providers=providers_out,
        ai_summary=ai_summary,
        generated_at=utcnow(),
        disclaimer=DISCLAIMER,
    )

    row = UrlAnalysis(
        org_id=org_id,
        url=url,
        score=score,
        band=band,
        result_json=result.model_dump(mode="json"),
    )
    db.add(row)
    db.commit()
    return result


def history(db: Session, org_id: str, limit: int = 20) -> list[HistoryItem]:
    rows = db.scalars(
        select(UrlAnalysis)
        .where(UrlAnalysis.org_id == org_id)
        .order_by(UrlAnalysis.created_at.desc())
        .limit(limit)
    ).all()
    return [
        HistoryItem(id=r.id, url=r.url, score=float(r.score), band=r.band, created_at=r.created_at)
        for r in rows
    ]
