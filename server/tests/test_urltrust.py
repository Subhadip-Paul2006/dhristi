# Drishti v0.1 — URL trust offline tests | 11-Jul-2026
"""URL Trust Analyzer — all network + providers mocked, so these run OFFLINE.

Honesty guarantees under test:
- structural red flags (http, IP host, punycode, '@') really change the signals,
- not-configured providers contribute NOTHING and fabricate no verdict,
- the score renormalizes so a missing provider neither tanks nor inflates it,
- the endpoint is authed and org-scoped.
"""
from unittest.mock import patch

import pytest

from app.services.urltrust import analyzer, network, providers, whois_lookup
from app.services.urltrust.scoring import compute_score
from app.services.urltrust.types import (
    FAIL,
    NOT_CONFIGURED,
    PASS,
    UNREACHABLE,
    Signal,
)


@pytest.fixture(autouse=True)
def offline_net():
    """Patch every outbound seam to healthy, deterministic defaults so no test
    touches the network. Individual tests override these as needed."""
    with patch.object(network, "resolve_dns", return_value=True), patch.object(
        network, "inspect_tls",
        return_value={"valid": True, "issuer": "Test CA", "expires": "2030-01-01"},
    ), patch.object(
        network, "http_probe",
        return_value={"status": 200, "final_url": None, "redirect_chain": [], "redirects_offsite": False},
    ), patch.object(
        whois_lookup, "domain_facts",
        return_value={"age_days": 3650, "registrar": "Test Registrar", "created": "2015-01-01", "expires": "2030-01-01"},
    ), patch.object(
        providers, "safe_browsing", return_value={"configured": False}
    ), patch.object(
        providers, "virustotal", return_value={"configured": False}
    ):
        yield


def _sig(res, key):
    return next(s for s in res.signals if s.key == key)


def _analyze(db, org_id, url):
    return analyzer.analyze(db, org_id, url)


# ---- structural red flags really change the signals -------------------------

def test_http_url_fails_https_signal(db_session, seed_acme_org):
    res = _analyze(db_session, seed_acme_org.id, "http://example.com")
    assert _sig(res, "https").status == FAIL
    assert res.website.https is False
    assert res.band in ("Caution", "High Risk")  # never Trusted over plain HTTP


def test_https_url_passes_https_signal(db_session, seed_acme_org):
    res = _analyze(db_session, seed_acme_org.id, "https://www.example.com")
    assert _sig(res, "https").status == PASS


def test_ip_host_flags(db_session, seed_acme_org):
    res = _analyze(db_session, seed_acme_org.id, "http://192.168.0.5/login")
    assert _sig(res, "no_ip_host").status == FAIL


def test_punycode_host_flags(db_session, seed_acme_org):
    res = _analyze(db_session, seed_acme_org.id, "https://xn--pple-43d.com")
    assert _sig(res, "no_punycode").status == FAIL
    assert res.band != "Trusted"


def test_at_symbol_fails(db_session, seed_acme_org):
    res = _analyze(db_session, seed_acme_org.id, "https://good.com@evil.example")
    assert _sig(res, "no_at_symbol").status == FAIL
    assert res.band != "Trusted"


def test_clean_https_scores_trusted(db_session, seed_acme_org):
    res = _analyze(db_session, seed_acme_org.id, "https://www.example.com")
    assert res.band == "Trusted"
    assert res.score >= 75
    # a real, populated website panel — not fabricated
    assert res.website.tls.valid is True
    assert res.website.domain_age_days == 3650


def test_different_urls_yield_different_verdicts(db_session, seed_acme_org):
    clean = _analyze(db_session, seed_acme_org.id, "https://www.example.com")
    ip = _analyze(db_session, seed_acme_org.id, "http://192.168.0.5/login")
    assert clean.score != ip.score
    assert clean.band == "Trusted" and ip.band != "Trusted"


# ---- providers: honesty when unconfigured / configured ----------------------

def test_providers_not_configured_contribute_nothing(db_session, seed_acme_org):
    res = _analyze(db_session, seed_acme_org.id, "https://www.example.com")
    sb, vt = _sig(res, "safe_browsing"), _sig(res, "virustotal")
    assert sb.status == NOT_CONFIGURED and vt.status == NOT_CONFIGURED
    # not counted toward the score, and NO fabricated verdict/number
    assert sb.counted is False and vt.counted is False
    assert res.providers.safe_browsing.configured is False
    assert res.providers.safe_browsing.verdict is None
    assert res.providers.virustotal.configured is False
    assert res.providers.virustotal.malicious is None
    # evaluated_count excludes the two unconfigured providers
    counted = [s for s in res.signals if s.counted]
    assert res.evaluated_count == len(counted)
    assert not any(s.key in ("safe_browsing", "virustotal") for s in counted)


def test_configured_safe_browsing_flag_forces_high_risk(db_session, seed_acme_org):
    with patch.object(
        providers, "safe_browsing",
        return_value={"configured": True, "verdict": "flagged", "threats": ["MALWARE"]},
    ):
        res = _analyze(db_session, seed_acme_org.id, "https://www.example.com")
    sb = _sig(res, "safe_browsing")
    assert sb.status == FAIL and sb.counted is True
    assert res.providers.safe_browsing.verdict == "flagged"
    assert res.band == "High Risk"  # a real threat-feed hit caps the verdict


def test_configured_virustotal_clean_passes(db_session, seed_acme_org):
    with patch.object(
        providers, "virustotal",
        return_value={"configured": True, "malicious": 0, "suspicious": 0, "harmless": 70, "reputation": 5},
    ):
        res = _analyze(db_session, seed_acme_org.id, "https://www.example.com")
    vt = _sig(res, "virustotal")
    assert vt.status == PASS
    assert res.providers.virustotal.malicious == 0 and res.providers.virustotal.harmless == 70


def test_unreachable_provider_not_counted(db_session, seed_acme_org):
    with patch.object(
        providers, "safe_browsing",
        return_value={"configured": True, "error": "HTTP 503"},
    ):
        res = _analyze(db_session, seed_acme_org.id, "https://www.example.com")
    sb = _sig(res, "safe_browsing")
    assert sb.status == UNREACHABLE and sb.counted is False


# ---- scoring renormalization (pure, no I/O) ---------------------------------

def test_renormalization_excludes_unavailable_signals():
    evaluated = [
        Signal("https", "HTTPS", PASS, "", 3.0),
        Signal("no_ip_host", "Domain", PASS, "", 2.0),
        Signal("tls_valid", "TLS", PASS, "", 3.0),
    ]
    base_score, base_band, base_n = compute_score(evaluated)

    with_missing = evaluated + [
        Signal("safe_browsing", "SB", NOT_CONFIGURED, "", 4.0),
        Signal("virustotal", "VT", NOT_CONFIGURED, "", 4.0),
        Signal("domain_age", "Age", "unknown", "", 2.0),
    ]
    miss_score, miss_band, miss_n = compute_score(with_missing)

    # a missing/unconfigured signal must not change the score or the count
    assert miss_score == base_score
    assert miss_band == base_band
    assert miss_n == base_n == 3


def test_missing_provider_does_not_tank_score():
    # same evaluated signals, once with an unconfigured provider appended:
    # the score is identical (provider excluded, not scored as 0).
    good = [Signal("https", "HTTPS", PASS, "", 3.0), Signal("tls_valid", "TLS", PASS, "", 3.0)]
    assert compute_score(good)[0] == 100.0
    assert compute_score(good + [Signal("virustotal", "VT", NOT_CONFIGURED, "", 4.0)])[0] == 100.0


# ---- endpoint: auth + org scoping -------------------------------------------

def test_analyze_requires_auth(client, seed_acme_org):
    resp = client.post("/api/url-analyzer/analyze", json={"url": "https://example.com"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


def test_invalid_url_rejected(client, user_headers):
    for bad in ["ftp://example.com", "   ", "javascript:alert(1)"]:
        resp = client.post("/api/url-analyzer/analyze", json={"url": bad}, headers=user_headers)
        assert resp.status_code == 422, bad


def test_analyze_and_history_org_scoped(client, user_headers, db_session, seed_acme_org):
    # org A (seeded demo user) analyzes a URL
    resp = client.post(
        "/api/url-analyzer/analyze", json={"url": "https://www.example.com"}, headers=user_headers
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["band"] == "Trusted" and body["evaluated_count"] > 0
    assert body["disclaimer"]

    hist = client.get("/api/url-analyzer/history", headers=user_headers).json()
    assert len(hist) == 1 and hist[0]["url"] == "https://www.example.com"

    # a fresh org B cannot see org A's history
    reg = client.post(
        "/api/auth/register",
        json={"name": "B", "email": "b@b.dev", "password": "p@ssw0rd12", "org_name": "Org B"},
    ).json()
    b_headers = {"Authorization": f"Bearer {reg['access_token']}"}
    assert client.get("/api/url-analyzer/history", headers=b_headers).json() == []
