# Drishti v0.1 — offline URL structure checks | 11-Jul-2026
"""Pure URL / structure checks — no network, always available.

Every function returns a Signal computed only from the URL string itself.
Deterministic: the same URL always yields the same signals.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import ParseResult

from app.services.urltrust.types import FAIL, PASS, WARN, Signal

# TLDs disproportionately abused for phishing/malware (documented, not exhaustive).
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "ml", "cf", "tk", "ga", "work", "click",
    "link", "country", "kim", "loan", "download", "racing", "stream", "cam",
}

# Lure words common in phishing paths/hosts.
RISKY_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "update", "confirm",
    "secure", "security", "webscr", "password", "banking", "wallet", "unlock",
    "suspended", "recover",
}

# Popular brands frequently impersonated. Real, computed lookalike hint only —
# flags when a brand token appears in the host but is NOT the registrable domain.
IMPERSONATED_BRANDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "outlook", "office365", "coinbase", "binance",
    "chase", "wellsfargo", "bankofamerica",
}


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without an external suffix list. Handles a small set
    of common two-level public suffixes; otherwise takes the last two labels.
    Documented heuristic (docs/URL_ANALYZER.md)."""
    host = (host or "").strip(".").lower()
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_level = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if labels[-2] in two_level and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _host_labels(host: str) -> list[str]:
    return [x for x in (host or "").strip(".").split(".") if x]


def structural_signals(raw_url: str, parts: ParseResult, scheme_inferred: bool) -> list[Signal]:
    host = (parts.hostname or "").lower()
    labels = _host_labels(host)
    path_q = f"{parts.path or ''} {parts.query or ''}".lower()
    signals: list[Signal] = []

    # 1) HTTPS
    if parts.scheme == "https":
        detail = (
            "Uses HTTPS (encrypted). Scheme was assumed since none was given."
            if scheme_inferred
            else "Uses HTTPS — traffic to this site is encrypted."
        )
        signals.append(Signal("https", "HTTPS encryption", PASS, detail, 3.0))
    else:
        signals.append(
            Signal("https", "HTTPS encryption", FAIL,
                   "Plain HTTP — traffic is not encrypted and can be intercepted.", 3.0)
        )

    # 2) Host is a domain, not a raw IP literal
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        signals.append(
            Signal("no_ip_host", "Domain name", FAIL,
                   f"Uses a raw IP address ({host}) instead of a domain name — common in phishing.", 2.0)
        )
    else:
        signals.append(Signal("no_ip_host", "Domain name", PASS,
                              "Uses a proper domain name.", 2.0))

    # 3) Punycode / homograph host (xn--)
    if any(lbl.startswith("xn--") for lbl in labels):
        signals.append(
            Signal("no_punycode", "No homograph host", FAIL,
                   "Host uses punycode (xn--) — can disguise a lookalike domain.", 2.0)
        )
    else:
        signals.append(Signal("no_punycode", "No homograph host", PASS,
                              "No punycode/homograph tricks in the hostname.", 2.0))

    # 4) '@' in the authority (classic obfuscation). Scope the test to the
    #    netloc so a legitimate query value like ?email=john@example.com — where
    #    the '@' is in the query string, not the authority — does not trip it.
    if "@" in (parts.netloc or ""):
        signals.append(
            Signal("no_at_symbol", "No '@' obfuscation", FAIL,
                   "URL contains '@', which can hide the real destination host.", 2.0)
        )
    else:
        signals.append(Signal("no_at_symbol", "No '@' obfuscation", PASS,
                              "No '@' redirection trick in the URL.", 2.0))

    # 5) Embedded credentials (user:pass@)
    if parts.username:
        signals.append(
            Signal("no_embedded_credentials", "No embedded credentials", FAIL,
                   "URL embeds login credentials — legitimate sites never do this.", 2.0)
        )
    else:
        signals.append(Signal("no_embedded_credentials", "No embedded credentials", PASS,
                              "No credentials embedded in the URL.", 2.0))

    # 6) Excessive subdomains
    depth = max(0, len(labels) - 2)
    if depth >= 3:
        signals.append(
            Signal("subdomain_depth", "Subdomain depth", WARN,
                   f"{depth} subdomain levels — deep nesting is often used to look legitimate.", 1.0)
        )
    else:
        signals.append(Signal("subdomain_depth", "Subdomain depth", PASS,
                              "Reasonable subdomain depth.", 1.0))

    # 7) Suspicious / known-abused TLD
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        signals.append(
            Signal("tld_reputation", "TLD reputation", WARN,
                   f".{tld} is disproportionately used for abuse — treat with extra caution.", 1.0)
        )
    else:
        signals.append(Signal("tld_reputation", "TLD reputation", PASS,
                              f".{tld or '?'} is not on the high-abuse list.", 1.0))

    # 8) Very long URL
    if len(raw_url) > 100:
        signals.append(
            Signal("url_length", "URL length", WARN,
                   f"URL is {len(raw_url)} characters — unusually long URLs can hide their true target.", 1.0)
        )
    else:
        signals.append(Signal("url_length", "URL length", PASS,
                              "URL length is unremarkable.", 1.0))

    # 9) Risky keywords (skip path keyword warnings on official verified domains)
    reg = registrable_domain(host)
    official_domains = {
        "instagram.com", "facebook.com", "google.com", "apple.com", "microsoft.com",
        "github.com", "amazon.com", "netflix.com", "linkedin.com", "twitter.com", "x.com",
    }
    hit = sorted({k for k in RISKY_KEYWORDS if k in host or (k in path_q and reg not in official_domains)})
    if hit:
        signals.append(
            Signal("no_risky_keywords", "Lure keywords", WARN,
                   f"Contains lure words ({', '.join(hit[:4])}) often seen in credential-phishing.", 1.0)
        )
    else:
        signals.append(Signal("no_risky_keywords", "Lure keywords", PASS,
                              "No common phishing lure words in the URL.", 1.0))

    # 10) Brand lookalike (real, computed hint)
    reg = registrable_domain(host)
    reg_first = reg.split(".")[0] if reg else ""
    # Match brands against host *labels* (and their hyphen-separated tokens),
    # not a raw substring — so a legitimate domain that merely contains a brand
    # name as an incidental substring (s3.amazonaws.com, snapple.com) is not
    # flagged. A brand only hits when it appears as a full label/token that is
    # NOT the site's own registrable domain (e.g. paypal.evil.com, secure-paypal.net).
    host_tokens = {tok for lbl in labels for tok in lbl.split("-") if tok}
    brand_hit = next((b for b in IMPERSONATED_BRANDS if b in host_tokens and reg_first != b), None)
    if brand_hit:
        signals.append(
            Signal("brand_lookalike", "Brand impersonation", WARN,
                   f"Mentions '{brand_hit}' but the real domain is '{reg}', not {brand_hit}'s — possible lookalike.", 2.0)
        )
    else:
        signals.append(Signal("brand_lookalike", "Brand impersonation", PASS,
                              "No obvious brand-in-hostname impersonation.", 2.0))

    return signals
