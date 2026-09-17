# Drishti v0.1 — transparent trust scoring | 11-Jul-2026
"""Transparent trust scoring. Two documented parts (docs/URL_ANALYZER.md):

1. Weighted base — combines ONLY evaluated signals (pass/warn/fail),
   renormalizing over their weights so an unavailable signal or provider neither
   tanks nor inflates the result.
2. Hard caps — a single serious red flag (e.g. a threat-feed hit, punycode host,
   embedded credentials) ceilings the final score, because real trust is not an
   average: one confirmed danger outweighs many passing checks. Caps only ever
   LOWER the score; they never invent risk that a real signal didn't find.
"""
from __future__ import annotations

from app.services.urltrust.types import EVALUATED, FAIL, STATUS_VALUE, WARN, Signal

# Band thresholds (inclusive lower bounds).
TRUSTED_MIN = 75.0
CAUTION_MIN = 40.0

# If a signal has this status, the FINAL score may not exceed the given ceiling.
# Values chosen so a confirmed threat lands in High Risk and a structural red
# flag lands no better than Caution. Documented in docs/URL_ANALYZER.md.
FAIL_CAPS: dict[str, float] = {
    "safe_browsing": 15.0,           # flagged by Google Safe Browsing
    "virustotal": 20.0,              # vendors call it malicious
    "no_embedded_credentials": 30.0,  # credentials embedded in the URL
    "dns_resolves": 40.0,            # domain does not resolve
    "no_punycode": 40.0,             # homograph/punycode host
    "no_at_symbol": 40.0,            # '@' obfuscation
    "no_ip_host": 50.0,              # raw IP instead of a domain
    "tls_valid": 50.0,               # invalid / expired certificate
    "https": 74.0,                   # plain HTTP (top of Caution at best)
}
WARN_CAPS: dict[str, float] = {
    "brand_lookalike": 55.0,         # brand name present but not the real domain
    "virustotal": 60.0,              # vendors call it suspicious
}


def band_for(score: float) -> str:
    if score >= TRUSTED_MIN:
        return "Trusted"
    if score >= CAUTION_MIN:
        return "Caution"
    return "High Risk"


def _cap(signals: list[Signal]) -> float:
    ceilings = [100.0]
    for s in signals:
        if s.status == FAIL and s.key in FAIL_CAPS:
            ceilings.append(FAIL_CAPS[s.key])
        elif s.status == WARN and s.key in WARN_CAPS:
            ceilings.append(WARN_CAPS[s.key])
    return min(ceilings)


def compute_score(signals: list[Signal]) -> tuple[float, str, int]:
    """Return (score 0-100, band, evaluated_count).

    Only pass/warn/fail signals count; their weights are renormalized so a
    missing provider is excluded (not scored as 0 or 100). A serious red flag
    then caps the result downward.
    """
    evaluated = [s for s in signals if s.status in EVALUATED]
    total_weight = sum(s.weight for s in evaluated)
    if total_weight <= 0:
        # Nothing could be evaluated at all — neutral, not a fabricated verdict.
        return 50.0, band_for(50.0), 0
    earned = sum(s.weight * STATUS_VALUE[s.status] for s in evaluated)
    base = 100.0 * earned / total_weight
    score = round(min(base, _cap(evaluated)), 1)
    return score, band_for(score), len(evaluated)
