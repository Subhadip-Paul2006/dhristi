# Drishti v0.1 — Device Security Profile | Phase 04
"""Unified Device Security Profile: deterministic, bounded risk-signal score.

FORMULA DOCUMENTATION
=====================
Output range : 0.0 (no signals detected) → 1.0 (maximum risk signals)
Label        : "Risk Signal Score" — NOT a compromise score, NOT proof of attack.

Three independent signal components are combined with fixed weights that sum to 1.0:

  Component         Weight   Source
  ─────────────────────────────────────────────────────────────────────────
  vuln_component     0.60    Confirmed vulnerability findings (Phase 03)
  kev_component      0.15    CISA KEV enrichment (additive signal ONLY)
  ai_component       0.25    AI traffic detection (CURRENT DETECTION signal)
  ─────────────────────────────────────────────────────────────────────────
  Total capacity     1.00

VULNERABILITY COMPONENT (0.0 – 1.0)
  Finding state priority (highest state wins):
    KNOWN_EXPLOITED  → 0.80 + (max_cvss / 10.0) * 0.20   [0.80 – 1.00]
    VULNERABLE       → max_cvss / 10.0                     [0.00 – 1.00]
    POTENTIAL_MATCH  → 0.30 (fixed)
    EXPOSED          → 0.15 (fixed)
    OPEN             → 0.05 (fixed)
    NO_CONFIRMED_VULNERABILITY / no findings → 0.00

KEV COMPONENT (0.0 or 0.15)
  KEV = a known-exploited-in-the-wild enrichment signal.
  It is NOT proof that this specific device was exploited.
  Contributes exactly 0.15 if any finding has in_kev=True, else 0.0.

AI DETECTION COMPONENT (0.0 – 0.25)
  AI detection is a CURRENT DETECTION signal, not a confirmed attack assertion.
  ANOMALOUS  + confidence c → 0.25 * c   [0.00 – 0.25]
  SUSPICIOUS + confidence c → 0.12 * c   [0.00 – 0.12]
  NORMAL / INSUFFICIENT_DATA / None      → 0.00

FINAL FORMULA
  raw = vuln_component * 0.60 + kev_component + ai_component
  device_security_score = clamp(raw, 0.0, 1.0)

SCORE INTERPRETATION
  0.00 – 0.10 : Minimal signals
  0.10 – 0.30 : Low signals (exposure only or clean endpoint)
  0.30 – 0.60 : Medium signals (potential match or suspicious traffic)
  0.60 – 0.80 : High signals (confirmed vulnerability)
  0.80 – 1.00 : Critical signals (KEV or known-exploited finding)

CONSTRAINTS
  - Forecast probability NEVER contributes to this score.
  - AI detection confidence NEVER makes a finding CONFIRMED.
  - KEV NEVER implies this device was successfully exploited.
  - Open port alone CANNOT raise score above 0.05 * 0.60 = 0.03.
"""
from __future__ import annotations

from dataclasses import dataclass


# ── Vulnerability-component thresholds (documented constants) ─────────────────
_VULN_KNOWN_EXPLOITED_BASE: float = 0.80   # guaranteed minimum for KEP finding
_VULN_POTENTIAL_MATCH: float = 0.30        # uncertain identity/version match
_VULN_EXPOSED: float = 0.15               # service detected, no advisory match
_VULN_OPEN_PORT: float = 0.05             # port open only, no product detected

# ── Component weights (must sum to 1.0) ──────────────────────────────────────
_W_VULN: float = 0.60
_W_KEV: float = 0.15
_W_AI: float = 0.25
assert abs(_W_VULN + _W_KEV + _W_AI - 1.0) < 1e-9, "Component weights must sum to 1.0"

# ── AI detection multipliers (clearly NOT proof of attack) ───────────────────
_AI_ANOMALOUS_MULT: float = 0.25    # ANOMALOUS: full ai_weight capacity
_AI_SUSPICIOUS_MULT: float = 0.12   # SUSPICIOUS: half ai_weight capacity


@dataclass(frozen=True)
class SecurityScoreInputs:
    """All inputs required to compute the device security score.

    All fields are documented in the module docstring above.
    This dataclass is frozen so the same inputs always produce the same output.
    """
    # Vulnerability component inputs
    max_cvss: float = 0.0                  # 0.0 – 10.0; highest CVSS among findings
    has_known_exploited: bool = False       # any finding in KNOWN_EXPLOITED state
    has_vulnerable: bool = False           # any finding in VULNERABLE state
    has_potential_match: bool = False      # any finding in POTENTIAL_MATCH state
    has_exposed: bool = False             # any finding in EXPOSED state
    has_open_port: bool = False           # any finding in OPEN state (port only)

    # KEV enrichment input (additive signal — NOT proof of local exploit)
    has_kev: bool = False

    # AI detection component inputs (CURRENT DETECTION signal — NOT confirmed attack)
    ai_verdict: str | None = None          # ANOMALOUS | SUSPICIOUS | NORMAL | INSUFFICIENT_DATA | None
    ai_confidence: float = 0.0            # 0.0 – 1.0


def compute_device_security_score(inputs: SecurityScoreInputs) -> float:
    """Compute the device security score from documented inputs.

    Pure, deterministic, bounded in [0.0, 1.0].

    Args:
        inputs: SecurityScoreInputs dataclass (frozen).

    Returns:
        float in [0.0, 1.0] — a risk-signal score, explicitly NOT a compromise score.
    """
    # Clamp CVSS to valid range
    cvss = max(0.0, min(10.0, inputs.max_cvss))

    # ── Vulnerability component ───────────────────────────────────────────────
    if inputs.has_known_exploited:
        # KEP finding: base 0.80 + CVSS contribution capped to 0.20
        vuln_component = _VULN_KNOWN_EXPLOITED_BASE + (cvss / 10.0) * (1.0 - _VULN_KNOWN_EXPLOITED_BASE)
    elif inputs.has_vulnerable:
        # Confirmed version-matched vulnerability — CVSS drives the score
        vuln_component = cvss / 10.0
    elif inputs.has_potential_match:
        # Uncertain identity or version — fixed moderate signal
        vuln_component = _VULN_POTENTIAL_MATCH
    elif inputs.has_exposed:
        # Service detected but no advisory match
        vuln_component = _VULN_EXPOSED
    elif inputs.has_open_port:
        # Port open only — minimum signal, port alone is NOT vulnerability evidence
        vuln_component = _VULN_OPEN_PORT
    else:
        vuln_component = 0.0

    # ── KEV enrichment component ──────────────────────────────────────────────
    # KEV means this CVE is known-exploited-in-the-wild.
    # It is NOT proof that this specific device was exploited.
    kev_component: float = _W_KEV if inputs.has_kev else 0.0

    # ── AI detection component ────────────────────────────────────────────────
    # AI detection is a CURRENT DETECTION signal, not a confirmed attack.
    # Forecast probability is intentionally excluded from this formula.
    ai_confidence = max(0.0, min(1.0, inputs.ai_confidence))
    verdict = (inputs.ai_verdict or "").upper()
    if verdict == "ANOMALOUS":
        ai_component = _AI_ANOMALOUS_MULT * ai_confidence
    elif verdict == "SUSPICIOUS":
        ai_component = _AI_SUSPICIOUS_MULT * ai_confidence
    else:
        ai_component = 0.0

    # ── Final formula ─────────────────────────────────────────────────────────
    raw = vuln_component * _W_VULN + kev_component + ai_component
    return round(max(0.0, min(1.0, raw)), 4)


def build_score_inputs_from_device(
    cves: list,                          # list of DeepScanCve or CorrelatedFinding-like objects
    ai_verdict: str | None = None,
    ai_confidence: float = 0.0,
) -> SecurityScoreInputs:
    """Convenience builder: derive SecurityScoreInputs from a device's live cves list + AI state.

    cves: list of objects with .severity, .cvss, .in_kev, .finding_state attributes.
    Returns a SecurityScoreInputs suitable for compute_device_security_score().
    """
    max_cvss: float = 0.0
    has_kev = False
    has_known_exploited = False
    has_vulnerable = False
    has_potential_match = False
    has_exposed = False
    has_open_port = False

    for c in cves:
        cvss = float(getattr(c, "cvss", 0.0) or 0.0)
        max_cvss = max(max_cvss, cvss)

        in_kev = bool(getattr(c, "in_kev", False))
        if in_kev:
            has_kev = True

        state = str(getattr(c, "finding_state", "VULNERABLE")).upper()
        if state == "KNOWN_EXPLOITED":
            has_known_exploited = True
        elif state == "VULNERABLE":
            has_vulnerable = True
        elif state == "POTENTIAL_MATCH":
            has_potential_match = True
        elif state == "EXPOSED":
            has_exposed = True
        elif state == "OPEN":
            has_open_port = True

    return SecurityScoreInputs(
        max_cvss=max_cvss,
        has_known_exploited=has_known_exploited,
        has_vulnerable=has_vulnerable,
        has_potential_match=has_potential_match,
        has_exposed=has_exposed,
        has_open_port=has_open_port,
        has_kev=has_kev,
        ai_verdict=ai_verdict,
        ai_confidence=ai_confidence,
    )
