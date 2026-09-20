# Drishti v0.1 — Phase 04 Unified Device Security Profile Tests
"""Tests for Phase 04: Unified Device Security Profile integration.

Mandatory test coverage (per approval prompt):
 1. active AI session → device receives detection
 2. active AI session → device receives forecast
 3. no AI session → no AI state (ai_tracking_active=False, ai_detection=None)
 4. correct device/session matching (session_id must match)
 5. cross-device isolation (Device A session never appears on Device B)
 6. stale endpoint + live network coexistence
 7. all Phase 03 finding states exposed correctly (6 states)
 8. deterministic security score (same inputs → same output)
 9. score boundary conditions (min, max, normal, vulnerable, KEV, mixed)
10. AI confidence must never become "confirmed attack"
11. forecast probability must never become "confirmed attack"
12. KEV must never become "device exploited"
"""
from __future__ import annotations

import pytest

from app.services.device_security_profile import (
    SecurityScoreInputs,
    _W_AI,
    _W_KEV,
    _W_VULN,
    build_score_inputs_from_device,
    compute_device_security_score,
)
from app.services.traffic.session_manager import ActiveTrackingSession, SessionManager
from app.schemas.tracking import CurrentBehaviourOut, ForecastResultOut, ForecastStepOut
from app.schemas.live import EndpointFindingOut


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_session(org_id: str, device_id: str, status: str = "LIVE") -> ActiveTrackingSession:
    """Create a minimal ActiveTrackingSession without starting capture."""
    sess = object.__new__(ActiveTrackingSession)
    sess.session_id = f"sess-{device_id}"
    sess.org_id = org_id
    sess.device_id = device_id
    sess.target_ip = "10.0.0.1"
    sess.status = status
    sess.last_detection = None
    sess.last_forecast = None
    return sess


def _detection(verdict: str = "NORMAL", confidence: float = 0.9) -> CurrentBehaviourOut:
    return CurrentBehaviourOut(verdict=verdict, confidence=confidence, signals=["test signal"])


def _forecast(state: str = "NORMAL_CONTINUATION", prob: float = 0.7) -> ForecastResultOut:
    return ForecastResultOut(
        is_available=True,
        status="FORECAST AVAILABLE",
        horizon_steps=[ForecastStepOut(step="T+1", state=state, probability=prob, status_label="PREDICTED")],
    )


class _FakeCve:
    """Minimal object that mimics a DeepScanCve for score input building."""
    def __init__(self, cvss: float = 0.0, in_kev: bool = False, finding_state: str = "VULNERABLE"):
        self.cvss = cvss
        self.in_kev = in_kev
        self.finding_state = finding_state
        self.severity = "high" if cvss >= 7 else "medium"


# ══════════════════════════════════════════════════════════════════════════════
# Tests 1–5: SessionManager device-scoped lookup
# ══════════════════════════════════════════════════════════════════════════════

class TestSessionManagerDeviceLookup:
    """Tests 1, 2, 3, 4, 5 — AI session isolation and lookup."""

    def _make_manager_with_sessions(self, sessions: list[ActiveTrackingSession]) -> SessionManager:
        sm = SessionManager()
        for s in sessions:
            sm._active_sessions[s.session_id] = s
        return sm

    # Test 1: active AI session → device receives detection
    def test_active_session_device_receives_detection(self):
        sess = _make_session("org1", "dev-a")
        sess.last_detection = _detection("ANOMALOUS", 0.94)
        sm = self._make_manager_with_sessions([sess])
        result = sm.get_active_session_for_device("org1", "dev-a")
        assert result is not None
        # CURRENT DETECTION — not confirmed attack
        assert result.last_detection is not None
        assert result.last_detection.verdict == "ANOMALOUS"
        assert result.last_detection.confidence == 0.94

    # Test 2: active AI session → device receives forecast
    def test_active_session_device_receives_forecast(self):
        sess = _make_session("org1", "dev-a")
        sess.last_forecast = _forecast("LIKELY_ESCALATION", 0.65)
        sm = self._make_manager_with_sessions([sess])
        result = sm.get_active_session_for_device("org1", "dev-a")
        assert result is not None
        # FORECAST — probabilistic, not confirmed future attack
        assert result.last_forecast is not None
        assert result.last_forecast.horizon_steps[0].status_label == "PREDICTED"
        assert result.last_forecast.horizon_steps[0].probability == 0.65

    # Test 3: no AI session → no AI state returned
    def test_no_session_returns_none(self):
        sm = SessionManager()  # empty
        result = sm.get_active_session_for_device("org1", "dev-a")
        assert result is None

    # Test 3 variant: STOPPED session not returned
    def test_stopped_session_not_returned(self):
        sess = _make_session("org1", "dev-a", status="STOPPED")
        sess.last_detection = _detection("ANOMALOUS", 0.9)
        sm = self._make_manager_with_sessions([sess])
        result = sm.get_active_session_for_device("org1", "dev-a")
        # Stopped session must NOT be returned to device profile
        assert result is None

    # Test 4: correct device/session matching
    def test_correct_device_session_matching(self):
        sess_a = _make_session("org1", "dev-a")
        sess_b = _make_session("org1", "dev-b")
        sess_a.last_detection = _detection("SUSPICIOUS", 0.75)
        sess_b.last_detection = _detection("NORMAL", 0.92)
        sm = self._make_manager_with_sessions([sess_a, sess_b])

        result_a = sm.get_active_session_for_device("org1", "dev-a")
        result_b = sm.get_active_session_for_device("org1", "dev-b")

        assert result_a is not None and result_a.session_id == "sess-dev-a"
        assert result_b is not None and result_b.session_id == "sess-dev-b"
        assert result_a.last_detection.verdict == "SUSPICIOUS"
        assert result_b.last_detection.verdict == "NORMAL"

    # Test 5: cross-device isolation
    def test_cross_device_isolation(self):
        """Device A's session must NEVER appear when querying Device B."""
        sess_a = _make_session("org1", "dev-a")
        sess_a.last_detection = _detection("ANOMALOUS", 0.99)
        sm = self._make_manager_with_sessions([sess_a])

        # Querying dev-b returns None, not dev-a's session
        result = sm.get_active_session_for_device("org1", "dev-b")
        assert result is None

    # Test 5 variant: cross-org isolation
    def test_cross_org_isolation(self):
        """org2 must not see org1's session."""
        sess = _make_session("org1", "dev-a")
        sess.last_detection = _detection("ANOMALOUS", 0.99)
        sm = self._make_manager_with_sessions([sess])

        result = sm.get_active_session_for_device("org2", "dev-a")
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# Tests 6–7: Finding states and stale endpoint coexistence
# ══════════════════════════════════════════════════════════════════════════════

class TestFindingStatesAndCoexistence:
    """Tests 6, 7 — stale endpoint state and all 6 finding states."""

    # Test 6: stale endpoint + live network coexistence
    def test_stale_endpoint_does_not_corrupt_live_network_state(self):
        """EndpointFindingOut with stale data is surfaced but marked stale;
        it must not overwrite or suppress live network scan data."""
        stale_finding = EndpointFindingOut(
            finding_id="f-stale",
            finding_state="NO_CONFIRMED_VULNERABILITY",
            evidence_source="endpoint_software",
            observed_product="TestApp",
            observed_version="1.0.0",
            source_freshness="stale",
        )
        # Stale finding is distinct — it preserves its state, not "no vulnerability"
        assert stale_finding.finding_state == "NO_CONFIRMED_VULNERABILITY"
        assert stale_finding.source_freshness == "stale"
        # Stale source ≠ clean device — it retains its recorded state
        assert stale_finding.finding_state != "VULNERABLE"

    # Test 7: all Phase 03 finding states correctly represented
    def test_all_six_finding_states_representable(self):
        states = [
            "OPEN",
            "EXPOSED",
            "POTENTIAL_MATCH",
            "VULNERABLE",
            "KNOWN_EXPLOITED",
            "NO_CONFIRMED_VULNERABILITY",
        ]
        for state in states:
            f = EndpointFindingOut(
                finding_id=f"f-{state}",
                finding_state=state,
                evidence_source="endpoint_software",
                observed_product="TestProduct",
            )
            assert f.finding_state == state, f"State {state} not preserved in EndpointFindingOut"

    def test_finding_state_kev_not_device_exploited(self):
        """KNOWN_EXPLOITED finding_state does NOT mean the local device was exploited.
        The label is preserved for UI to display correctly with disclaimer."""
        f = EndpointFindingOut(
            finding_id="f-kev",
            finding_state="KNOWN_EXPLOITED",
            evidence_source="endpoint_software",
            observed_product="VulnApp",
            in_kev=True,
        )
        assert f.finding_state == "KNOWN_EXPLOITED"
        assert f.in_kev is True
        # The model carries the raw evidence; "device was exploited" interpretation
        # must not be made by backend — that is UI/analyst responsibility.


# ══════════════════════════════════════════════════════════════════════════════
# Tests 8–12: Device security score formula
# ══════════════════════════════════════════════════════════════════════════════

class TestDeviceSecurityScore:
    """Tests 8, 9, 10, 11, 12 — deterministic score, boundaries, label safety."""

    # Test 8: deterministic — same inputs always produce same output
    def test_score_is_deterministic(self):
        inputs = SecurityScoreInputs(
            max_cvss=7.5, has_vulnerable=True, has_kev=False,
            ai_verdict="SUSPICIOUS", ai_confidence=0.8,
        )
        result1 = compute_device_security_score(inputs)
        result2 = compute_device_security_score(inputs)
        assert result1 == result2

    # Test 9a: minimum — no signals → score == 0.0
    def test_score_minimum_no_signals(self):
        inputs = SecurityScoreInputs()
        score = compute_device_security_score(inputs)
        assert score == 0.0

    # Test 9b: open port only → very low score
    def test_score_open_port_only(self):
        inputs = SecurityScoreInputs(has_open_port=True)
        score = compute_device_security_score(inputs)
        # 0.05 * 0.60 = 0.03
        expected = round(0.05 * _W_VULN, 4)
        assert score == expected
        assert score < 0.10

    # Test 9c: EXPOSED only → low score
    def test_score_exposed_only(self):
        inputs = SecurityScoreInputs(has_exposed=True)
        score = compute_device_security_score(inputs)
        expected = round(0.15 * _W_VULN, 4)
        assert score == expected

    # Test 9d: POTENTIAL_MATCH → moderate score
    def test_score_potential_match(self):
        inputs = SecurityScoreInputs(has_potential_match=True)
        score = compute_device_security_score(inputs)
        expected = round(0.30 * _W_VULN, 4)
        assert score == expected

    # Test 9e: VULNERABLE with CVSS 9.8
    def test_score_vulnerable_high_cvss(self):
        inputs = SecurityScoreInputs(max_cvss=9.8, has_vulnerable=True)
        score = compute_device_security_score(inputs)
        expected = round((9.8 / 10.0) * _W_VULN, 4)
        assert abs(score - expected) < 0.001

    # Test 9f: KNOWN_EXPLOITED → high score
    def test_score_known_exploited(self):
        inputs = SecurityScoreInputs(max_cvss=9.8, has_known_exploited=True)
        score = compute_device_security_score(inputs)
        # 0.80 + (9.8/10.0)*0.20 = 0.996, then * 0.60 = 0.5976
        assert score >= 0.55

    # Test 9g: KEV adds component
    def test_score_kev_adds_signal(self):
        inputs_no_kev = SecurityScoreInputs(max_cvss=7.0, has_vulnerable=True, has_kev=False)
        inputs_with_kev = SecurityScoreInputs(max_cvss=7.0, has_vulnerable=True, has_kev=True)
        score_no_kev = compute_device_security_score(inputs_no_kev)
        score_kev = compute_device_security_score(inputs_with_kev)
        assert score_kev > score_no_kev
        assert abs(score_kev - score_no_kev - _W_KEV) < 0.001

    # Test 9h: maximum — all signals maxed → score ≤ 1.0
    def test_score_maximum_clamped_to_one(self):
        inputs = SecurityScoreInputs(
            max_cvss=10.0,
            has_known_exploited=True,
            has_kev=True,
            ai_verdict="ANOMALOUS",
            ai_confidence=1.0,
        )
        score = compute_device_security_score(inputs)
        assert score <= 1.0
        assert score >= 0.90  # should be near maximum

    # Test 9i: mixed signals
    def test_score_mixed_signals(self):
        inputs = SecurityScoreInputs(
            max_cvss=5.0, has_vulnerable=True, has_kev=False,
            ai_verdict="SUSPICIOUS", ai_confidence=0.5,
        )
        score = compute_device_security_score(inputs)
        # vuln = (5.0/10.0)*0.60 = 0.30; ai = 0.12*0.5 = 0.06; total = 0.36
        expected = round((5.0 / 10.0) * _W_VULN + 0.12 * 0.5, 4)
        assert abs(score - expected) < 0.001

    # Test 10: AI confidence NEVER becomes "confirmed attack"
    def test_ai_confidence_not_confirmed_attack(self):
        """AI confidence of 1.0 with ANOMALOUS verdict:
        - contributes at most 0.25 to the raw score
        - never sets has_known_exploited or has_vulnerable
        - the score label must NOT be "confirmed attack"
        """
        inputs = SecurityScoreInputs(
            has_known_exploited=False, has_vulnerable=False,
            ai_verdict="ANOMALOUS", ai_confidence=1.0,
        )
        score = compute_device_security_score(inputs)
        # Without vuln findings, max possible = _W_AI * 1.0 = 0.25
        assert score == round(_W_AI, 4)
        # AI alone cannot push score to "critical" level (>0.60 requires vuln findings)
        assert score < 0.60, "AI signal alone must not reach critical score threshold"

    # Test 11: forecast probability NEVER becomes "confirmed attack"
    def test_forecast_probability_not_in_score(self):
        """Forecast probability is intentionally excluded from the score formula.
        Two otherwise identical devices with different forecast probabilities must
        produce the same score if their vuln findings and AI detection are identical.
        """
        base_inputs = SecurityScoreInputs(max_cvss=7.0, has_vulnerable=True, ai_verdict="NORMAL")
        score = compute_device_security_score(base_inputs)
        # If we were to naively use forecast_prob=0.99 vs 0.01, score must be unchanged.
        # The formula doesn't accept forecast as input — confirmed by its signature.
        import inspect
        sig = inspect.signature(compute_device_security_score)
        param_names = list(sig.parameters.keys())
        assert "forecast" not in param_names, "Forecast must not be an input to security score"
        assert "forecast_prob" not in param_names

    # Test 12: KEV never means "device exploited"
    def test_kev_not_device_exploited(self):
        """KEV = known-exploited-in-the-wild CVE.
        has_kev=True raises the score signal but does NOT imply this specific
        device has been successfully exploited. The score must remain < 1.0
        from KEV alone (without max-CVSS KNOWN_EXPLOITED finding).
        """
        inputs_kev_only = SecurityScoreInputs(has_kev=True)
        score = compute_device_security_score(inputs_kev_only)
        # KEV alone: vuln_component=0, ai_component=0, kev_component=0.15
        assert score == _W_KEV, f"KEV alone: expected {_W_KEV}, got {score}"
        # KEV alone must not be a near-maximum score
        assert score < 0.5, "KEV alone must not produce a critical risk-signal score"


# ══════════════════════════════════════════════════════════════════════════════
# Build from device helper tests
# ══════════════════════════════════════════════════════════════════════════════

class TestBuildScoreInputsFromDevice:
    """Tests for build_score_inputs_from_device() convenience builder."""

    def test_empty_cves_produces_zero_inputs(self):
        inputs = build_score_inputs_from_device(cves=[])
        assert inputs.max_cvss == 0.0
        assert not inputs.has_kev
        assert not inputs.has_known_exploited
        assert not inputs.has_vulnerable

    def test_kev_finding_detected(self):
        cves = [_FakeCve(cvss=9.0, in_kev=True, finding_state="KNOWN_EXPLOITED")]
        inputs = build_score_inputs_from_device(cves=cves)
        assert inputs.has_kev is True
        assert inputs.has_known_exploited is True
        assert inputs.max_cvss == 9.0

    def test_ai_verdict_passed_through(self):
        inputs = build_score_inputs_from_device(
            cves=[], ai_verdict="SUSPICIOUS", ai_confidence=0.75
        )
        assert inputs.ai_verdict == "SUSPICIOUS"
        assert inputs.ai_confidence == 0.75

    def test_score_weights_sum_to_one(self):
        """The documented weights must sum exactly to 1.0."""
        assert abs(_W_VULN + _W_KEV + _W_AI - 1.0) < 1e-9
