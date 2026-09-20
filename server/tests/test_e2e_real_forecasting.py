# Drishti v0.1 — Phase 03 real live end-to-end forecasting pipeline test
# Validates real flow lifecycle: packets -> flows -> features -> window sequence -> current detection -> future forecast
from __future__ import annotations

import time
import pytest
from app.services.traffic.session_manager import ActiveTrackingSession, SessionManager


def test_real_live_e2e_forecasting_pipeline():
    """E2E Test: Real packet flow -> Time Windows -> AI Detection -> Multi-Step Forecast."""
    manager = SessionManager()
    local_target_ip = "127.0.0.1"

    session = ActiveTrackingSession(
        session_id="e2e-sess-forecast-1",
        org_id="org-e2e",
        device_id="dev-local-1",
        target_ip=local_target_ip,
        capture_source="SCAPY / LOCAL TESTBED",
    )

    # Ingest packets across 2 distinct temporal windows to satisfy window threshold (>= 2)
    now = time.time()
    from datetime import datetime, timezone
    session.started_at = datetime.fromtimestamp(now - 30.0, tz=timezone.utc)
    session.window_engine.start_time = now - 30.0

    # Window 1 packets (SYN flood / DoS pattern simulation)
    for i in range(25):
        session.aggregator.ingest_packet(
            src_ip=local_target_ip,
            dst_ip="10.0.0.1",
            src_port=40000 + i,
            dst_port=80,
            protocol=6,
            length=64,
            tcp_flags="S",
            timestamp=now - 12.0,
        )
        session.window_engine.ingest_event(
            src_ip=local_target_ip,
            dst_ip="10.0.0.1",
            src_port=40000 + i,
            dst_port=80,
            protocol=6,
            length=64,
            tcp_flags="S",
            timestamp=now - 12.0,
        )

    # Slide window 1
    session.window_engine.slide_and_compute(current_time=now - 6.0)
    session.graph_engine.update_from_flows(session.aggregator.get_all_flows())
    session.graph_engine.snapshot()

    # Window 2 packets
    for i in range(30):
        session.aggregator.ingest_packet(
            src_ip=local_target_ip,
            dst_ip="10.0.0.1",
            src_port=40100 + i,
            dst_port=80,
            protocol=6,
            length=64,
            tcp_flags="S",
            timestamp=now,
        )
        session.window_engine.ingest_event(
            src_ip=local_target_ip,
            dst_ip="10.0.0.1",
            src_port=40100 + i,
            dst_port=80,
            protocol=6,
            length=64,
            tcp_flags="S",
            timestamp=now,
        )

    # Slide window 2
    session.window_engine.slide_and_compute(current_time=now)
    manager._active_sessions[session.session_id] = session

    # Query Results
    results = manager.get_results(db=None, org_id="org-e2e", session_id=session.session_id)

    # Assertions
    assert results.metrics.packet_count == 55
    assert results.current_behaviour.verdict in ("SUSPICIOUS", "ANOMALOUS", "NORMAL")
    assert results.forecast is not None
    assert results.forecast.is_available is True
    assert len(results.forecast.horizon_steps) == 3

    # Verify multi-step forecast properties
    assert [s.step for s in results.forecast.horizon_steps] == ["T+1", "T+2", "T+3"]
    for step in results.forecast.horizon_steps:
        assert step.status_label == "PREDICTED"
        assert 0.0 <= step.probability <= 1.0

    # Verify explainability ("WHY?")
    assert results.forecast.explainability is not None
    assert len(results.forecast.explainability.top_signals) > 0
    assert results.forecast.explainability.state_transition != ""

    # Verify deterministic risk scoring
    assert results.forecast.composite_risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert 0.0 <= results.forecast.composite_risk_score <= 100.0


def test_unobservable_target_reports_unavailable_without_fake_forecast():
    """Validates truthful fallback when target device traffic is unobservable."""
    manager = SessionManager()
    remote_unobservable_ip = "192.168.1.250"

    from datetime import datetime, timedelta, timezone

    session = ActiveTrackingSession(
        session_id="e2e-unavail-1",
        org_id="org-e2e",
        device_id="dev-remote-unavail",
        target_ip=remote_unobservable_ip,
        capture_source="SCAPY / MONITORED INTERFACE",
    )
    session.started_at = datetime.now(timezone.utc) - timedelta(seconds=20.0)

    manager._active_sessions[session.session_id] = session

    # Query results with zero packets
    results = manager.get_results(db=None, org_id="org-e2e", session_id=session.session_id)

    # Truthful visibility check
    assert results.metrics.packet_count == 0
    assert results.network_visibility == "UNAVAILABLE"
    # Zero fabricated forecast
    assert results.forecast is not None
    assert results.forecast.is_available is False
    assert "INSUFFICIENT HISTORY" in results.forecast.status
