# Drishti v0.1 — Phase 03 future network behaviour forecasting comprehensive tests
# Covers: sequence creation, multi-step targets, chronological split, models, graph dynamics,
# MITRE mapping, explainability, risk scoring, device isolation, and truthful gating.
from __future__ import annotations

import numpy as np
import pytest
import torch

from app.schemas.tracking import ForecastResultOut, TrackingResultsOut
from app.services.traffic.flow_aggregator import FlowRecord
from app.services.traffic.graph_engine import NetworkGraphEngine
from app.services.traffic.session_manager import ActiveTrackingSession, SessionManager
from ml.forecasting.classes import (
    FORECAST_CLASSES,
    FORECAST_IDX_TO_LABEL,
    FORECAST_LABEL_TO_IDX,
    map_flow_label_to_forecast_target,
)
from ml.forecasting.engine import ForecastingEngine
from ml.forecasting.explainability import generate_forecast_explanation
from ml.forecasting.mitre_mapping import map_to_mitre_attack
from ml.forecasting.risk_engine import calculate_composite_risk
from ml.models.forecaster import (
    FusionForecaster,
    LSTMForecaster,
    TemporalGraphForecaster,
    TransformerForecaster,
)
from ml.training.train_forecaster import (
    build_forecasting_sequences,
    split_chronological_with_buffer,
)
from ml.preprocessing.scaler import TrafficPreprocessor


# ── Test 1: Sequence Creation & Shape ─────────────────────────────────────────
def test_sequence_creation_shape():
    preprocessor = TrafficPreprocessor()
    # Dummy data
    import pandas as pd
    from ml.preprocessing.scaler import CANONICAL_FEATURE_NAMES
    data = {feat: np.random.randn(20) for feat in CANONICAL_FEATURE_NAMES}
    data["forecast_target"] = [0] * 20
    df = pd.DataFrame(data)
    preprocessor.fit(df)

    seq_len = 5
    horizon = 3
    X, y = build_forecasting_sequences(df, preprocessor, seq_len=seq_len, horizon=horizon)

    expected_samples = 20 - (seq_len + horizon) + 1
    assert X.shape == (expected_samples, 5, 27)
    assert y.shape == (expected_samples, 3)


# ── Test 2: Future Target Generation Alignment ────────────────────────────────
def test_future_target_generation_alignment():
    import pandas as pd
    from ml.preprocessing.scaler import CANONICAL_FEATURE_NAMES
    data = {feat: np.zeros(12) for feat in CANONICAL_FEATURE_NAMES}
    data["forecast_target"] = list(range(12))
    df = pd.DataFrame(data)
    preprocessor = TrafficPreprocessor()
    preprocessor.fit(df)

    X, y = build_forecasting_sequences(df, preprocessor, seq_len=5, horizon=3)
    # First sequence uses indices [0, 1, 2, 3, 4], targets must be [5, 6, 7]
    assert list(y[0]) == [5, 6, 7]
    # Second sequence uses indices [1, 2, 3, 4, 5], targets must be [6, 7, 8]
    assert list(y[1]) == [6, 7, 8]


# ── Test 3: Chronological Split (No-Leakage Buffer) ───────────────────────────
def test_chronological_split_no_leakage():
    X = np.arange(100).reshape(100, 1)
    y = np.arange(100).reshape(100, 1)
    buffer_gap = 8
    X_train, y_train, X_val, y_val, X_test, y_test = split_chronological_with_buffer(
        X, y, train_ratio=0.70, val_ratio=0.15, buffer_gap=buffer_gap
    )
    # Train ends at index 69
    assert y_train[-1][0] == 69
    # Val starts at 69 + buffer_gap + 1 = 78
    assert y_val[0][0] == 70 + buffer_gap
    # No index overlap exists
    assert set(y_train.flatten()).isdisjoint(set(y_val.flatten()))
    assert set(y_val.flatten()).isdisjoint(set(y_test.flatten()))
    assert set(y_train.flatten()).isdisjoint(set(y_test.flatten()))


# ── Test 4: LSTM Forecaster Multi-Step Output Shape & Probabilities ───────────
def test_lstm_forecaster_output():
    model = LSTMForecaster(input_dim=27, hidden_dim=64, num_layers=2, horizon=3, num_classes=5)
    x = torch.randn(4, 5, 27)
    logits, emb = model(x)
    assert logits.shape == (4, 3, 5)
    assert emb.shape == (4, 128)
    probs = torch.softmax(logits, dim=-1)
    assert torch.allclose(torch.sum(probs, dim=-1), torch.ones(4, 3), atol=1e-5)


# ── Test 5: Transformer Forecaster Multi-Step Output Shape & Probabilities ────
def test_transformer_forecaster_output():
    model = TransformerForecaster(input_dim=27, d_model=64, nhead=4, num_layers=2, horizon=3, num_classes=5)
    x = torch.randn(2, 5, 27)
    logits, emb = model(x)
    assert logits.shape == (2, 3, 5)
    assert emb.shape == (2, 64)
    probs = torch.softmax(logits, dim=-1)
    assert torch.allclose(torch.sum(probs, dim=-1), torch.ones(2, 3), atol=1e-5)


# ── Test 6: Temporal Graph History [G_t-2, G_t-1, G_t] ────────────────────────
def test_graph_history_snapshots():
    import time
    t = time.time()
    engine = NetworkGraphEngine(target_ip="192.168.1.50")
    assert len(engine.history) == 1  # Initial baseline snapshot

    # Simulate window 1 flow
    flow1 = FlowRecord(src_ip="192.168.1.50", dst_ip="10.0.0.1", src_port=50000, dst_port=80, protocol=6, start_time=t, last_time=t)
    engine.update_from_flows([flow1])
    engine.snapshot()
    assert len(engine.history) == 2

    # Simulate window 2 flow
    flow2 = FlowRecord(src_ip="192.168.1.50", dst_ip="10.0.0.2", src_port=50001, dst_port=443, protocol=6, start_time=t, last_time=t)
    engine.update_from_flows([flow2])
    engine.snapshot()
    assert len(engine.history) == 3

    # Ensure maxlen=3 is respected on next snapshot
    engine.snapshot()
    assert len(engine.history) == 3


# ── Test 7: Temporal Graph Topological Velocity Features ──────────────────────
def test_graph_temporal_features():
    import time
    t = time.time()
    engine = NetworkGraphEngine(target_ip="192.168.1.50")
    flow1 = FlowRecord(src_ip="192.168.1.50", dst_ip="10.0.0.1", src_port=50000, dst_port=80, protocol=6, start_time=t, last_time=t)
    flow1.fwd_packets = 10
    flow1.fwd_bytes = 1000
    engine.update_from_flows([flow1])
    engine.snapshot()

    # Add second flow creating new node & edge
    flow2 = FlowRecord(src_ip="192.168.1.50", dst_ip="10.0.0.2", src_port=50001, dst_port=22, protocol=6, start_time=t, last_time=t)
    flow2.fwd_packets = 50
    flow2.fwd_bytes = 5000
    engine.update_from_flows([flow2])
    engine.snapshot()

    feats = engine.get_temporal_graph_features()
    assert feats.shape == (8,)
    # d_nodes > 0, d_edges > 0, topo_velocity > 0
    assert feats[0] >= 1.0  # delta_nodes
    assert feats[1] >= 1.0  # delta_edges
    assert feats[6] > 0.0  # topological velocity
    assert feats[7] == 3.0  # history depth


# ── Test 8: Multimodal Fusion Forecaster ──────────────────────────────────────
def test_fusion_forecaster():
    model = FusionForecaster(temporal_dim=128, graph_dim=64, horizon=3, num_classes=5)
    temp_emb = torch.randn(3, 128)
    graph_emb = torch.randn(3, 64)
    out = model(temp_emb, graph_emb)
    assert out.shape == (3, 3, 5)


# ── Test 9: Calibrated Confidence Output ──────────────────────────────────────
def test_confidence_calibration():
    engine = ForecastingEngine()
    x = torch.zeros(1, 5, 27)
    graph_engine = NetworkGraphEngine(target_ip="192.168.1.50")
    graph_engine.snapshot()

    res = engine.forecast_progression(
        seq_tensor=x,
        graph_engine=graph_engine,
        current_features={"flow_packets_per_sec": 10.0},
        current_verdict="NORMAL",
        window_count=3,
        horizon=3,
    )
    assert res.is_available is True
    for step in res.horizon_steps:
        assert 0.0 <= step.probability <= 1.0
        assert step.status_label == "PREDICTED"


# ── Test 10: Device Isolation & No Cross-Device Leakage ───────────────────────
def test_device_isolation():
    active_a = ActiveTrackingSession(
        session_id="sess-A", org_id="org-1", device_id="dev-A", target_ip="192.168.1.10"
    )
    active_b = ActiveTrackingSession(
        session_id="sess-B", org_id="org-1", device_id="dev-B", target_ip="192.168.1.20"
    )

    # Ingest packet strictly for Device A
    active_a.aggregator.ingest_packet(
        src_ip="192.168.1.10", dst_ip="8.8.8.8", src_port=1000, dst_port=53, protocol=17, length=64
    )

    summary_a = active_a.aggregator.get_summary_metrics()
    summary_b = active_b.aggregator.get_summary_metrics()

    assert summary_a["packet_count"] == 1
    assert summary_b["packet_count"] == 0



# ── Test 11: Configurable Forecast Horizon (T+1, T+2, T+3) ────────────────────
def test_forecast_horizon():
    engine = ForecastingEngine()
    x = torch.randn(1, 5, 27)
    graph_engine = NetworkGraphEngine(target_ip="192.168.1.50")
    graph_engine.snapshot()

    res = engine.forecast_progression(
        seq_tensor=x,
        graph_engine=graph_engine,
        current_features={"flow_packets_per_sec": 10.0},
        current_verdict="NORMAL",
        window_count=3,
        horizon=3,
    )
    assert len(res.horizon_steps) == 3
    assert [s.step for s in res.horizon_steps] == ["T+1", "T+2", "T+3"]


# ── Test 12: Truthful Gating: Insufficient History ────────────────────────────
def test_insufficient_history_fallback():
    engine = ForecastingEngine()
    x = torch.randn(1, 5, 27)
    graph_engine = NetworkGraphEngine(target_ip="192.168.1.50")

    # Only 1 window recorded (< 2 threshold)
    res = engine.forecast_progression(
        seq_tensor=x,
        graph_engine=graph_engine,
        window_count=1,
    )
    assert res.is_available is False
    assert "INSUFFICIENT HISTORY" in res.status
    assert len(res.horizon_steps) == 0


# ── Test 13: Truthful Gating: Missing Checkpoints ─────────────────────────────
def test_missing_checkpoints_fallback():
    engine = ForecastingEngine(artifacts_dir="/non/existent/path")
    x = torch.randn(1, 5, 27)
    graph_engine = NetworkGraphEngine(target_ip="192.168.1.50")

    res = engine.forecast_progression(
        seq_tensor=x,
        graph_engine=graph_engine,
        window_count=5,
    )
    assert res.is_available is False
    assert "MODEL NOT LOADED" in res.status


# ── Test 14: Forecast State Labels Supported ──────────────────────────────────
def test_forecast_classes_membership():
    for class_name in [
        "NORMAL_CONTINUATION",
        "SUSPICIOUS_CONTINUATION",
        "LIKELY_ESCALATION",
        "POTENTIAL_LATERAL_MOVEMENT",
        "POTENTIAL_RECONNAISSANCE_CONTINUATION",
    ]:
        assert class_name in FORECAST_CLASSES
        idx = FORECAST_LABEL_TO_IDX[class_name]
        assert FORECAST_IDX_TO_LABEL[idx] == class_name


# ── Test 15: Strict Observed vs Predicted Separation ──────────────────────────
def test_observed_vs_predicted_separation():
    engine = ForecastingEngine()
    x = torch.randn(1, 5, 27)
    graph_engine = NetworkGraphEngine(target_ip="192.168.1.50")
    graph_engine.snapshot()

    res = engine.forecast_progression(
        seq_tensor=x,
        graph_engine=graph_engine,
        current_features={"flow_packets_per_sec": 10.0},
        current_verdict="NORMAL",
        window_count=3,
        horizon=3,
    )
    for step in res.horizon_steps:
        # Every future forecast must have explicit PREDICTED status
        assert step.status_label == "PREDICTED"


# ── Test 16: Deterministic MITRE ATT&CK & CAPEC Mapping ───────────────────────
def test_mitre_mapping():
    # Reconnaissance mapping
    res = map_to_mitre_attack(
        detected_verdict="ANOMALOUS",
        detected_category="PortScan",
        forecast_states=["POTENTIAL_RECONNAISSANCE_CONTINUATION"],
        forecast_probabilities=[0.85],
    )
    assert res is not None
    assert res.tactic_id == "TA0007"
    assert res.technique_id == "T1046"
    assert res.capec_id == "CAPEC-300"

    # DoS escalation mapping
    res_dos = map_to_mitre_attack(
        detected_verdict="ANOMALOUS",
        detected_category="DoS",
        forecast_states=["LIKELY_ESCALATION"],
        forecast_probabilities=[0.92],
    )
    assert res_dos is not None
    assert res_dos.tactic_id == "TA0040"
    assert res_dos.technique_id == "T1498.001"
    assert res_dos.capec_id == "CAPEC-486"

    # Benign traffic returns None (no false technique assigned)
    res_benign = map_to_mitre_attack(
        detected_verdict="NORMAL",
        detected_category=None,
        forecast_states=["NORMAL_CONTINUATION", "NORMAL_CONTINUATION"],
        forecast_probabilities=[0.95, 0.94],
    )
    assert res_benign is None


# ── Test 17: Deterministic Risk Scoring ───────────────────────────────────────
def test_deterministic_risk_scoring():
    # Benign baseline
    score_low, level_low, _ = calculate_composite_risk(
        detected_verdict="NORMAL",
        detected_category=None,
        forecast_steps=[{"state": "NORMAL_CONTINUATION", "probability": 0.90}],
        graph_dynamics=["Stable network topology"],
    )
    assert level_low == "LOW"
    assert score_low < 25.0

    # High threat escalation with topological expansion
    score_crit, level_crit, formula = calculate_composite_risk(
        detected_verdict="ANOMALOUS",
        detected_category="DoS",
        forecast_steps=[{"state": "LIKELY_ESCALATION", "probability": 0.92}],
        graph_dynamics=["Topological expansion: +3 peer node(s), +5 communication edge(s)"],
    )
    assert level_crit == "CRITICAL"
    assert score_crit >= 75.0
    assert "Score = 0.40 * DetectionScore" in formula


# ── Test 18: Zero Fabrication Guarantee (No Fake Predictions) ─────────────────
def test_zero_fabrication_on_empty_features():
    engine = ForecastingEngine()
    graph_engine = NetworkGraphEngine(target_ip="192.168.1.50")
    # Without sequence tensor, never fabricate forecast
    res = engine.forecast_progression(
        seq_tensor=None,
        graph_engine=graph_engine,
        window_count=0,
    )
    assert res.is_available is False
    assert len(res.horizon_steps) == 0


# ── Test 19: Factual Explainability Attribution ───────────────────────────────
def test_explainability_factual_attribution():
    curr = {"flow_packets_per_sec": 750.0, "flag_syn_count": 220.0, "port_scan_score": 6.0}
    prev = {"flow_packets_per_sec": 120.0, "flag_syn_count": 10.0, "port_scan_score": 1.0}
    dynamics = ["New communication edge established with 192.168.1.120"]

    explanation = generate_forecast_explanation(
        current_features=curr,
        previous_features=prev,
        graph_dynamics=dynamics,
        current_verdict="ANOMALOUS",
        top_forecast_state="LIKELY_ESCALATION",
        top_probability=0.88,
    )
    assert len(explanation.top_signals) > 0
    assert explanation.state_transition == "ESCALATING"
    assert explanation.feature_deltas["delta_packets_per_sec"] == 630.0
    assert explanation.feature_deltas["delta_syn_count"] == 210.0
    assert explanation.feature_deltas["delta_unique_ports"] == 5.0
