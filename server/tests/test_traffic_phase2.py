# Drishti v0.1 — Phase 02 Comprehensive Test Suite
import os
import torch
import pytest
from app.services.traffic.capture_adapter import detect_capture_backends, TrafficVisibilityChecker
from app.services.traffic.flow_aggregator import FlowAggregator
from app.services.traffic.graph_engine import NetworkGraphEngine
from app.services.traffic.time_window import TimeWindowEngine
from ml.models.fusion import FusionDetector
from ml.models.gnn import GraphNetworkDetector
from ml.models.temporal import LSTMDetector, TransformerDetector
from ml.preprocessing.scaler import TrafficPreprocessor, CANONICAL_FEATURE_NAMES
from ml.inference.engine import ModelInferenceEngine


def test_traffic_preprocessor():
    preprocessor = TrafficPreprocessor()
    assert len(preprocessor.feature_names) == 27
    sample_feat = {k: 1.0 for k in CANONICAL_FEATURE_NAMES}
    transformed = preprocessor.transform_dict(sample_feat)
    assert len(transformed) == 27


def test_time_window_engine():
    engine = TimeWindowEngine(target_device_id="dev-test", target_ip="192.168.1.50")
    engine.ingest_event(
        src_ip="192.168.1.50",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=53,
        protocol=17,
        length=64,
        timestamp=1000.0,
    )
    windows = engine.slide_and_compute(current_time=1005.0)
    assert len(windows) >= 1
    tensor = engine.get_sequence_tensor()
    assert tensor.shape == (1, 5, 27)


def test_network_graph_engine():
    graph = NetworkGraphEngine(target_ip="192.168.1.50")
    agg = FlowAggregator(target_ip="192.168.1.50", device_id="dev-test", session_id="sess-test")
    agg.ingest_packet(
        src_ip="192.168.1.50",
        dst_ip="1.1.1.1",
        src_port=50000,
        dst_port=443,
        protocol=6,
        length=120,
    )
    graph.update_from_flows(agg.get_all_flows())
    node_feat, norm_adj = graph.get_graph_tensors()
    assert node_feat.shape[0] >= 2
    assert node_feat.shape[1] == 4
    assert norm_adj.shape[0] == node_feat.shape[0]
    assert norm_adj.shape[1] == node_feat.shape[0]


def test_lstm_forward_pass():
    model = LSTMDetector(input_dim=27, hidden_dim=64, num_layers=2, num_classes=8)
    dummy_input = torch.randn(2, 5, 27)
    logits, emb = model(dummy_input)
    assert logits.shape == (2, 8)
    assert emb.shape == (2, 128)


def test_transformer_forward_pass():
    model = TransformerDetector(input_dim=27, d_model=64, nhead=4, num_layers=2, num_classes=8)
    dummy_input = torch.randn(2, 5, 27)
    logits, emb = model(dummy_input)
    assert logits.shape == (2, 8)
    assert emb.shape == (2, 64)


def test_gnn_forward_pass():
    model = GraphNetworkDetector(node_in_dim=4, hidden_dim=32, num_classes=8)
    node_feat = torch.randn(3, 4)
    norm_adj = torch.eye(3)
    logits, emb = model(node_feat, norm_adj)
    assert logits.shape == (1, 8)
    assert emb.shape == (1, 64)


def test_fusion_forward_pass():
    model = FusionDetector(temporal_dim=128, graph_dim=64, num_classes=8)
    temp_emb = torch.randn(2, 128)
    graph_emb = torch.randn(2, 64)
    logits = model(temp_emb, graph_emb)
    assert logits.shape == (2, 8)


def test_traffic_visibility_checker():
    # Localhost should be identified as local IP
    assert TrafficVisibilityChecker.is_local_ip("127.0.0.1") is True
    # Evaluates visibility when packets observed
    res = TrafficVisibilityChecker.evaluate_visibility("127.0.0.1", packets_observed=10, session_duration=2.0)
    assert res["visibility"] == "VISIBLE"


def test_capture_backends_detected():
    backends = detect_capture_backends()
    assert "active_backend" in backends
    assert "scapy" in backends
    assert "zeek" in backends
    assert "tshark" in backends
    assert backends["scapy"]["status"] == "AVAILABLE"


def test_model_inference_engine():
    engine = ModelInferenceEngine()
    status = engine.get_status()
    assert "lstm" in status
    assert "transformer" in status
    assert "gnn" in status

    # Evaluate live sequence
    dummy_seq = torch.randn(1, 5, 27)
    dummy_graph = (torch.randn(2, 4), torch.eye(2))
    verdict = engine.evaluate_live_traffic(
        seq_tensor=dummy_seq,
        graph_tensors=dummy_graph,
        total_packets=10,
        flow_count=2,
        features={"flag_syn_count": 5.0, "total_fwd_packets": 6.0, "total_bwd_packets": 4.0},
    )
    assert verdict.verdict in ("NORMAL", "SUSPICIOUS", "ANOMALOUS", "INSUFFICIENT_DATA")
    assert verdict.confidence > 0.0
    assert len(verdict.signals) > 0
