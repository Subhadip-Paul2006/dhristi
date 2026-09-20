# Drishti v0.1 — per-device live network traffic tracking tests | Phase 01
from __future__ import annotations

import time
import pytest
from app.models import Organization
from app.schemas.tracking import TrackingStartRequest, TrackingStopRequest
from app.services.traffic.detection_engine import TrafficDetectionEngine
from app.services.traffic.feature_extractor import FEATURE_NAMES, extract_session_features
from app.services.traffic.flow_aggregator import FlowAggregator
from app.services.traffic.session_manager import SessionManager, tracking_manager


def test_flow_aggregator_and_device_isolation():
    """Verify flow aggregator creates flows and strictly isolates devices."""
    agg_a = FlowAggregator(target_ip="192.168.1.50", device_id="dev-a", session_id="sess-a")
    agg_b = FlowAggregator(target_ip="192.168.1.60", device_id="dev-b", session_id="sess-b")

    # Ingest packet for Device A (192.168.1.50 -> 8.8.8.8:53)
    accepted_a = agg_a.ingest_packet(
        src_ip="192.168.1.50",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=53,
        protocol=17,
        length=75,
    )
    assert accepted_a is True
    assert agg_a.total_packets == 1
    assert agg_a.total_bytes == 75

    # Device B MUST reject packet belonging to Device A (STRICT DEVICE ISOLATION)
    accepted_b = agg_b.ingest_packet(
        src_ip="192.168.1.50",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=53,
        protocol=17,
        length=75,
    )
    assert accepted_b is False
    assert agg_b.total_packets == 0
    assert agg_b.total_bytes == 0
    assert len(agg_b.get_all_flows()) == 0

    # Ingest return packet for Device A (8.8.8.8:53 -> 192.168.1.50)
    accepted_ret = agg_a.ingest_packet(
        src_ip="8.8.8.8",
        dst_ip="192.168.1.50",
        src_port=53,
        dst_port=54321,
        protocol=17,
        length=140,
    )
    assert accepted_ret is True
    assert agg_a.total_packets == 2
    assert agg_a.total_bytes == 215

    flows_a = agg_a.get_all_flows()
    assert len(flows_a) == 1
    flow = flows_a[0]
    assert flow.total_fwd_packets == 1
    assert flow.total_bwd_packets == 1
    assert flow.total_fwd_bytes == 75
    assert flow.total_bwd_bytes == 140

    # Top destinations check
    top_dests = agg_a.get_top_destinations()
    assert len(top_dests) == 1
    assert top_dests[0]["destination_ip"] == "8.8.8.8"
    assert top_dests[0]["destination_port"] == 53
    assert top_dests[0]["connection_count"] == 2

    # Protocols check
    protos = agg_a.get_protocols()
    assert protos["udp"] == 2
    assert protos["dns"] == 2
    assert protos["tcp"] == 0


def test_feature_extractor_schema_compatibility():
    """Verify extracted features match canonical dataset schema."""
    agg = FlowAggregator(target_ip="192.168.1.100", device_id="dev-1", session_id="sess-1")

    # Ingest 3 TCP packets with SYN and ACK flags
    agg.ingest_packet(
        src_ip="192.168.1.100",
        dst_ip="93.184.216.34",
        src_port=49152,
        dst_port=443,
        protocol=6,
        length=64,
        tcp_flags={"SYN": True, "ACK": False},
        ttl=64,
        tcp_window=65535,
    )
    agg.ingest_packet(
        src_ip="93.184.216.34",
        dst_ip="192.168.1.100",
        src_port=443,
        dst_port=49152,
        protocol=6,
        length=64,
        tcp_flags={"SYN": True, "ACK": True},
        ttl=55,
        tcp_window=28960,
    )
    agg.ingest_packet(
        src_ip="192.168.1.100",
        dst_ip="93.184.216.34",
        src_port=49152,
        dst_port=443,
        protocol=6,
        length=120,
        tcp_flags={"SYN": False, "ACK": True, "PSH": True},
        ttl=64,
        tcp_window=65535,
        payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )

    features = extract_session_features(agg)
    for name in FEATURE_NAMES:
        assert name in features, f"Missing expected dataset feature: {name}"
        assert isinstance(features[name], (int, float))

    assert features["total_fwd_packets"] == 2.0
    assert features["total_bwd_packets"] == 1.0
    assert features["flag_syn_count"] == 2.0
    assert features["flag_ack_count"] == 2.0
    assert features["port_scan_score"] == 1.0
    assert features["payload_entropy"] > 0.0


def test_detection_engine_current_detection():
    """Verify detection engine outputs CURRENT DETECTION ONLY with factual signals."""
    detector = TrafficDetectionEngine()

    # 1. Insufficient data (< 3 packets)
    insufficient = detector.evaluate_traffic(
        features={"flow_packets_per_sec": 1.0},
        total_packets=2,
        flow_count=1,
        unique_ports=1,
    )
    assert insufficient.verdict == "INSUFFICIENT_DATA"
    assert "Insufficient" in insufficient.signals[0]

    # 2. Benign normal traffic
    normal = detector.evaluate_traffic(
        features={
            "flow_packets_per_sec": 12.0,
            "flow_bytes_per_sec": 2400.0,
            "flag_syn_count": 2.0,
            "flag_ack_count": 4.0,
            "payload_entropy": 3.5,
            "total_fwd_packets": 5,
            "total_bwd_packets": 5,
        },
        total_packets=10,
        flow_count=2,
        unique_ports=2,
    )
    assert normal.verdict == "NORMAL"
    assert normal.confidence >= 0.85
    assert any("benign" in s.lower() for s in normal.signals)

    # 3. Port scan detection
    port_scan = detector.evaluate_traffic(
        features={
            "flow_packets_per_sec": 50.0,
            "flow_bytes_per_sec": 4000.0,
            "flag_syn_count": 15.0,
            "flag_ack_count": 0.0,
            "payload_entropy": 1.2,
        },
        total_packets=15,
        flow_count=8,
        unique_ports=8,
    )
    assert port_scan.verdict == "ANOMALOUS"
    assert port_scan.attack_category == "PortScan"
    assert any("distinct destination ports" in s for s in port_scan.signals)

    # 4. Volumetric flood / DoS
    dos = detector.evaluate_traffic(
        features={
            "flow_packets_per_sec": 850.0,
            "flow_bytes_per_sec": 500000.0,
            "flag_syn_count": 200.0,
            "flag_ack_count": 1.0,
            "payload_entropy": 2.0,
        },
        total_packets=500,
        flow_count=10,
        unique_ports=2,
    )
    assert dos.verdict == "ANOMALOUS"
    assert dos.attack_category == "DoS"
    assert any("Abnormal packet rate" in s for s in dos.signals)


def test_tracking_manager_session_lifecycle(db_session, seed_acme_org):
    """Verify session manager start, get, and stop lifecycle in DB and memory."""
    mgr = SessionManager()

    # Start tracking session for Device 1
    session = mgr.start_tracking(
        db=db_session,
        org_id=seed_acme_org.id,
        device_id="dev-test-1",
        ip="192.168.1.88",
        mac="aa:bb:cc:dd:ee:ff",
        hostname="lab-workstation-1",
    )
    assert session.tracking_session_id is not None
    assert session.device_id == "dev-test-1"
    assert session.target_ip == "192.168.1.88"
    assert session.target_mac == "aa:bb:cc:dd:ee:ff"
    assert session.target_hostname == "lab-workstation-1"
    assert session.status in ("LIVE", "STARTING", "UNAVAILABLE")

    # Ingest mock packet into active session aggregator
    active = mgr._active_sessions[session.tracking_session_id]
    active.aggregator.ingest_packet(
        src_ip="192.168.1.88",
        dst_ip="1.1.1.1",
        src_port=51234,
        dst_port=53,
        protocol=17,
        length=80,
    )
    active.aggregator.ingest_packet(
        src_ip="1.1.1.1",
        dst_ip="192.168.1.88",
        src_port=53,
        dst_port=51234,
        protocol=17,
        length=120,
    )
    active.aggregator.ingest_packet(
        src_ip="192.168.1.88",
        dst_ip="1.1.1.1",
        src_port=51235,
        dst_port=53,
        protocol=17,
        length=90,
    )

    # Get live results
    results = mgr.get_results(db_session, seed_acme_org.id, session.tracking_session_id)
    assert results.session.tracking_session_id == session.tracking_session_id
    assert results.metrics.packet_count == 3
    assert results.metrics.byte_count == 290
    assert results.protocols.udp == 3
    assert results.protocols.dns == 3
    assert len(results.top_destinations) == 1
    assert results.top_destinations[0].destination_ip == "1.1.1.1"
    assert results.current_behaviour.verdict in ("NORMAL", "INSUFFICIENT_DATA")
    assert len(results.evidence) > 0
    assert results.evidence[0].evidence_type == "NETWORK_TRAFFIC"
    assert results.evidence[0].device_id == "dev-test-1"

    # Stop tracking
    stopped = mgr.stop_tracking(db_session, seed_acme_org.id, session.tracking_session_id)
    assert stopped.status == "STOPPED"
    assert stopped.ended_at is not None
    assert stopped.packet_count == 3

    # Re-retrieve stopped session results (retained history)
    post_stop_results = mgr.get_results(db_session, seed_acme_org.id, session.tracking_session_id)
    assert post_stop_results.session.status == "STOPPED"
    assert post_stop_results.metrics.packet_count == 3


def test_api_endpoints(client, user_headers):
    """Verify FastAPI routes for tracking: start -> results -> stop."""
    # 1. Start tracking
    start_payload = {
        "device_id": "dev-api-1",
        "ip": "192.168.1.200",
        "mac": "11:22:33:44:55:66",
        "hostname": "test-device",
    }
    res = client.post("/api/live/tracking/start", json=start_payload, headers=user_headers)
    assert res.status_code == 200, res.text
    data = res.json()
    session_id = data["tracking_session_id"]
    assert data["target_ip"] == "192.168.1.200"

    # 2. Get status
    res_status = client.get(f"/api/live/tracking/{session_id}", headers=user_headers)
    assert res_status.status_code == 200
    assert res_status.json()["tracking_session_id"] == session_id

    # 3. Get results
    res_results = client.get(f"/api/live/tracking/{session_id}/results", headers=user_headers)
    assert res_results.status_code == 200
    r_data = res_results.json()
    assert "metrics" in r_data
    assert "protocols" in r_data
    assert "current_behaviour" in r_data
    assert "evidence" in r_data

    # 4. Stop tracking
    stop_payload = {"tracking_session_id": session_id}
    res_stop = client.post("/api/live/tracking/stop", json=stop_payload, headers=user_headers)
    assert res_stop.status_code == 200
    assert res_stop.json()["status"] == "STOPPED"
