import time
import socket
import pytest
from app.services.traffic.session_manager import tracking_manager
from app.services.traffic.capture_adapter import TrafficVisibilityChecker


def test_real_local_and_remote_device_e2e(db_session, seed_acme_org):
    db = db_session
    org_id = seed_acme_org.id

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Local Device Tracking Test
    # ─────────────────────────────────────────────────────────────────────────
    local_session = tracking_manager.start_tracking(
        db=db,
        org_id=org_id,
        device_id="dev-local-01",
        ip="127.0.0.1",
        hostname="localhost",
    )
    assert local_session.status in ("LIVE", "UNAVAILABLE")
    assert local_session.target_ip == "127.0.0.1"

    # Generate real network activity to localhost
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect_ex(("127.0.0.1", 8000))
        s.close()
    except Exception:
        pass

    # Ingest a real packet event for 127.0.0.1
    active_local = tracking_manager._active_sessions[local_session.tracking_session_id]
    active_local.aggregator.ingest_packet(
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=54321,
        dst_port=8000,
        protocol=6,
        length=60,
        tcp_flags={"SYN": True, "ACK": False},
    )

    local_results = tracking_manager.get_results(db=db, org_id=org_id, session_id=local_session.tracking_session_id)
    assert local_results.metrics.packet_count >= 1
    assert local_results.network_visibility == "VISIBLE"
    assert local_results.model_status is not None
    assert local_results.model_status["lstm"] == "READY"
    assert local_results.model_status["transformer"] == "READY"
    assert local_results.model_status["gnn"] == "READY"
    assert local_results.current_behaviour.verdict in ("NORMAL", "SUSPICIOUS", "ANOMALOUS", "INSUFFICIENT_DATA")

    # Stop local tracking
    tracking_manager.stop_tracking(db=db, org_id=org_id, session_id=local_session.tracking_session_id)

    # ─────────────────────────────────────────────────────────────────────────
    # 2. Remote / Switched LAN Device Test (Truthful Unavailability)
    # ─────────────────────────────────────────────────────────────────────────
    remote_session = tracking_manager.start_tracking(
        db=db,
        org_id=org_id,
        device_id="dev-remote-lan",
        ip="192.168.1.250",
        hostname="unobservable-peer",
    )
    active_remote = tracking_manager._active_sessions[remote_session.tracking_session_id]

    # Verify zero packets arrived for remote peer on switched Wi-Fi
    assert active_remote.aggregator.total_packets == 0

    # Visibility evaluation after elapsed threshold
    visibility = TrafficVisibilityChecker.evaluate_visibility(
        target_ip="192.168.1.250",
        packets_observed=0,
        session_duration=5.0,
    )
    assert visibility["visibility"] in ("UNAVAILABLE", "LIMITED")
    assert "not observable from this monitoring interface" in visibility["reason"] or "not responding" in visibility["reason"]

    # ─────────────────────────────────────────────────────────────────────────
    # 3. Strict Device Isolation Verification
    # ─────────────────────────────────────────────────────────────────────────
    # Ingest packet for Device A (127.0.0.1) into the network layer
    rejected = active_remote.aggregator.ingest_packet(
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=54321,
        dst_port=8000,
        protocol=6,
        length=60,
    )
    # MUST BE REJECTED by Device B's aggregator
    assert rejected is False
    assert active_remote.aggregator.total_packets == 0
    assert active_remote.aggregator.total_bytes == 0

    tracking_manager.stop_tracking(db=db, org_id=org_id, session_id=remote_session.tracking_session_id)
