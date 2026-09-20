# Drishti v0.1 — model-compatible 32-feature extractor | Phase 01
from __future__ import annotations

from typing import Any
from app.services.traffic.flow_aggregator import FlowAggregator, FlowRecord

# Canonical feature keys matching datasets/*.csv schema
FEATURE_NAMES: list[str] = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_mean",
    "bwd_iat_std",
    "flag_syn_count",
    "flag_ack_count",
    "flag_fin_count",
    "flag_rst_count",
    "flag_psh_count",
    "flag_urg_count",
    "fwd_avg_bytes_per_pkt",
    "bwd_avg_bytes_per_pkt",
    "active_mean",
    "idle_mean",
    "port_scan_score",
    "mean_ttl",
    "mean_tcp_window",
    "payload_entropy",
]


def extract_features_from_flow(flow: FlowRecord, port_scan_score: int = 1) -> dict[str, float]:
    """Extract model-compatible features from a single FlowRecord matching dataset schema."""
    return {
        "flow_duration": round(flow.duration, 4),
        "total_fwd_packets": float(flow.total_fwd_packets),
        "total_bwd_packets": float(flow.total_bwd_packets),
        "total_fwd_bytes": float(flow.total_fwd_bytes),
        "total_bwd_bytes": float(flow.total_bwd_bytes),
        "flow_bytes_per_sec": float(flow.flow_bytes_per_sec),
        "flow_packets_per_sec": float(flow.flow_packets_per_sec),
        "fwd_iat_mean": round(flow.fwd_iat_mean, 4),
        "fwd_iat_std": round(flow.fwd_iat_std, 4),
        "fwd_iat_max": round(flow.fwd_iat_max, 4),
        "fwd_iat_min": round(flow.fwd_iat_min, 4),
        "bwd_iat_mean": round(flow.bwd_iat_mean, 4),
        "bwd_iat_std": round(flow.bwd_iat_std, 4),
        "flag_syn_count": float(flow.flag_syn_count),
        "flag_ack_count": float(flow.flag_ack_count),
        "flag_fin_count": float(flow.flag_fin_count),
        "flag_rst_count": float(flow.flag_rst_count),
        "flag_psh_count": float(flow.flag_psh_count),
        "flag_urg_count": float(flow.flag_urg_count),
        "fwd_avg_bytes_per_pkt": float(flow.fwd_avg_bytes_per_pkt),
        "bwd_avg_bytes_per_pkt": float(flow.bwd_avg_bytes_per_pkt),
        "active_mean": round(flow.duration * 0.8, 4),
        "idle_mean": round(flow.duration * 0.2, 4),
        "port_scan_score": float(port_scan_score),
        "mean_ttl": round(flow.mean_ttl, 2),
        "mean_tcp_window": round(flow.mean_tcp_window, 2),
        "payload_entropy": round(flow.payload_entropy, 4),
    }


def extract_session_features(aggregator: FlowAggregator) -> dict[str, float]:
    """Aggregate all observed flows for the target device into a composite feature vector."""
    flows = aggregator.get_all_flows()
    if not flows:
        return {k: 0.0 for k in FEATURE_NAMES}

    port_scan_score = len(aggregator.unique_dst_ports)
    total_fwd_pkts = sum(f.total_fwd_packets for f in flows)
    total_bwd_pkts = sum(f.total_bwd_packets for f in flows)
    total_fwd_bytes = sum(f.total_fwd_bytes for f in flows)
    total_bwd_bytes = sum(f.total_bwd_bytes for f in flows)
    total_duration = max(0.001, max(f.last_time for f in flows) - min(f.start_time for f in flows))
    total_pkts = total_fwd_pkts + total_bwd_pkts
    total_bytes = total_fwd_bytes + total_bwd_bytes

    return {
        "flow_duration": round(total_duration, 4),
        "total_fwd_packets": float(total_fwd_pkts),
        "total_bwd_packets": float(total_bwd_pkts),
        "total_fwd_bytes": float(total_fwd_bytes),
        "total_bwd_bytes": float(total_bwd_bytes),
        "flow_bytes_per_sec": round(total_bytes / total_duration, 2),
        "flow_packets_per_sec": round(total_pkts / total_duration, 2),
        "fwd_iat_mean": round(sum(f.fwd_iat_mean for f in flows) / len(flows), 4),
        "fwd_iat_std": round(sum(f.fwd_iat_std for f in flows) / len(flows), 4),
        "fwd_iat_max": round(max(f.fwd_iat_max for f in flows), 4),
        "fwd_iat_min": round(min(f.fwd_iat_min for f in flows), 4),
        "bwd_iat_mean": round(sum(f.bwd_iat_mean for f in flows) / len(flows), 4),
        "bwd_iat_std": round(sum(f.bwd_iat_std for f in flows) / len(flows), 4),
        "flag_syn_count": float(sum(f.flag_syn_count for f in flows)),
        "flag_ack_count": float(sum(f.flag_ack_count for f in flows)),
        "flag_fin_count": float(sum(f.flag_fin_count for f in flows)),
        "flag_rst_count": float(sum(f.flag_rst_count for f in flows)),
        "flag_psh_count": float(sum(f.flag_psh_count for f in flows)),
        "flag_urg_count": float(sum(f.flag_urg_count for f in flows)),
        "fwd_avg_bytes_per_pkt": round(total_fwd_bytes / total_fwd_pkts, 2) if total_fwd_pkts > 0 else 0.0,
        "bwd_avg_bytes_per_pkt": round(total_bwd_bytes / total_bwd_pkts, 2) if total_bwd_pkts > 0 else 0.0,
        "active_mean": round(total_duration * 0.75, 4),
        "idle_mean": round(total_duration * 0.25, 4),
        "port_scan_score": float(port_scan_score),
        "mean_ttl": round(sum(f.mean_ttl for f in flows) / len(flows), 2),
        "mean_tcp_window": round(sum(f.mean_tcp_window for f in flows) / len(flows), 2),
        "payload_entropy": round(sum(f.payload_entropy for f in flows) / len(flows), 4),
    }
