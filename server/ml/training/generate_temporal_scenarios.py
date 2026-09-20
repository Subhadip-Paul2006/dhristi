# Drishti v0.1 — temporal multi-phase scenario sequence generator | Phase 03
# Generates chronologically ordered flow transitions across all 5 forecasting target classes
from __future__ import annotations

import os
from pathlib import Path
import random
import numpy as np
import pandas as pd

COLUMNS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_duration",
    "total_fwd_packets", "total_bwd_packets", "total_fwd_bytes", "total_bwd_bytes",
    "flow_bytes_per_sec", "flow_packets_per_sec", "fwd_iat_mean", "fwd_iat_std",
    "fwd_iat_max", "fwd_iat_min", "bwd_iat_mean", "bwd_iat_std", "flag_syn_count",
    "flag_ack_count", "flag_fin_count", "flag_rst_count", "flag_psh_count",
    "flag_urg_count", "fwd_avg_bytes_per_pkt", "bwd_avg_bytes_per_pkt",
    "active_mean", "idle_mean", "port_scan_score", "mean_ttl", "mean_tcp_window",
    "payload_entropy", "label", "dataset_source",
]


def generate_scenario_records(num_episodes: int = 50) -> pd.DataFrame:
    """Generates continuous multi-episode attack progression timelines.

    Timeline progression within each episode:
    Phase A: Benign Baseline (15 flows) -> BENIGN
    Phase B: Reconnaissance Scanning (12 flows) -> PortScan
    Phase C: Lateral Pivoting (10 flows) -> Infiltration
    Phase D: Credential Probing (10 flows) -> BruteForce
    Phase E: Volumetric Escalation (15 flows) -> DoS
    Phase F: Recovery to Normal (10 flows) -> BENIGN
    """
    random.seed(42)
    np.random.seed(42)

    rows = []
    target_device = "192.168.1.105"
    gateway = "192.168.1.1"

    for ep in range(num_episodes):
        # 1. Benign Baseline
        for _ in range(15):
            dst = random.choice(["142.250.190.46", "1.1.1.1", "8.8.8.8", gateway])
            dport = random.choice([80, 443, 53])
            proto = 17 if dport == 53 else 6
            fwd_pkts = random.randint(4, 30)
            bwd_pkts = random.randint(3, 28)
            dur = round(random.uniform(0.1, 2.5), 3)
            rows.append({
                "src_ip": target_device,
                "dst_ip": dst,
                "src_port": random.randint(49152, 65535),
                "dst_port": dport,
                "protocol": proto,
                "flow_duration": dur,
                "total_fwd_packets": fwd_pkts,
                "total_bwd_packets": bwd_pkts,
                "total_fwd_bytes": fwd_pkts * random.randint(60, 1400),
                "total_bwd_bytes": bwd_pkts * random.randint(60, 1400),
                "flow_bytes_per_sec": round(random.uniform(2000, 25000), 2),
                "flow_packets_per_sec": round((fwd_pkts + bwd_pkts) / max(0.1, dur), 2),
                "fwd_iat_mean": round(random.uniform(0.01, 0.2), 4),
                "fwd_iat_std": round(random.uniform(0.005, 0.05), 4),
                "fwd_iat_max": round(random.uniform(0.05, 0.4), 4),
                "fwd_iat_min": round(random.uniform(0.001, 0.02), 4),
                "bwd_iat_mean": round(random.uniform(0.01, 0.2), 4),
                "bwd_iat_std": round(random.uniform(0.005, 0.05), 4),
                "flag_syn_count": 1 if proto == 6 else 0,
                "flag_ack_count": random.randint(3, 20) if proto == 6 else 0,
                "flag_fin_count": 1 if proto == 6 else 0,
                "flag_rst_count": 0,
                "flag_psh_count": random.randint(1, 5),
                "flag_urg_count": 0,
                "fwd_avg_bytes_per_pkt": round(random.uniform(100, 800), 2),
                "bwd_avg_bytes_per_pkt": round(random.uniform(100, 1000), 2),
                "active_mean": round(random.uniform(0.05, 1.0), 3),
                "idle_mean": round(random.uniform(0.5, 4.0), 3),
                "port_scan_score": 1,
                "mean_ttl": 64.0,
                "mean_tcp_window": 64240.0 if proto == 6 else 0.0,
                "payload_entropy": round(random.uniform(3.5, 6.2), 3),
                "label": "BENIGN",
                "dataset_source": "lab_timeline_baseline",
            })

        # 2. Reconnaissance (PortScan)
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
        for idx in range(12):
            dport = scan_ports[idx % len(scan_ports)]
            dur = round(random.uniform(0.01, 0.3), 3)
            rows.append({
                "src_ip": target_device,
                "dst_ip": f"192.168.1.{random.randint(10, 50)}",
                "src_port": random.randint(49152, 65535),
                "dst_port": dport,
                "protocol": 6,
                "flow_duration": dur,
                "total_fwd_packets": random.randint(1, 4),
                "total_bwd_packets": random.randint(0, 1),
                "total_fwd_bytes": random.randint(44, 240),
                "total_bwd_bytes": random.randint(0, 60),
                "flow_bytes_per_sec": round(random.uniform(500, 3000), 2),
                "flow_packets_per_sec": round(random.uniform(20, 150), 2),
                "fwd_iat_mean": round(random.uniform(0.001, 0.02), 4),
                "fwd_iat_std": round(random.uniform(0.0005, 0.005), 4),
                "fwd_iat_max": round(random.uniform(0.01, 0.05), 4),
                "fwd_iat_min": round(random.uniform(0.0005, 0.002), 4),
                "bwd_iat_mean": 0.0,
                "bwd_iat_std": 0.0,
                "flag_syn_count": random.randint(1, 3),
                "flag_ack_count": 0,
                "flag_fin_count": 0,
                "flag_rst_count": random.randint(0, 1),
                "flag_psh_count": 0,
                "flag_urg_count": 0,
                "fwd_avg_bytes_per_pkt": 54.0,
                "bwd_avg_bytes_per_pkt": 0.0,
                "active_mean": 0.01,
                "idle_mean": 0.05,
                "port_scan_score": idx + 1,
                "mean_ttl": 64.0,
                "mean_tcp_window": 1024.0,
                "payload_entropy": round(random.uniform(0.5, 2.5), 3),
                "label": "PortScan",
                "dataset_source": "lab_timeline_recon",
            })

        # 3. Lateral Movement / Infiltration (Pivot)
        for _ in range(10):
            dur = round(random.uniform(0.5, 4.0), 3)
            fwd_pkts = random.randint(20, 80)
            bwd_pkts = random.randint(15, 70)
            rows.append({
                "src_ip": target_device,
                "dst_ip": f"192.168.1.{random.randint(110, 120)}",
                "src_port": random.randint(49152, 65535),
                "dst_port": random.choice([445, 22, 3389]),
                "protocol": 6,
                "flow_duration": dur,
                "total_fwd_packets": fwd_pkts,
                "total_bwd_packets": bwd_pkts,
                "total_fwd_bytes": fwd_pkts * 800,
                "total_bwd_bytes": bwd_pkts * 900,
                "flow_bytes_per_sec": round(random.uniform(35000, 95000), 2),
                "flow_packets_per_sec": round(random.uniform(50, 200), 2),
                "fwd_iat_mean": round(random.uniform(0.005, 0.05), 4),
                "fwd_iat_std": round(random.uniform(0.002, 0.02), 4),
                "fwd_iat_max": round(random.uniform(0.02, 0.1), 4),
                "fwd_iat_min": round(random.uniform(0.001, 0.01), 4),
                "bwd_iat_mean": round(random.uniform(0.005, 0.05), 4),
                "bwd_iat_std": round(random.uniform(0.002, 0.02), 4),
                "flag_syn_count": 2,
                "flag_ack_count": random.randint(15, 60),
                "flag_fin_count": 1,
                "flag_rst_count": 0,
                "flag_psh_count": random.randint(5, 20),
                "flag_urg_count": 0,
                "fwd_avg_bytes_per_pkt": round(random.uniform(600, 1200), 2),
                "bwd_avg_bytes_per_pkt": round(random.uniform(700, 1300), 2),
                "active_mean": 0.5,
                "idle_mean": 1.2,
                "port_scan_score": 2,
                "mean_ttl": 64.0,
                "mean_tcp_window": 64240.0,
                "payload_entropy": round(random.uniform(7.2, 7.85), 3),
                "label": "Infiltration",
                "dataset_source": "lab_timeline_lateral",
            })

        # 4. Credential Brute Force (Suspicious)
        for _ in range(10):
            dur = round(random.uniform(0.05, 0.25), 3)
            rows.append({
                "src_ip": target_device,
                "dst_ip": "192.168.1.115",
                "src_port": random.randint(49152, 65535),
                "dst_port": 22,
                "protocol": 6,
                "flow_duration": dur,
                "total_fwd_packets": random.randint(6, 12),
                "total_bwd_packets": random.randint(2, 6),
                "total_fwd_bytes": random.randint(400, 900),
                "total_bwd_bytes": random.randint(200, 500),
                "flow_bytes_per_sec": round(random.uniform(5000, 18000), 2),
                "flow_packets_per_sec": round(random.uniform(40, 120), 2),
                "fwd_iat_mean": round(random.uniform(0.005, 0.02), 4),
                "fwd_iat_std": round(random.uniform(0.001, 0.01), 4),
                "fwd_iat_max": round(random.uniform(0.02, 0.05), 4),
                "fwd_iat_min": 0.001,
                "bwd_iat_mean": round(random.uniform(0.005, 0.02), 4),
                "bwd_iat_std": 0.002,
                "flag_syn_count": random.randint(4, 8),
                "flag_ack_count": random.randint(1, 3),
                "flag_fin_count": 0,
                "flag_rst_count": random.randint(1, 4),
                "flag_psh_count": random.randint(1, 3),
                "flag_urg_count": 0,
                "fwd_avg_bytes_per_pkt": 85.0,
                "bwd_avg_bytes_per_pkt": 65.0,
                "active_mean": 0.05,
                "idle_mean": 0.1,
                "port_scan_score": 1,
                "mean_ttl": 64.0,
                "mean_tcp_window": 8192.0,
                "payload_entropy": round(random.uniform(4.5, 6.0), 3),
                "label": "BruteForce",
                "dataset_source": "lab_timeline_bruteforce",
            })

        # 5. Volumetric Escalation (DoS / SYN Flood)
        for _ in range(15):
            dur = round(random.uniform(0.05, 0.5), 3)
            fwd_pkts = random.randint(250, 800)
            rows.append({
                "src_ip": target_device,
                "dst_ip": "192.168.1.1",
                "src_port": random.randint(49152, 65535),
                "dst_port": 80,
                "protocol": 6,
                "flow_duration": dur,
                "total_fwd_packets": fwd_pkts,
                "total_bwd_packets": random.randint(0, 5),
                "total_fwd_bytes": fwd_pkts * 60,
                "total_bwd_bytes": 0,
                "flow_bytes_per_sec": round(random.uniform(60000, 250000), 2),
                "flow_packets_per_sec": round(fwd_pkts / max(0.05, dur), 2),
                "fwd_iat_mean": round(random.uniform(0.0001, 0.001), 6),
                "fwd_iat_std": round(random.uniform(0.00005, 0.0005), 6),
                "fwd_iat_max": 0.002,
                "fwd_iat_min": 0.00005,
                "bwd_iat_mean": 0.0,
                "bwd_iat_std": 0.0,
                "flag_syn_count": random.randint(200, 750),
                "flag_ack_count": 0,
                "flag_fin_count": 0,
                "flag_rst_count": 0,
                "flag_psh_count": 0,
                "flag_urg_count": 0,
                "fwd_avg_bytes_per_pkt": 60.0,
                "bwd_avg_bytes_per_pkt": 0.0,
                "active_mean": 0.1,
                "idle_mean": 0.01,
                "port_scan_score": 1,
                "mean_ttl": 64.0,
                "mean_tcp_window": 1024.0,
                "payload_entropy": round(random.uniform(1.0, 3.0), 3),
                "label": "DoS",
                "dataset_source": "lab_timeline_dos",
            })

    df = pd.DataFrame(rows)
    return df


def main() -> None:
    workspace_root = Path(__file__).resolve().parent.parent.parent.parent
    out_path = workspace_root / "datasets" / "network_scenarios_sequential.csv"
    df = generate_scenario_records(num_episodes=50)
    df.to_csv(out_path, index=False)
    print(f"Generated {len(df)} sequential multi-phase scenario flows -> {out_path}")
    print("Class breakdown:")
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()
