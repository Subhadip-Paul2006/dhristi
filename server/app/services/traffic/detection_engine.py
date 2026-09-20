# Drishti v0.1 — real-time current threat & anomaly detection engine | Phase 01
from __future__ import annotations

import logging
from typing import Any
from app.schemas.tracking import CurrentBehaviourOut

logger = logging.getLogger("drishti")


class TrafficDetectionEngine:
    """Evaluates CURRENT behaviour on observed network traffic flows for a single target device.

    Strictly CURRENT DETECTION ONLY:
    Answers 'What is happening on this device's observed network traffic RIGHT NOW?'
    Never performs future forecasting or remediation generation.
    """

    def __init__(self) -> None:
        pass

    def evaluate_traffic(
        self,
        features: dict[str, float],
        total_packets: int,
        flow_count: int,
        unique_ports: int,
    ) -> CurrentBehaviourOut:
        # 1. Check for Insufficient Data threshold
        if total_packets < 3 or flow_count == 0:
            return CurrentBehaviourOut(
                verdict="INSUFFICIENT_DATA",
                confidence=0.0,
                signals=["Insufficient observed traffic for reliable detection (minimum 3 packets required)"],
                attack_category=None,
            )

        signals: list[str] = []
        is_anomalous = False
        is_suspicious = False
        detected_category: str | None = None
        confidence: float = 0.85

        syn_count = features.get("flag_syn_count", 0.0)
        ack_count = features.get("flag_ack_count", 0.0)
        pps = features.get("flow_packets_per_sec", 0.0)
        bps = features.get("flow_bytes_per_sec", 0.0)
        entropy = features.get("payload_entropy", 0.0)

        # ── Signal Check A: Volumetric Flooding / DoS ────────────────────────
        if (pps > 600.0 and total_packets >= 20) or syn_count > 150:
            is_anomalous = True
            detected_category = "DoS"
            confidence = 0.94
            signals.append(f"Abnormal packet rate burst: {pps:.1f} packets/sec exceeds normal desktop baseline")
            if syn_count > 100:
                signals.append(f"Rapid TCP SYN transmission: {int(syn_count)} SYN packets in active session")

        # ── Signal Check B: Port Scan Signature ──────────────────────────────
        elif unique_ports >= 5 or (syn_count >= 10 and ack_count <= 2):
            is_anomalous = True
            detected_category = "PortScan"
            confidence = min(0.98, 0.75 + (unique_ports * 0.03))
            signals.append(
                f"Elevated horizontal/vertical port activity: {unique_ports} distinct destination ports contacted"
            )
            if syn_count > ack_count * 3:
                signals.append(f"High unacknowledged SYN ratio: {int(syn_count)} SYNs vs {int(ack_count)} ACKs")

        # ── Signal Check C: High Entropy / Potential Infiltration ────────────
        elif entropy > 7.1 and bps > 50000.0:
            is_suspicious = True
            detected_category = "Infiltration"
            confidence = 0.82
            signals.append(
                f"Elevated payload entropy ({entropy:.2f} bits/byte) with sustained transfer rate ({bps:.0f} B/s)"
            )

        # ── Signal Check D: Repeated Single-Port Connection Anomalies ────────
        elif syn_count > 25 and ack_count < 3 and unique_ports == 1:
            is_suspicious = True
            detected_category = "BruteForce"
            confidence = 0.80
            signals.append("Repetitive connection attempts to single port without established session (possible auth brute-force)")

        # ── Signal Check E: Normal Benign Traffic Baseline ───────────────────
        if not is_anomalous and not is_suspicious:
            signals.append("Observed traffic aligns with typical benign communication profiles")
            signals.append(f"Balanced flow characteristics ({int(features.get('total_fwd_packets', 0))} fwd / {int(features.get('total_bwd_packets', 0))} bwd pkts)")
            if ack_count > 0:
                signals.append("Valid TCP handshakes and completed transport streams")
            return CurrentBehaviourOut(
                verdict="NORMAL",
                confidence=0.92,
                signals=signals,
                attack_category=None,
            )

        verdict = "ANOMALOUS" if is_anomalous else "SUSPICIOUS"
        return CurrentBehaviourOut(
            verdict=verdict,
            confidence=round(confidence, 2),
            signals=signals,
            attack_category=detected_category,
        )
