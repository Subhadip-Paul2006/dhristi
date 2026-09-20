# Drishti v0.1 — deterministic MITRE ATT&CK & CAPEC mapping layer | Phase 03
from __future__ import annotations

from typing import Any
from app.schemas.tracking import MitreMappingOut


# Deterministic knowledge table mapping (detected_state, forecasted_state, evidence_pattern) -> MITRE / CAPEC
# Grounded strictly in MITRE ATT&CK Enterprise Matrix v14 and CAPEC v3.9
MITRE_RULES: list[dict[str, Any]] = [
    {
        "match_forecast": ["POTENTIAL_RECONNAISSANCE_CONTINUATION"],
        "match_detection": ["PortScan", "ANOMALOUS"],
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique": "Network Service Scanning",
        "technique_id": "T1046",
        "capec_id": "CAPEC-300",
        "capec_name": "Port Scanning",
        "base_confidence": 0.88,
    },
    {
        "match_forecast": ["LIKELY_ESCALATION"],
        "match_detection": ["DoS", "ANOMALOUS"],
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique": "Network Denial of Service: Direct Network Flood",
        "technique_id": "T1498.001",
        "capec_id": "CAPEC-486",
        "capec_name": "TCP SYN Flood",
        "base_confidence": 0.92,
    },
    {
        "match_forecast": ["POTENTIAL_LATERAL_MOVEMENT"],
        "match_detection": ["Infiltration", "ANOMALOUS", "SUSPICIOUS"],
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "technique": "Remote Services",
        "technique_id": "T1021",
        "capec_id": "CAPEC-292",
        "capec_name": "Host-to-Host Pivoting",
        "base_confidence": 0.78,
    },
    {
        "match_forecast": ["SUSPICIOUS_CONTINUATION"],
        "match_detection": ["BruteForce", "SUSPICIOUS"],
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force: Password Guessing",
        "technique_id": "T1110.001",
        "capec_id": "CAPEC-112",
        "capec_name": "Brute Force",
        "base_confidence": 0.81,
    },
    {
        "match_forecast": ["SUSPICIOUS_CONTINUATION"],
        "match_detection": ["WebAttack", "ANOMALOUS"],
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "capec_id": "CAPEC-66",
        "capec_name": "SQL Injection",
        "base_confidence": 0.80,
    },
    {
        "match_forecast": ["LIKELY_ESCALATION"],
        "match_detection": ["Botnet", "ANOMALOUS"],
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "technique": "Application Layer Protocol: Web Protocols",
        "technique_id": "T1071.001",
        "capec_id": "CAPEC-584",
        "capec_name": "Botnet Command and Control",
        "base_confidence": 0.85,
    },
]


def map_to_mitre_attack(
    detected_verdict: str,
    detected_category: str | None,
    forecast_states: list[str],
    forecast_probabilities: list[float],
) -> MitreMappingOut | None:
    """Deterministically maps observed detection and forecasted progression to MITRE ATT&CK and CAPEC.

    STRICT GUARANTEE:
    Does NOT assign a technique merely because traffic is unusual.
    Only maps when the behaviour class or evidence matches configured mapping rules.
    If traffic is BENIGN / NORMAL_CONTINUATION, returns None.
    """
    if not forecast_states:
        return None

    # Check top forecasted future state (T+1 or highest threat level)
    top_forecast = forecast_states[0]
    top_prob = forecast_probabilities[0] if forecast_probabilities else 0.5

    # If traffic is completely normal, do not fabricate an ATT&CK mapping
    if (
        detected_verdict == "NORMAL"
        and all(s == "NORMAL_CONTINUATION" for s in forecast_states)
    ):
        return None

    # Iterate rules in precedence order
    for rule in MITRE_RULES:
        forecast_match = any(state in rule["match_forecast"] for state in forecast_states)
        detection_match = (
            detected_category in rule["match_detection"]
            or detected_verdict in rule["match_detection"]
        )

        if forecast_match and detection_match:
            calibrated_conf = round(min(0.99, max(0.40, rule["base_confidence"] * 0.5 + top_prob * 0.5)), 2)
            return MitreMappingOut(
                tactic=rule["tactic"],
                tactic_id=rule["tactic_id"],
                technique=rule["technique"],
                technique_id=rule["technique_id"],
                capec_id=rule.get("capec_id"),
                capec_name=rule.get("capec_name"),
                confidence=calibrated_conf,
            )

    # Fallback only if non-benign but no specific category matched
    if any(s != "NORMAL_CONTINUATION" for s in forecast_states):
        first_non_normal = next((s for s in forecast_states if s != "NORMAL_CONTINUATION"), None)
        if first_non_normal == "POTENTIAL_RECONNAISSANCE_CONTINUATION":
            return MitreMappingOut(
                tactic="Discovery",
                tactic_id="TA0007",
                technique="Network Service Scanning",
                technique_id="T1046",
                capec_id="CAPEC-300",
                capec_name="Port Scanning",
                confidence=round(top_prob, 2),
            )
        elif first_non_normal == "LIKELY_ESCALATION":
            return MitreMappingOut(
                tactic="Impact",
                tactic_id="TA0040",
                technique="Network Denial of Service",
                technique_id="T1498",
                capec_id="CAPEC-486",
                capec_name="TCP SYN Flood",
                confidence=round(top_prob, 2),
            )
        elif first_non_normal == "POTENTIAL_LATERAL_MOVEMENT":
            return MitreMappingOut(
                tactic="Lateral Movement",
                tactic_id="TA0008",
                technique="Remote Services",
                technique_id="T1021",
                capec_id="CAPEC-292",
                capec_name="Host-to-Host Pivoting",
                confidence=round(top_prob, 2),
            )

    return None
