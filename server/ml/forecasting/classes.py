# Drishti v0.1 — future attack forecasting class definitions | Phase 03
from __future__ import annotations

FORECAST_CLASSES = [
    "NORMAL_CONTINUATION",
    "SUSPICIOUS_CONTINUATION",
    "LIKELY_ESCALATION",
    "POTENTIAL_LATERAL_MOVEMENT",
    "POTENTIAL_RECONNAISSANCE_CONTINUATION",
]

FORECAST_LABEL_TO_IDX = {name: idx for idx, name in enumerate(FORECAST_CLASSES)}
FORECAST_IDX_TO_LABEL = {idx: name for idx, name in enumerate(FORECAST_CLASSES)}

# Mapping from Phase 02 current threat classes to future forecast targets
DETECTION_TO_FORECAST_MAP: dict[str, str] = {
    "BENIGN": "NORMAL_CONTINUATION",
    "PortScan": "POTENTIAL_RECONNAISSANCE_CONTINUATION",
    "DoS": "LIKELY_ESCALATION",
    "Botnet": "LIKELY_ESCALATION",
    "Infiltration": "POTENTIAL_LATERAL_MOVEMENT",
    "BruteForce": "SUSPICIOUS_CONTINUATION",
    "WebAttack": "SUSPICIOUS_CONTINUATION",
    "Generic": "SUSPICIOUS_CONTINUATION",
}


def map_flow_label_to_forecast_target(flow_label: str) -> int:
    """Deterministically maps raw or normalized flow label into a forecast target index."""
    cleaned = str(flow_label).strip()
    target_class = DETECTION_TO_FORECAST_MAP.get(cleaned)
    if target_class is None:
        lower = cleaned.lower()
        if "dos" in lower or "ddos" in lower or "bot" in lower:
            target_class = "LIKELY_ESCALATION"
        elif "port" in lower or "scan" in lower:
            target_class = "POTENTIAL_RECONNAISSANCE_CONTINUATION"
        elif "infiltr" in lower or "pivot" in lower:
            target_class = "POTENTIAL_LATERAL_MOVEMENT"
        elif "brute" in lower or "patator" in lower or "web" in lower:
            target_class = "SUSPICIOUS_CONTINUATION"
        elif "benign" in lower:
            target_class = "NORMAL_CONTINUATION"
        else:
            target_class = "SUSPICIOUS_CONTINUATION"

    return FORECAST_LABEL_TO_IDX[target_class]
