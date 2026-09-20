# Drishti v0.1 — deterministic composite risk engine | Phase 03
# Mathematically calculates risk scores from current detection, future forecast, and graph dynamics
from __future__ import annotations

from typing import Any


RISK_FORMULA_DOCUMENTATION = (
    "Score = 0.40 * DetectionScore + 0.45 * ForecastScore + GraphModifier. "
    "Thresholds: CRITICAL >= 75 | HIGH >= 50 | MEDIUM >= 25 | LOW < 25."
)


def calculate_composite_risk(
    detected_verdict: str,
    detected_category: str | None,
    forecast_steps: list[dict[str, Any]],
    graph_dynamics: list[str],
) -> tuple[float, str, str]:
    """Calculates composite risk level using an explicit deterministic formula.

    Returns:
      (composite_score: float, risk_level: str, formula_doc: str)
    """
    # 1. Detection score [0 .. 100]
    if detected_verdict == "ANOMALOUS":
        det_score = 95.0 if detected_category in ("DoS", "Botnet") else 85.0
    elif detected_verdict == "SUSPICIOUS":
        det_score = 55.0
    elif detected_verdict == "NORMAL":
        det_score = 10.0
    else:  # INSUFFICIENT_DATA
        det_score = 0.0

    # 2. Forecast threat component [0 .. 100]
    forecast_scores = []
    for step in forecast_steps:
        st = step.get("state", "NORMAL_CONTINUATION")
        prob = float(step.get("probability", 0.0))

        if st == "LIKELY_ESCALATION":
            base = 95.0
        elif st == "POTENTIAL_LATERAL_MOVEMENT":
            base = 82.0
        elif st == "POTENTIAL_RECONNAISSANCE_CONTINUATION":
            base = 72.0
        elif st == "SUSPICIOUS_CONTINUATION":
            base = 50.0
        else:
            base = 5.0

        forecast_scores.append(base * prob)

    fore_score = max(forecast_scores) if forecast_scores else 5.0

    # 3. Graph dynamics modifier [0 .. 15]
    graph_modifier = 0.0
    for gd in graph_dynamics:
        lower = gd.lower()
        if "expansion" in lower or "fan-out" in lower:
            graph_modifier += 8.0
        elif "new communication" in lower:
            graph_modifier += 5.0

    graph_modifier = min(15.0, graph_modifier)

    # 4. Composite weighted sum
    composite = round(0.40 * det_score + 0.45 * fore_score + graph_modifier, 1)
    composite = max(0.0, min(100.0, composite))

    # 5. Severity Categorization
    if composite >= 75.0:
        level = "CRITICAL"
    elif composite >= 50.0:
        level = "HIGH"
    elif composite >= 25.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    return composite, level, RISK_FORMULA_DOCUMENTATION
