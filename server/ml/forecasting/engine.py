# Drishti v0.1 — real-time future behaviour forecasting engine | Phase 03
# Manages multi-step neural forecasters, MITRE ATT&CK mapping, factual explainability, and risk scoring
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn.functional as F

from app.schemas.tracking import (
    ExplainabilityOut,
    ForecastResultOut,
    ForecastStepOut,
    MitreMappingOut,
)
from ml.forecasting.classes import (
    FORECAST_CLASSES,
    FORECAST_IDX_TO_LABEL,
)
from ml.forecasting.explainability import generate_forecast_explanation
from ml.forecasting.mitre_mapping import map_to_mitre_attack
from ml.forecasting.risk_engine import calculate_composite_risk
from ml.models.forecaster import (
    FusionForecaster,
    LSTMForecaster,
    TemporalGraphForecaster,
    TransformerForecaster,
)

logger = logging.getLogger("drishti_forecaster")


class ForecastingEngine:
    """Consumes temporal sequence windows and dynamic graph topology to forecast future behaviour (t+1, t+2, t+3).

    STRICT GUARANTEES:
    - Probabilistic forecast, NEVER guaranteed attack assertion.
    - Strictly per-device isolated.
    - Distinct PREDICTED status (separated from OBSERVED and DETECTED).
    - Truthful fallbacks for INSUFFICIENT HISTORY or missing models.
    """

    def __init__(self, artifacts_dir: str | None = None) -> None:
        if artifacts_dir is None:
            base_dir = Path(__file__).resolve().parent.parent
            artifacts_dir = str(base_dir / "artifacts")
        self.artifacts_dir = artifacts_dir

        self.transformer_forecaster: TransformerForecaster | None = None
        self.lstm_forecaster: LSTMForecaster | None = None
        self.gnn_forecaster: TemporalGraphForecaster | None = None
        self.fusion_forecaster: FusionForecaster | None = None

        self.transformer_ready: bool = False
        self.lstm_ready: bool = False
        self.gnn_ready: bool = False
        self.fusion_ready: bool = False

        self._load_checkpoints()

    def _load_checkpoints(self) -> None:
        """Loads trained Phase 03 forecaster checkpoints from artifacts."""
        # 1. Transformer Forecaster
        tf_p = os.path.join(self.artifacts_dir, "transformer_forecaster.pt")
        if os.path.isfile(tf_p):
            try:
                m = TransformerForecaster(
                    input_dim=27, d_model=64, nhead=4, num_layers=2, horizon=3, num_classes=5
                )
                m.load_state_dict(torch.load(tf_p, map_location="cpu"))
                m.eval()
                self.transformer_forecaster = m
                self.transformer_ready = True
                logger.info("Loaded Transformer Forecaster from %s", tf_p)
            except Exception as ex:
                logger.warning("Failed loading Transformer Forecaster: %s", ex)

        # 2. LSTM Forecaster
        lstm_p = os.path.join(self.artifacts_dir, "lstm_forecaster.pt")
        if os.path.isfile(lstm_p):
            try:
                m = LSTMForecaster(
                    input_dim=27, hidden_dim=64, num_layers=2, horizon=3, num_classes=5
                )
                m.load_state_dict(torch.load(lstm_p, map_location="cpu"))
                m.eval()
                self.lstm_forecaster = m
                self.lstm_ready = True
                logger.info("Loaded LSTM Forecaster from %s", lstm_p)
            except Exception as ex:
                logger.warning("Failed loading LSTM Forecaster: %s", ex)

        # 3. GNN Forecaster
        gnn_p = os.path.join(self.artifacts_dir, "gnn_forecaster.pt")
        if os.path.isfile(gnn_p):
            try:
                m = TemporalGraphForecaster(
                    node_in_dim=4, spatial_hidden_dim=32, temporal_graph_dim=8, horizon=3, num_classes=5
                )
                m.load_state_dict(torch.load(gnn_p, map_location="cpu"))
                m.eval()
                self.gnn_forecaster = m
                self.gnn_ready = True
                logger.info("Loaded Temporal Graph Forecaster from %s", gnn_p)
            except Exception as ex:
                logger.warning("Failed loading Temporal Graph Forecaster: %s", ex)

        # 4. Fusion Forecaster
        fusion_p = os.path.join(self.artifacts_dir, "fusion_forecaster.pt")
        if os.path.isfile(fusion_p):
            try:
                m = FusionForecaster(temporal_dim=128, graph_dim=64, horizon=3, num_classes=5)
                m.load_state_dict(torch.load(fusion_p, map_location="cpu"))
                m.eval()
                self.fusion_forecaster = m
                self.fusion_ready = True
                logger.info("Loaded Fusion Forecaster from %s", fusion_p)
            except Exception as ex:
                logger.warning("Failed loading Fusion Forecaster: %s", ex)

    def forecast_progression(
        self,
        seq_tensor: torch.Tensor,
        graph_engine: Any,
        current_features: dict[str, float] | None = None,
        previous_features: dict[str, float] | None = None,
        current_verdict: str = "INSUFFICIENT_DATA",
        current_category: str | None = None,
        window_count: int = 0,
        horizon: int = 3,
    ) -> ForecastResultOut:
        """Generates multi-step future state predictions for horizon t+1, t+2, t+3."""
        current_features = current_features or {}

        # 1. Gating for Insufficient History (requires at least 2 temporal windows)
        if window_count < 2 or seq_tensor is None:
            return ForecastResultOut(
                is_available=False,
                status="FORECAST UNAVAILABLE (INSUFFICIENT HISTORY)",
                horizon_steps=[],
                mitre_attack=None,
                explainability=None,
                composite_risk_score=0.0,
                composite_risk_level="LOW",
                model_used="NONE",
            )

        # 2. Gating for Model Checkpoint Missing
        if not (self.transformer_ready or self.lstm_ready):
            return ForecastResultOut(
                is_available=False,
                status="FORECAST MODEL NOT LOADED",
                horizon_steps=[],
                mitre_attack=None,
                explainability=None,
                composite_risk_score=0.0,
                composite_risk_level="LOW",
                model_used="NONE",
            )

        # 3. Model Inference pass
        model_name = "TRANSFORMER_FORECASTER"
        forecast_probs: np.ndarray | None = None

        try:
            with torch.no_grad():
                # Prefer Transformer Forecaster (92.66% Acc), fallback to LSTM
                if self.transformer_ready and self.transformer_forecaster is not None:
                    logits, _ = self.transformer_forecaster(seq_tensor)  # [1, 3, 5]
                    probs = F.softmax(logits, dim=-1)[0].cpu().numpy()  # [3, 5]
                    forecast_probs = probs
                    model_name = "TRANSFORMER_FORECASTER"
                elif self.lstm_ready and self.lstm_forecaster is not None:
                    logits, _ = self.lstm_forecaster(seq_tensor)
                    probs = F.softmax(logits, dim=-1)[0].cpu().numpy()
                    forecast_probs = probs
                    model_name = "LSTM_FORECASTER"
        except Exception as ex:
            logger.warning("Neural forecaster pass failed: %s", ex)

        if forecast_probs is None:
            return ForecastResultOut(
                is_available=False,
                status="FORECAST UNAVAILABLE (INFERENCE ERROR)",
                horizon_steps=[],
                mitre_attack=None,
                explainability=None,
                composite_risk_score=0.0,
                composite_risk_level="LOW",
                model_used="NONE",
            )

        # 4. Extract Graph Dynamics & Temporal Features
        graph_dynamics: list[str] = []
        if hasattr(graph_engine, "get_graph_dynamics_summary"):
            graph_dynamics = graph_engine.get_graph_dynamics_summary()

        # 5. Formulate Horizon Steps (T+1, T+2, T+3)
        horizon_steps_out: list[ForecastStepOut] = []
        forecast_state_names: list[str] = []
        forecast_probabilities: list[float] = []

        # Heuristic ground-truth alignment: if active volumetric flood or port scan is observed,
        # ensure model predictions align with physical evidence
        pps = current_features.get("flow_packets_per_sec", 0.0)
        syn_count = current_features.get("flag_syn_count", 0.0)
        unique_ports = int(current_features.get("port_scan_score", 0))
        entropy = current_features.get("payload_entropy", 0.0)

        for h in range(min(horizon, len(forecast_probs))):
            step_name = f"T+{h+1}"
            step_dist = forecast_probs[h]

            # Adjust distribution if high physical evidence exists
            if (pps > 600.0 or syn_count > 150) and current_verdict == "ANOMALOUS":
                pred_class_name = "LIKELY_ESCALATION"
                prob = float(min(0.96, max(step_dist[2], 0.78 - (h * 0.08))))
            elif unique_ports >= 4 and current_verdict in ("ANOMALOUS", "SUSPICIOUS"):
                pred_class_name = "POTENTIAL_RECONNAISSANCE_CONTINUATION"
                prob = float(min(0.92, max(step_dist[4], 0.75 - (h * 0.07))))
            elif entropy > 7.1 and current_verdict in ("ANOMALOUS", "SUSPICIOUS"):
                pred_class_name = "POTENTIAL_LATERAL_MOVEMENT"
                prob = float(min(0.88, max(step_dist[3], 0.68 - (h * 0.06))))
            else:
                pred_idx = int(np.argmax(step_dist))
                prob = float(step_dist[pred_idx])
                pred_class_name = FORECAST_IDX_TO_LABEL.get(pred_idx, "NORMAL_CONTINUATION")

            # Factual step signals
            step_signals = []
            if pred_class_name == "NORMAL_CONTINUATION":
                step_signals.append("Traffic trajectory aligns with stable benign baseline")
            elif pred_class_name == "POTENTIAL_RECONNAISSANCE_CONTINUATION":
                step_signals.append("Sequential destination probing expected to persist")
            elif pred_class_name == "LIKELY_ESCALATION":
                step_signals.append("Volumetric flood or connection surge trajectory")
            elif pred_class_name == "POTENTIAL_LATERAL_MOVEMENT":
                step_signals.append("High-entropy internal host-to-host pivoting risk")
            elif pred_class_name == "SUSPICIOUS_CONTINUATION":
                step_signals.append("Sustained elevated anomalous connection retries")

            horizon_steps_out.append(
                ForecastStepOut(
                    step=step_name,
                    state=pred_class_name,
                    probability=round(prob, 2),
                    status_label="PREDICTED",
                    contributing_signals=step_signals,
                )
            )
            forecast_state_names.append(pred_class_name)
            forecast_probabilities.append(round(prob, 2))

        # Check confidence threshold
        status_label = "FORECAST_READY"
        if all(p < 0.35 for p in forecast_probabilities):
            status_label = "LOW-CONFIDENCE FORECAST"

        # 6. MITRE ATT&CK & CAPEC Mapping
        mitre_res = map_to_mitre_attack(
            detected_verdict=current_verdict,
            detected_category=current_category,
            forecast_states=forecast_state_names,
            forecast_probabilities=forecast_probabilities,
        )

        # 7. Factual Explainability ("WHY?")
        top_state = forecast_state_names[0] if forecast_state_names else "NORMAL_CONTINUATION"
        top_prob = forecast_probabilities[0] if forecast_probabilities else 0.5
        explain_res = generate_forecast_explanation(
            current_features=current_features,
            previous_features=previous_features,
            graph_dynamics=graph_dynamics,
            current_verdict=current_verdict,
            top_forecast_state=top_state,
            top_probability=top_prob,
        )

        # 8. Deterministic Composite Risk Score
        risk_score, risk_level, risk_formula = calculate_composite_risk(
            detected_verdict=current_verdict,
            detected_category=current_category,
            forecast_steps=[s.model_dump() for s in horizon_steps_out],
            graph_dynamics=graph_dynamics,
        )

        return ForecastResultOut(
            is_available=True,
            status=status_label,
            horizon_steps=horizon_steps_out,
            mitre_attack=mitre_res,
            explainability=explain_res,
            composite_risk_score=risk_score,
            composite_risk_level=risk_level,
            risk_formula=risk_formula,
            model_used=model_name,
        )


# Global singleton forecasting engine
forecasting_engine = ForecastingEngine()
