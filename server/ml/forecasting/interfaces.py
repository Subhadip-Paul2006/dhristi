# Drishti v0.1 — future attack forecasting interface contract | Phase 03
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.schemas.tracking import ForecastResultOut
from ml.forecasting.engine import ForecastingEngine, forecasting_engine


@dataclass
class ForecastResult:
    is_available: bool = False
    status: str = "FORECAST_READY"
    forecasted_steps: list[dict[str, Any]] | None = None
    rationale: str = "Phase 03 multi-step temporal neural forecasting."


class ForecastingEngineInterface:
    """Architectural interface for future network behaviour forecasting.

    STRICT GUARANTEE:
    Never fabricates future attack predictions.
    Only returns probabilistic forecasts grounded in actual observed temporal sequences.
    """

    def __init__(self) -> None:
        self.engine: ForecastingEngine = forecasting_engine

    def forecast_progression(
        self,
        seq_tensor: Any,
        graph_engine: Any,
        current_features: dict[str, float] | None = None,
        previous_features: dict[str, float] | None = None,
        current_verdict: str = "INSUFFICIENT_DATA",
        current_category: str | None = None,
        window_count: int = 0,
        horizon_steps: int = 3,
    ) -> ForecastResultOut:
        return self.engine.forecast_progression(
            seq_tensor=seq_tensor,
            graph_engine=graph_engine,
            current_features=current_features,
            previous_features=previous_features,
            current_verdict=current_verdict,
            current_category=current_category,
            window_count=window_count,
            horizon=horizon_steps,
        )
