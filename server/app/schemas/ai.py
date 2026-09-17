# Drishti v0.1 — AI request/response schemas | 11-Jul-2026
"""AI request/response schemas (AI_INSTRUCTIONS.md §4–6)."""
from typing import Literal

from pydantic import BaseModel


class RemediateRequest(BaseModel):
    finding_id: str
    preferred_kind: Literal["ansible", "shell", "cloud_cli"] = "ansible"
    regenerate: bool = False


class RemediationOut(BaseModel):
    id: str | None = None
    refused: bool = False
    reason: str | None = None
    kind: str = "ansible"
    title: str = ""
    summary: str = ""
    script: str = ""
    steps: list[str] = []
    estimated_risk_reduction: float | None = None
    requires_restart: bool = False
    disclaimer: str = "Generated suggestion — review and test before running in production."
    reviewed: bool = False
    model: str | None = None
    # The exact finding context handed to the LLM (asset/service/vulnerability).
    # Surfaced in the UI as an input→output "what the AI saw" inspector so the
    # fix is verifiably grounded in real data, never invented.
    context: dict | None = None


class ImpactRequest(BaseModel):
    path_id: str


class ImpactOut(BaseModel):
    refused: bool = False
    reason: str | None = None
    impact_usd: float = 0.0
    headline: str = ""
    narrative: str = ""
    drivers: list[str] = []
    highest_leverage_action: str = ""


class PredictRequest(BaseModel):
    asset_id: str


class PredictionItem(BaseModel):
    asset: str
    likelihood: float
    reason: str
    defensive_action: str


class PredictOut(BaseModel):
    refused: bool = False
    reason: str | None = None
    from_asset: str = ""
    predictions: list[PredictionItem] = []
