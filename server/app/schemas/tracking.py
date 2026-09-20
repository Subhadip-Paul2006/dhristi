# Drishti v0.1 — live per-device tracking schemas | Phase 01
from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class TrackingStartRequest(BaseModel):
    device_id: str = Field(..., description="Unique identifier for the target network device")
    ip: str = Field(..., description="Target IPv4 or IPv6 address")
    mac: str | None = Field(default=None, description="MAC address if known/on-link")
    hostname: str | None = Field(default=None, description="Discovered hostname or label")


class TrackingStopRequest(BaseModel):
    tracking_session_id: str = Field(..., description="Active session ID to terminate")


class TrackingSessionOut(BaseModel):
    tracking_session_id: str
    device_id: str
    target_ip: str
    target_mac: str | None = None
    target_hostname: str | None = None
    status: str  # STARTING | LIVE | STOPPED | ERROR | UNAVAILABLE
    capture_source: str  # MONITORED INTERFACE | ENDPOINT AGENT | SCAPY | UNAVAILABLE
    status_message: str | None = None
    started_at: datetime
    ended_at: datetime | None = None
    last_event_at: datetime | None = None
    packet_count: int = 0
    flow_count: int = 0
    byte_count: int = 0


class LiveTrafficMetrics(BaseModel):
    packet_count: int = 0
    flow_count: int = 0
    byte_count: int = 0
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    active_connections: int = 0


class ProtocolBreakdown(BaseModel):
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    dns: int = 0
    http_https: int = 0
    other: int = 0


class TopDestinationItem(BaseModel):
    destination_ip: str
    destination_port: int
    protocol: str
    connection_count: int = 1
    last_seen: datetime | None = None


class CurrentBehaviourOut(BaseModel):
    verdict: str  # NORMAL | SUSPICIOUS | ANOMALOUS | INSUFFICIENT_DATA
    confidence: float = 0.0  # 0.0 to 1.0
    signals: list[str] = Field(default_factory=list)
    attack_category: str | None = None  # e.g., PortScan, DoS, BruteForce, Infiltration


class TrafficEvidenceItem(BaseModel):
    evidence_type: str = "NETWORK_TRAFFIC"
    source: str
    observed_at: datetime
    device_id: str
    confidence: str = "high"
    details: dict[str, Any] = Field(default_factory=dict)


class ForecastStepOut(BaseModel):
    step: str  # T+1 | T+2 | T+3
    state: str  # NORMAL_CONTINUATION | SUSPICIOUS_CONTINUATION | LIKELY_ESCALATION | POTENTIAL_LATERAL_MOVEMENT | POTENTIAL_RECONNAISSANCE_CONTINUATION | INSUFFICIENT_HISTORY
    probability: float = 0.0
    status_label: str = "PREDICTED"  # OBSERVED | DETECTED | PREDICTED | POTENTIAL | CONFIRMED
    contributing_signals: list[str] = Field(default_factory=list)


class MitreMappingOut(BaseModel):
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    capec_id: str | None = None
    capec_name: str | None = None
    confidence: float = 0.0


class ExplainabilityOut(BaseModel):
    top_signals: list[str] = Field(default_factory=list)
    state_transition: str = "STEADY"
    graph_dynamics: list[str] = Field(default_factory=list)
    feature_deltas: dict[str, float] = Field(default_factory=dict)


class ForecastResultOut(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    is_available: bool = False
    status: str = "FORECAST UNAVAILABLE (INSUFFICIENT HISTORY)"
    horizon_steps: list[ForecastStepOut] = Field(default_factory=list)
    mitre_attack: MitreMappingOut | None = None
    explainability: ExplainabilityOut | None = None
    composite_risk_score: float = 0.0
    composite_risk_level: str = "LOW"  # LOW | MEDIUM | HIGH | CRITICAL
    risk_formula: str = "Score = 0.40 * Detection + 0.45 * Max(Forecast_i * Conf_i) + 0.15 * GraphDynamics"
    model_used: str = "NONE"



class TrackingResultsOut(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    session: TrackingSessionOut
    metrics: LiveTrafficMetrics
    protocols: ProtocolBreakdown
    top_destinations: list[TopDestinationItem] = Field(default_factory=list)
    current_behaviour: CurrentBehaviourOut
    evidence: list[TrafficEvidenceItem] = Field(default_factory=list)
    features: dict[str, float] | None = None
    model_status: dict[str, str] | None = None
    network_visibility: str | None = None
    visibility_reason: str | None = None
    window_count: int | None = None
    graph_summary: dict[str, Any] | None = None
    forecast: ForecastResultOut | None = None

