"""Pydantic schemas for asset, finding, live, AI, and other endpoints."""
from __future__ import annotations
from pydantic import BaseModel
from datetime import datetime
from typing import Any


# ---- Assets ----
class AssetSummary(BaseModel):
 id: str
 ip: str
 hostname: str | None = ""
 zone: str = ""
 asset_type: str
 criticality: str
 internet_facing: bool = False
 risk_score: float | None = 0.0
 is_crown_jewel: bool = False
 blast_radius_count: int = 0
 downstream_value_usd: float = 0.0
 last_scanned_at: str | None = None

 class Config:
 from_attributes = True


class ServiceOut(BaseModel):
 id: str
 port: int
 protocol: str
 name: str
 version: str | None = None

 class Config:
 from_attributes = True


class FindingOut(BaseModel):
 id: str
 asset_id: str
 asset_ip: str = ""
 asset_hostname: str = ""
 cve_id: str = ""
 title: str
 severity: str
 cvss: float
 port: int | None = None
 service_name: str = ""
 status: str
 auto_resolved: bool = False
 accepted_until: str | None = None

 class Config:
 from_attributes = True


class AssetDetail(BaseModel):
 id: str
 ip: str
 hostname: str | None = ""
 os: str | None = ""
 zone: str = ""
 asset_type: str
 criticality: str
 internet_facing: bool = False
 base_value_usd: float
 risk_score: float | None = 0.0
 is_crown_jewel: bool = False
 blast_radius_count: int = 0
 downstream_value_usd: float = 0.0
 services: list[ServiceOut] = []
 findings: list[FindingOut] = []
 hardening: list[dict] = []

 class Config:
 from_attributes = True


# ---- Graph ----
class GraphNode(BaseModel):
 id: str
 type: str
 position: dict
 data: dict


class GraphEdge(BaseModel):
 id: str
 source: str
 target: str
 label: str = ""
 style: dict | None = None
 data: dict | None = None


class GraphResponse(BaseModel):
 nodes: list[GraphNode]
 edges: list[GraphEdge]
 zones: list[dict]
 live_devices: list[dict]
 network_threats: list[dict]


# ---- Paths ----
class PathSummary(BaseModel):
 path_id: str
 entry: dict
 target: dict
 hops: int
 risk_score: float
 likelihood: float
 impact_usd: float
 narrative: str = ""
 top_hop_labels: list[str] = []
 top_cves: list[str] = []

 class Config:
 from_attributes = True


# ---- Findings ----
class FindingUpdate(BaseModel):
 status: str | None = None
 accepted_until: str | None = None


# ---- Dashboard ----
class ZoneSummary(BaseModel):
 zone: str
 count: int
 exposure_usd: float = 0.0
 avg_risk: float = 0.0
 critical_count: int = 0


class DashboardOut(BaseModel):
 total_exposure_usd: float
 open_findings: int
 critical_assets: int
 top_path: PathSummary | None = None
 paths: list[PathSummary] = []
 zone_summary: list[ZoneSummary] = []
 severity_counts: dict[str, int] = {}
 last_recompute_at: str | None = None
 recompute_ms: float = 0.0


# ---- Live ----
class DeviceBatch(BaseModel):
 label: str = ""
 self_mac: str = ""
 gateway_ip: str = ""
 subnet: str = ""
 active_subnets: list[str] = []
 devices: list[dict] = []
 agent_id: str = ""


class LiveThreatOut(BaseModel):
 kind: str
 severity: str
 title: str
 detail: str
 device: str | None = None
 evidence: str
 recommendation: str
 mitre: str | None = None


class NetworkThreat(BaseModel):
 kind: str
 severity: str
 title: str
 detail: str
 device: str | None = None
 evidence: str
 recommendation: str
 mitre: str | None = None


class BlockFixOut(BaseModel):
 id: str
 domain: str
 action: str
 detail: str


# ---- Deep Scan ----
class DeepScanRequest(BaseModel):
 ip: str
 consent: bool = False


class DeepScanRangeRequest(BaseModel):
 cidr: str
 consent: bool = False


# ---- Netconfig ----
class NetconfigAnalyzeRequest(BaseModel):
 scan_dmz: bool = True
 scan_nat: bool = True
 scan_dhcp: bool = True


class NetconfigResult(BaseModel):
 dmz: dict | None = None
 nat: dict | None = None
 dhcp: dict | None = None


# ---- AI ----
class RemediateRequest(BaseModel):
 finding_id: str
 preferred_kind: str = "ansible"
 regenerate: bool = False


class RemediationOut(BaseModel):
 id: str | None = None
 refused: bool = False
 reason: str | None = None
 kind: str
 title: str
 summary: str
 script: str
 steps: list[str] = []
 estimated_risk_reduction: float | None = None
 requires_restart: bool = False
 disclaimer: str = "AI-generated. Validate in your environment."
 reviewed: bool = False
 model: str | None = None
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


# ---- URL Trust ----
class URLAnalysisRequest(BaseModel):
 url: str


class URLAnalysisResult(BaseModel):
 url: str
 hostname: str
 score: int
 band: str
 signals: dict | None = None
 website: dict | None = None
 providers: dict | None = None
 summary: dict | None = None


# ---- Report ----
class NetworkSummaryOut(BaseModel):
 summary: str
 total_assets: int
 total_paths: int
 total_exposure: float
