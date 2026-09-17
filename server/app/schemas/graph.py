# Drishti v0.1 — graph visualization schemas | 11-Jul-2026
"""Graph + paths + assets read schemas. Graph payload = React Flow contract (BACKEND.md §4.3)."""
from pydantic import BaseModel


class GraphNodeData(BaseModel):
    label: str
    asset_type: str
    zone: str | None = None
    criticality: str
    risk_score: float
    business_value: float
    internet_facing: bool
    open_findings: int
    is_crown_jewel: bool = False
    in_blast_radius: bool | None = None
    # live-device fields — set when the node is a device the agent sees on the
    # wire (not a risk-assessed asset). Lets the attack map show the REAL network.
    is_device: bool = False
    is_gateway: bool = False
    online: bool = True
    mac: str | None = None
    vendor: str | None = None
    ip: str | None = None
    # active threat this node is part of (ARP-spoof / rogue / risky service / C2),
    # so the attack map lights up "how the attack is happening"
    threat: bool = False
    threat_kind: str | None = None  # arp_spoof | rogue_device | risky_service | malicious_domain
    threat_severity: str | None = None
    threat_title: str | None = None
    mitre: str | None = None


class GraphNode(BaseModel):
    id: str
    type: str = "asset"
    data: GraphNodeData
    position: dict[str, float]


class GraphEdgeData(BaseModel):
    relation: str
    weight: float
    via_cve: str | None = None
    on_top_path: bool = False
    # highest-risk cached attack path this edge belongs to (drives edge-click → path drawer)
    path_id: str | None = None


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    data: GraphEdgeData


class GraphMeta(BaseModel):
    entry_nodes: list[str]
    crown_jewels: list[str]
    focus: str | None = None
    blast_radius_ids: list[str] = []


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    meta: GraphMeta


class AssetSummary(BaseModel):
    id: str
    hostname: str | None
    ip: str
    asset_type: str
    zone: str | None
    criticality: str
    business_value: float
    internet_facing: bool
    risk_score: float | None
    blast_radius_count: int | None
    open_findings: int


class ServiceOut(BaseModel):
    id: str
    port: int
    protocol: str
    name: str
    version: str | None


class FindingOut(BaseModel):
    id: str
    status: str
    cve_id: str | None
    title: str
    severity: str
    cvss: float
    exploitability: float
    description: str | None
    asset_id: str
    asset_hostname: str | None
    asset_ip: str
    service_port: int | None
    detected_at: str | None


class AssetDetail(AssetSummary):
    os: str | None
    services: list[ServiceOut]
    findings: list[FindingOut]
    blast_radius_count: int | None
    downstream_value: float


class BlastRadiusOut(BaseModel):
    asset_id: str
    count: int
    downstream_value: float
    reachable_ids: list[str]


class PathStepOut(BaseModel):
    step_index: int
    asset_id: str
    asset_hostname: str | None
    asset_ip: str
    asset_type: str
    zone: str | None
    via_cve: str | None
    via_title: str | None
    via_severity: str | None = None
    via_cvss: float | None = None
    edge_weight: float | None


class PathSummary(BaseModel):
    id: str
    entry_label: str
    target_asset_id: str
    target_hostname: str | None
    hop_count: int
    path_risk: float
    likelihood: float
    impact_usd: float
    narrative: str | None


class PathDetail(PathSummary):
    steps: list[PathStepOut]
    drivers: list[str] = []
