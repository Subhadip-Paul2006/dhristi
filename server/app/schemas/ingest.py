# Drishti v0.1 — ingestion contract schemas | 11-Jul-2026
"""Edge Agent → server ingestion contract (ARCHITECTURE.md §3.3–3.4). Do not drift."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

AssetType = Literal["server", "database", "workstation", "firewall", "router", "webapp", "iot", "cloud"]
Severity = Literal["low", "medium", "high", "critical"]
ZoneHint = Literal["dmz", "internal", "crown_jewel", "cloud"]


class IngestHost(BaseModel):
    hostname: str = Field(max_length=255)
    ip: str = Field(max_length=45)
    os: str | None = Field(default=None, max_length=120)
    asset_type: AssetType = "server"
    zone_hint: ZoneHint | None = None
    criticality_hint: Severity | None = None


class IngestService(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    name: str = Field(max_length=120)
    version: str | None = Field(default=None, max_length=80)


class IngestVulnerability(BaseModel):
    cve_id: str | None = Field(default=None, max_length=30)
    title: str = Field(max_length=255)
    cvss: float = Field(ge=0, le=10)
    severity: Severity
    exploitability: float = Field(ge=0, le=1)
    port: int | None = None
    summary: str | None = None


class IngestConnectivity(BaseModel):
    to_ip: str
    via: Literal["network", "admin", "trust", "exposure"] = "network"
    note: str | None = Field(default=None, max_length=255)


class IngestPayload(BaseModel):
    agent_id: str
    org_slug: str
    collected_at: datetime
    host: IngestHost
    services: list[IngestService] = []
    vulnerabilities: list[IngestVulnerability] = []
    connectivity: list[IngestConnectivity] = []


class IngestCounts(BaseModel):
    services: int
    vulnerabilities: int


class IngestResponse(BaseModel):
    status: Literal["accepted"] = "accepted"
    asset_id: str
    ingested: IngestCounts
    server_time: datetime
