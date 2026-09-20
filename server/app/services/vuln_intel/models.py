# Drishti v0.1 — Vulnerability Intelligence Models & Contracts | Phase 03
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class FindingState(str, Enum):
    OPEN = "OPEN"
    EXPOSED = "EXPOSED"
    POTENTIAL_MATCH = "POTENTIAL_MATCH"
    VULNERABLE = "VULNERABLE"
    KNOWN_EXPLOITED = "KNOWN_EXPLOITED"
    NO_CONFIRMED_VULNERABILITY = "NO_CONFIRMED_VULNERABILITY"


@dataclass
class VersionRange:
    """Represents an affected version range with explicit boundary semantics."""

    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VersionRange:
        return cls(
            start_including=data.get("start_including"),
            start_excluding=data.get("start_excluding"),
            end_including=data.get("end_including"),
            end_excluding=data.get("end_excluding"),
        )

    def summary_text(self) -> str:
        parts: list[str] = []
        if self.start_including:
            parts.append(f">={self.start_including}")
        elif self.start_excluding:
            parts.append(f">{self.start_excluding}")
        if self.end_including:
            parts.append(f"<={self.end_including}")
        elif self.end_excluding:
            parts.append(f"<{self.end_excluding}")
        return ", ".join(parts) if parts else "all versions"


@dataclass
class VulnerabilityRecord:
    """Normalized advisory record from NVD, OSV, GHSA, or CISA KEV."""

    id: str  # Primary canonical identifier (e.g. CVE-YYYY-NNNN or OSV/GHSA ID)
    summary: str
    cvss: float
    severity: str  # low | medium | high | critical
    aliases: list[str] = field(default_factory=list)
    title: str | None = None
    vendor: str | None = None
    product: str | None = None
    package: str | None = None
    ecosystem: str | None = None
    cpe23: str | None = None
    affected_ranges: list[VersionRange] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    exploitability: float | None = None
    cwe: str | None = None
    in_kev: bool = False
    kev_date_added: str | None = None
    published_at: str | None = None
    modified_at: str | None = None
    sources: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    fetched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["affected_ranges"] = [r.to_dict() for r in self.affected_ranges]
        return d


@dataclass
class SourceStatus:
    """Status metadata for external vulnerability intelligence sources."""

    source_name: str
    available: bool = True
    last_sync: str | None = None
    error_reason: str | None = None
    is_stale: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelatedFinding:
    """Deterministic, device-scoped vulnerability finding with evidence provenance."""

    finding_id: str
    device_id: str
    org_id: str
    finding_state: FindingState
    observed_product: str
    evidence_source: str  # endpoint_software | network_service
    evidence_type: str  # ENDPOINT_SOFTWARE_VULNERABILITY | SERVICE_VULNERABILITY | NO_CONFIRMED_VULNERABILITY
    observed_vendor: str | None = None
    observed_version: str | None = None
    cve_id: str | None = None
    title: str | None = None
    summary: str | None = None
    cvss: float = 0.0
    severity: str = "none"
    in_kev: bool = False
    kev_date_added: str | None = None
    ghsa_ids: list[str] = field(default_factory=list)
    affected_range_text: str | None = None
    fixed_version_text: str | None = None
    intel_sources: list[str] = field(default_factory=list)
    source_freshness: str = "live"  # live | cached | stale | source_unavailable
    source_status_reason: str | None = None
    source_details: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["finding_state"] = self.finding_state.value
        return d
