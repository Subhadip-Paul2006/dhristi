# Drishti v0.1 — OSV & GHSA Vulnerability Intelligence Source | Phase 03
from __future__ import annotations

import logging
from typing import Any

from app.services.deepscan.intel_correlate import _OSV_VULN_URL, fetch_osv_vuln
from app.services.vuln_intel.models import (
    SourceStatus,
    VersionRange,
    VulnerabilityRecord,
)
from app.services.vuln_intel.sources.base import BaseVulnerabilitySource

logger = logging.getLogger("drishti.vuln_intel.osv")

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def fetch_osv_package(package_name: str, ecosystem: str, timeout: float) -> tuple[dict | None, str | None]:
    """Query OSV package endpoint for advisories affecting a package in an ecosystem."""
    try:
        import httpx

        body = {"package": {"name": package_name, "ecosystem": ecosystem}}
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(_OSV_QUERY_URL, json=body)
        if resp.status_code == 404:
            return {"vulns": []}, None
        if resp.status_code != 200:
            return None, f"OSV query HTTP {resp.status_code}"
        return resp.json(), None
    except Exception as exc:
        return None, f"OSV query unreachable: {str(exc)[:120]}"


class OSVSource(BaseVulnerabilitySource):
    """Integrates with Google Open Source Vulnerabilities (OSV) API & GHSA."""

    def __init__(self, timeout: float = 6.0):
        super().__init__(name="osv")
        self.timeout = timeout

    def parse_osv_advisory(self, vuln_data: dict[str, Any]) -> VulnerabilityRecord | None:
        """Parse raw OSV JSON structure into a normalized VulnerabilityRecord."""
        vuln_id = vuln_data.get("id")
        if not vuln_id:
            return None

        aliases = vuln_data.get("aliases") or []
        summary = vuln_data.get("summary") or vuln_data.get("details") or ""

        # Extract affected ranges and fixed versions from affected blocks
        ranges: list[VersionRange] = []
        fixed_versions: list[str] = []
        affected_package: str | None = None
        affected_ecosystem: str | None = None

        for aff in vuln_data.get("affected") or []:
            pkg = aff.get("package") or {}
            if pkg.get("name"):
                affected_package = pkg.get("name")
                affected_ecosystem = pkg.get("ecosystem")

            for r in aff.get("ranges") or []:
                events = r.get("events") or []
                intro = None
                fixed = None
                for ev in events:
                    if "introduced" in ev and ev["introduced"] != "0":
                        intro = ev["introduced"]
                    if "fixed" in ev:
                        fixed = ev["fixed"]
                        fixed_versions.append(fixed)

                if intro or fixed:
                    ranges.append(
                        VersionRange(
                            start_including=intro,
                            end_excluding=fixed,
                        )
                    )

        # Approximate CVSS from severity if present
        cvss = 5.0
        severity_label = "medium"
        severity_arr = vuln_data.get("severity") or []
        for s in severity_arr:
            score_str = s.get("score")
            if score_str and isinstance(score_str, str) and score_str.startswith("CVSS:"):
                # Could parse CVSS vector, fallback to medium if not parsed
                pass

        # Check aliases for primary CVE
        primary_cve = next((a for a in aliases if a.startswith("CVE-")), None)
        canonical_id = primary_cve or vuln_id

        return VulnerabilityRecord(
            id=canonical_id,
            aliases=[a for a in ([vuln_id] + aliases) if a != canonical_id],
            title=vuln_data.get("summary"),
            summary=summary[:600],
            cvss=cvss,
            severity=severity_label,
            package=affected_package,
            ecosystem=affected_ecosystem,
            affected_ranges=ranges,
            fixed_versions=list(set(fixed_versions)),
            published_at=vuln_data.get("published"),
            modified_at=vuln_data.get("modified"),
            sources=["osv"],
            references=[ref.get("url") for ref in (vuln_data.get("references") or []) if ref.get("url")][:5],
        )

    def lookup_cve_aliases(self, cve_id: str) -> tuple[dict[str, Any], SourceStatus]:
        """Fetch OSV record for a CVE to extract aliases (such as GHSA IDs)."""
        payload, err = fetch_osv_vuln(cve_id, self.timeout)
        if err:
            self.mark_failure(err)
            return {}, self.status

        self.mark_success()
        return payload or {}, self.status

    def lookup(
        self,
        product: str,
        version: str | None,
        vendor: str | None = None,
        cpe: str | None = None,
        ecosystem: str | None = None,
    ) -> tuple[list[VulnerabilityRecord], SourceStatus]:
        """Query OSV for packages in an ecosystem."""
        if not ecosystem:
            return [], self.status

        payload, err = fetch_osv_package(product, ecosystem, self.timeout)
        if err or not payload:
            self.mark_failure(err or "OSV query failed")
            return [], self.status

        self.mark_success()
        records: list[VulnerabilityRecord] = []
        for v in payload.get("vulns") or []:
            rec = self.parse_osv_advisory(v)
            if rec:
                records.append(rec)

        return records, self.status
