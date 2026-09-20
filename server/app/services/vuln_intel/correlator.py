# Drishti v0.1 — Vulnerability Correlation Engine | Phase 03
from __future__ import annotations

import logging
import uuid
from typing import Any

from app.services.vuln_intel.cache import LocalVulnerabilityCache
from app.services.vuln_intel.models import (
    CorrelatedFinding,
    FindingState,
    SourceStatus,
    VulnerabilityRecord,
)
from app.services.vuln_intel.normalizer import (
    UNKNOWN_PRODUCT,
    UNKNOWN_VERSION,
    ProductNormalizer,
)
from app.services.vuln_intel.sources.cisa_kev import CISAKEVSource
from app.services.vuln_intel.sources.nvd import NVDSource
from app.services.vuln_intel.sources.osv import OSVSource
from app.services.vuln_intel.version_matcher import VersionMatcher

logger = logging.getLogger("drishti.vuln_intel.correlator")


class VulnerabilityCorrelator:
    """Unified, evidence-backed vulnerability correlation engine."""

    def __init__(
        self,
        cache: LocalVulnerabilityCache | None = None,
        nvd_source: NVDSource | None = None,
        osv_source: OSVSource | None = None,
        kev_source: CISAKEVSource | None = None,
    ):
        self.cache = cache or LocalVulnerabilityCache()
        self.nvd_source = nvd_source or NVDSource()
        self.osv_source = osv_source or OSVSource()
        self.kev_source = kev_source or CISAKEVSource()

    def correlate_target(
        self,
        org_id: str,
        device_id: str,
        product: str,
        version: str | None,
        vendor: str | None = None,
        cpe: str | None = None,
        ecosystem: str | None = None,
        evidence_source: str = "endpoint_software",
        source_details: dict[str, Any] | None = None,
    ) -> list[CorrelatedFinding]:
        """Correlate a single normalized target against vulnerability intelligence sources."""
        source_details = source_details or {}

        # 1. Reject unknown product from becoming vulnerable
        if not product or product == UNKNOWN_PRODUCT:
            return []

        # 2. Reject unknown version from becoming vulnerable
        if not version or version == UNKNOWN_VERSION:
            finding_id = str(uuid.uuid4())
            return [
                CorrelatedFinding(
                    finding_id=finding_id,
                    device_id=device_id,
                    org_id=org_id,
                    finding_state=FindingState.POTENTIAL_MATCH,
                    observed_product=product,
                    observed_vendor=vendor,
                    observed_version=version or UNKNOWN_VERSION,
                    evidence_source=evidence_source,
                    evidence_type="POTENTIAL_MATCH",
                    summary=f"Detected product {product} has unknown or unparseable version; cannot establish vulnerability.",
                    source_details=source_details,
                    source_freshness="live",
                )
            ]

        # 3. Check local cache
        cached_records = self.cache.query_by_product(vendor, product)
        records_to_evaluate: list[VulnerabilityRecord] = list(cached_records)
        source_status_map: dict[str, SourceStatus] = {}

        # If cache miss, query sources
        if not records_to_evaluate:
            # Query NVD
            nvd_recs, nvd_status = self.nvd_source.lookup(product, version, vendor=vendor, cpe=cpe)
            source_status_map["nvd"] = nvd_status
            self.cache.set_source_status(nvd_status)
            for rec in nvd_recs:
                self.cache.put(rec)
                records_to_evaluate.append(rec)

            # Query OSV if ecosystem specified
            if ecosystem:
                osv_recs, osv_status = self.osv_source.lookup(product, version, ecosystem=ecosystem)
                source_status_map["osv"] = osv_status
                self.cache.set_source_status(osv_status)
                for rec in osv_recs:
                    self.cache.put(rec)
                    records_to_evaluate.append(rec)

        # Check source availability
        any_source_failed = any(not s.available for s in source_status_map.values())
        source_freshness = "source_unavailable" if any_source_failed else ("cached" if cached_records else "live")
        error_reason = next((s.error_reason for s in source_status_map.values() if not s.available), None)

        findings: list[CorrelatedFinding] = []

        for rec in records_to_evaluate:
            # Enrich with CISA KEV
            self.kev_source.enrich(rec)

            # Evaluate version match
            is_vuln, reason = VersionMatcher.evaluate_vulnerability(
                version,
                rec.affected_ranges,
                rec.fixed_versions,
            )

            # Strict rule: Fixed or non-affected version MUST NOT be marked vulnerable
            if not is_vuln:
                continue

            # Query GHSA / OSV aliases if not present
            ghsa_aliases = [a for a in rec.aliases if a.startswith("GHSA-")]
            if not ghsa_aliases and rec.id.startswith("CVE-"):
                alias_data, _ = self.osv_source.lookup_cve_aliases(rec.id)
                found_aliases = alias_data.get("aliases") or []
                for a in found_aliases:
                    if a.startswith("GHSA-") and a not in rec.aliases:
                        rec.aliases.append(a)
                        ghsa_aliases.append(a)

            state = FindingState.KNOWN_EXPLOITED if rec.in_kev else FindingState.VULNERABLE
            finding_id = str(uuid.uuid4())
            range_text = (
                "; ".join(r.summary_text() for r in rec.affected_ranges)
                if rec.affected_ranges
                else "Confirmed version match"
            )
            fixed_text = ", ".join(rec.fixed_versions) if rec.fixed_versions else None

            findings.append(
                CorrelatedFinding(
                    finding_id=finding_id,
                    device_id=device_id,
                    org_id=org_id,
                    finding_state=state,
                    cve_id=rec.id,
                    title=rec.title or f"{rec.id} in {product}",
                    summary=rec.summary,
                    cvss=rec.cvss,
                    severity=rec.severity,
                    in_kev=rec.in_kev,
                    kev_date_added=rec.kev_date_added,
                    ghsa_ids=ghsa_aliases,
                    observed_product=product,
                    observed_vendor=vendor,
                    observed_version=version,
                    affected_range_text=range_text,
                    fixed_version_text=fixed_text,
                    evidence_source=evidence_source,
                    evidence_type=(
                        "ENDPOINT_SOFTWARE_VULNERABILITY"
                        if evidence_source == "endpoint_software"
                        else "SERVICE_VULNERABILITY"
                    ),
                    intel_sources=list(rec.sources),
                    source_freshness=source_freshness,
                    source_status_reason=error_reason,
                    source_details=source_details,
                )
            )

        # Deduplicate findings by CVE ID
        deduped: dict[str, CorrelatedFinding] = {}
        for f in findings:
            if f.cve_id:
                if f.cve_id not in deduped or f.cvss > deduped[f.cve_id].cvss:
                    deduped[f.cve_id] = f

        final_findings = sorted(deduped.values(), key=lambda x: x.cvss, reverse=True)

        # If zero findings and sources were clean, return explicit NO_CONFIRMED_VULNERABILITY
        if not final_findings:
            if any_source_failed and not cached_records:
                # Do not convert source failure into no vulnerability
                return [
                    CorrelatedFinding(
                        finding_id=str(uuid.uuid4()),
                        device_id=device_id,
                        org_id=org_id,
                        finding_state=FindingState.EXPOSED,
                        observed_product=product,
                        observed_vendor=vendor,
                        observed_version=version,
                        evidence_source=evidence_source,
                        evidence_type="SOURCE_UNAVAILABLE",
                        summary=f"Vulnerability intelligence sources temporarily unavailable for {product}: {error_reason}",
                        source_details=source_details,
                        source_freshness="source_unavailable",
                        source_status_reason=error_reason,
                    )
                ]
            else:
                return [
                    CorrelatedFinding(
                        finding_id=str(uuid.uuid4()),
                        device_id=device_id,
                        org_id=org_id,
                        finding_state=FindingState.NO_CONFIRMED_VULNERABILITY,
                        observed_product=product,
                        observed_vendor=vendor,
                        observed_version=version,
                        evidence_source=evidence_source,
                        evidence_type="NO_CONFIRMED_VULNERABILITY",
                        summary=f"No confirmed vulnerability advisories found for {product} {version}.",
                        source_details=source_details,
                        source_freshness=source_freshness,
                    )
                ]

        return final_findings

    def correlate_endpoint_software(
        self,
        org_id: str,
        device_id: str,
        software_items: list[dict[str, Any]],
    ) -> list[CorrelatedFinding]:
        """Correlate genuine installed software telemetry from an endpoint."""
        all_findings: list[CorrelatedFinding] = []

        for sw in software_items:
            name = sw.get("name") or ""
            version = sw.get("version")
            publisher = sw.get("vendor") or sw.get("publisher")

            norm = ProductNormalizer.normalize_endpoint_software(name, version, publisher)
            if not norm.is_known_product:
                continue

            findings = self.correlate_target(
                org_id=org_id,
                device_id=device_id,
                product=norm.canonical_product,
                version=norm.canonical_version,
                vendor=norm.canonical_vendor,
                cpe=norm.cpe_prefix,
                evidence_source="endpoint_software",
                source_details=sw,
            )
            all_findings.extend(findings)

        # Sort findings: KNOWN_EXPLOITED > VULNERABLE > POTENTIAL_MATCH > NO_CONFIRMED
        order = {
            FindingState.KNOWN_EXPLOITED: 0,
            FindingState.VULNERABLE: 1,
            FindingState.POTENTIAL_MATCH: 2,
            FindingState.EXPOSED: 3,
            FindingState.OPEN: 4,
            FindingState.NO_CONFIRMED_VULNERABILITY: 5,
        }
        all_findings.sort(key=lambda f: (order.get(f.finding_state, 9), -f.cvss))
        return all_findings

    def correlate_network_services(
        self,
        org_id: str,
        device_id: str,
        services: list[dict[str, Any]],
        open_ports: list[int] | None = None,
    ) -> list[CorrelatedFinding]:
        """Correlate network service evidence from DeepScan/Nmap."""
        all_findings: list[CorrelatedFinding] = []

        # If ports are open but no services identified, record OPEN state without CVEs
        if open_ports and not services:
            for p in open_ports:
                all_findings.append(
                    CorrelatedFinding(
                        finding_id=str(uuid.uuid4()),
                        device_id=device_id,
                        org_id=org_id,
                        finding_state=FindingState.OPEN,
                        observed_product=f"Port {p}/TCP",
                        evidence_source="network_service",
                        evidence_type="OPEN_PORT",
                        summary=f"Port {p}/TCP is open on device; no service or product identified.",
                        source_details={"port": p},
                    )
                )
            return all_findings

        for s in services:
            svc_name = s.get("service_name") or "unknown"
            product = s.get("product")
            version = s.get("version")
            cpe = s.get("cpe")

            norm = ProductNormalizer.normalize_network_service(svc_name, product, version, cpe)
            if not norm.is_known_product:
                continue

            findings = self.correlate_target(
                org_id=org_id,
                device_id=device_id,
                product=norm.canonical_product,
                version=norm.canonical_version,
                vendor=norm.canonical_vendor,
                cpe=norm.cpe_prefix or cpe,
                evidence_source="network_service",
                source_details=s,
            )
            all_findings.extend(findings)

        return all_findings
