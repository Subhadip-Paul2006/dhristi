# Drishti v0.1 — Vulnerability Correlator Tests | Phase 03
from unittest.mock import MagicMock
import pytest

from app.services.vuln_intel.cache import LocalVulnerabilityCache
from app.services.vuln_intel.correlator import VulnerabilityCorrelator
from app.services.vuln_intel.models import (
    CorrelatedFinding,
    FindingState,
    SourceStatus,
    VersionRange,
    VulnerabilityRecord,
)
from app.services.vuln_intel.sources.cisa_kev import CISAKEVSource
from app.services.vuln_intel.sources.nvd import NVDSource
from app.services.vuln_intel.sources.osv import OSVSource


def build_mock_correlator(records: list[VulnerabilityRecord] | None = None) -> VulnerabilityCorrelator:
    cache = LocalVulnerabilityCache()
    if records:
        for r in records:
            cache.put(r)

    mock_nvd = MagicMock(spec=NVDSource)
    mock_nvd.name = "nvd"
    mock_nvd.lookup.return_value = ([], SourceStatus(source_name="nvd", available=True))

    mock_osv = MagicMock(spec=OSVSource)
    mock_osv.name = "osv"
    mock_osv.lookup.return_value = ([], SourceStatus(source_name="osv", available=True))
    mock_osv.lookup_cve_aliases.return_value = ({"aliases": []}, SourceStatus(source_name="osv", available=True))

    mock_kev = MagicMock(spec=CISAKEVSource)
    mock_kev.name = "cisa_kev"
    mock_kev.enrich.side_effect = lambda rec: rec.in_kev

    return VulnerabilityCorrelator(
        cache=cache,
        nvd_source=mock_nvd,
        osv_source=mock_osv,
        kev_source=mock_kev,
    )


def test_correlate_unknown_product_and_version():
    corr = build_mock_correlator()

    # Unknown product is rejected completely
    res_prod = corr.correlate_target("org-1", "dev-1", "UNKNOWN_PRODUCT", "1.0.0")
    assert res_prod == []

    # Unknown version results in POTENTIAL_MATCH, never VULNERABLE
    res_ver = corr.correlate_target("org-1", "dev-1", "7-zip", "UNKNOWN_VERSION")
    assert len(res_ver) == 1
    assert res_ver[0].finding_state == FindingState.POTENTIAL_MATCH
    assert res_ver[0].cve_id is None
    assert "unknown or unparseable version" in res_ver[0].summary


def test_correlate_vulnerable_and_known_exploited():
    rec_vuln = VulnerabilityRecord(
        id="CVE-2023-1111",
        summary="7-Zip heap corruption",
        cvss=7.5,
        severity="high",
        vendor="7-zip",
        product="7-zip",
        affected_ranges=[VersionRange(end_excluding="24.01")],
        fixed_versions=["24.01"],
        in_kev=False,
    )
    rec_kev = VulnerabilityRecord(
        id="CVE-2023-2222",
        summary="7-Zip actively exploited RCE",
        cvss=9.8,
        severity="critical",
        vendor="7-zip",
        product="7-zip",
        affected_ranges=[VersionRange(end_excluding="24.01")],
        fixed_versions=["24.01"],
        in_kev=True,
        kev_date_added="2023-09-01",
    )
    corr = build_mock_correlator([rec_vuln, rec_kev])

    # Test affected version 23.01
    findings = corr.correlate_target("org-1", "dev-1", "7-zip", "23.01", vendor="7-zip")
    assert len(findings) == 2

    # Verify states
    cve_states = {f.cve_id: f.finding_state for f in findings}
    assert cve_states["CVE-2023-1111"] == FindingState.VULNERABLE
    assert cve_states["CVE-2023-2222"] == FindingState.KNOWN_EXPLOITED

    # Verify KEV date added and flags
    kev_finding = next(f for f in findings if f.cve_id == "CVE-2023-2222")
    assert kev_finding.in_kev is True
    assert kev_finding.kev_date_added == "2023-09-01"


def test_correlate_fixed_version_not_marked_vulnerable():
    rec = VulnerabilityRecord(
        id="CVE-2023-1111",
        summary="7-Zip flaw",
        cvss=7.5,
        severity="high",
        vendor="7-zip",
        product="7-zip",
        affected_ranges=[VersionRange(end_excluding="24.01")],
        fixed_versions=["24.01"],
    )
    corr = build_mock_correlator([rec])

    # Fixed version 24.01
    findings = corr.correlate_target("org-1", "dev-1", "7-zip", "24.01", vendor="7-zip")
    assert len(findings) == 1
    assert findings[0].finding_state == FindingState.NO_CONFIRMED_VULNERABILITY


def test_network_open_ports_only_no_cves():
    corr = build_mock_correlator()

    # Device with open port 443 and 80, but NO identified services
    findings = corr.correlate_network_services("org-1", "dev-1", services=[], open_ports=[80, 443])
    assert len(findings) == 2
    for f in findings:
        assert f.finding_state == FindingState.OPEN
        assert f.evidence_type == "OPEN_PORT"
        assert f.cve_id is None
        assert "open on device" in f.summary
        assert f.cvss == 0.0


def test_source_outage_does_not_become_no_vulnerability():
    cache = LocalVulnerabilityCache()
    mock_nvd = MagicMock(spec=NVDSource)
    mock_nvd.name = "nvd"
    mock_nvd.lookup.return_value = ([], SourceStatus(source_name="nvd", available=False, error_reason="Timeout 504 Gateway"))

    corr = VulnerabilityCorrelator(
        cache=cache,
        nvd_source=mock_nvd,
        osv_source=MagicMock(),
        kev_source=MagicMock(),
    )

    findings = corr.correlate_target("org-1", "dev-1", "apache", "2.4.49", vendor="apache")
    assert len(findings) == 1
    f = findings[0]
    # Invariant: source failure must NOT become NO_CONFIRMED_VULNERABILITY
    assert f.finding_state == FindingState.EXPOSED
    assert f.evidence_type == "SOURCE_UNAVAILABLE"
    assert f.source_freshness == "source_unavailable"
    assert "Timeout 504" in (f.source_status_reason or "")
