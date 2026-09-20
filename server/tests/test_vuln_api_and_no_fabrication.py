# Drishti v0.1 — Vulnerability API & Zero Fabrication Tests | Phase 03
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.schemas.endpoint import EndpointTelemetrySubmitRequest, SoftwareTelemetryItem
from app.services import endpoint_telemetry
from app.services.vuln_intel.cache import LocalVulnerabilityCache
from app.services.vuln_intel.correlator import VulnerabilityCorrelator
from app.services.vuln_intel.models import VersionRange, VulnerabilityRecord, FindingState, SourceStatus
from app.services.vuln_intel.sources.cisa_kev import CISAKEVSource
from app.services.vuln_intel.sources.nvd import NVDSource
from app.services.vuln_intel.sources.osv import OSVSource


@pytest.fixture(autouse=True)
def clean_stores():
    endpoint_telemetry.clear_telemetry_store()
    yield
    endpoint_telemetry.clear_telemetry_store()


def setup_mock_correlator():
    cache = LocalVulnerabilityCache()
    rec1 = VulnerabilityRecord(
        id="CVE-2023-38831",
        summary="WinRAR remote code execution",
        cvss=7.8,
        severity="high",
        vendor="rarlab",
        product="winrar",
        affected_ranges=[VersionRange(end_excluding="6.23")],
        fixed_versions=["6.23"],
        in_kev=True,
        kev_date_added="2023-08-28",
        sources=["nvd", "cisa_kev"],
    )
    rec2 = VulnerabilityRecord(
        id="CVE-2024-1111",
        summary="7-Zip heap flaw",
        cvss=7.5,
        severity="high",
        vendor="7-zip",
        product="7-zip",
        affected_ranges=[VersionRange(end_excluding="24.01")],
        fixed_versions=["24.01"],
        in_kev=False,
        sources=["nvd"],
    )
    cache.put(rec1)
    cache.put(rec2)

    mock_nvd = MagicMock(spec=NVDSource)
    mock_nvd.name = "nvd"
    mock_nvd.lookup.return_value = ([], SourceStatus(source_name="nvd", available=True))

    mock_osv = MagicMock(spec=OSVSource)
    mock_osv.name = "osv"
    mock_osv.lookup.return_value = ([], SourceStatus(source_name="osv", available=True))
    mock_osv.lookup_cve_aliases.return_value = ({"aliases": []}, SourceStatus(source_name="osv", available=True))


    mock_kev = MagicMock(spec=CISAKEVSource)
    mock_kev.name = "cisa_kev"
    mock_kev.enrich.side_effect = lambda r: r.in_kev

    corr = VulnerabilityCorrelator(
        cache=cache,
        nvd_source=mock_nvd,
        osv_source=mock_osv,
        kev_source=mock_kev,
    )
    endpoint_telemetry.set_correlator(corr)
    return corr


def test_vulnerability_api_authentication(client: TestClient):
    # Unauthenticated request must be rejected
    res = client.get("/api/endpoint/vulnerabilities/dev-123")
    assert res.status_code == 401


def test_vulnerability_api_response_schema_and_counts(
    client: TestClient,
    seed_acme_org,
    user_headers: dict,
):
    setup_mock_correlator()
    org_id = seed_acme_org.id
    device_id = "test-workstation-01"

    # Ingest genuine endpoint software telemetry
    now_utc = datetime.now(timezone.utc)
    payload = EndpointTelemetrySubmitRequest(
        agent_id="agent-01",
        device_id=device_id,
        timestamp=now_utc,
        installed_software=[
            SoftwareTelemetryItem(name="7-Zip 23.01", version="23.01", vendor="7-zip"),
            SoftwareTelemetryItem(name="WinRAR 6.22", version="6.22", vendor="rarlab"),
            SoftwareTelemetryItem(name="Python 3.12.2", version="3.12.2", vendor="python"),
        ],
    )
    endpoint_telemetry.record_telemetry(org_id, "agent-01", device_id, payload)

    # Query vulnerabilities endpoint
    res = client.get(f"/api/endpoint/vulnerabilities/{device_id}", headers=user_headers)
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["device_id"] == device_id
    assert "findings" in data
    assert "source_statuses" in data
    assert data["total_findings"] >= 2
    assert data["vulnerable_count"] >= 2
    assert data["known_exploited_count"] >= 1  # WinRAR is in KEV

    # Verify KEV finding properties
    winrar_finding = next(f for f in data["findings"] if f["cve_id"] == "CVE-2023-38831")
    assert winrar_finding["finding_state"] == "KNOWN_EXPLOITED"
    assert winrar_finding["in_kev"] is True
    assert winrar_finding["kev_date_added"] == "2023-08-28"
    assert winrar_finding["evidence_source"] == "endpoint_software"


def test_zero_fabrication_safety_invariants():
    corr = setup_mock_correlator()

    # Invariant 1: Open port alone MUST NEVER produce a CVE
    findings_ports = corr.correlate_network_services("org-1", "dev-1", services=[], open_ports=[443, 8080, 22])
    for f in findings_ports:
        assert f.cve_id is None
        assert f.finding_state == FindingState.OPEN
        assert f.evidence_type == "OPEN_PORT"
        assert f.cvss == 0.0

    # Invariant 2: Pure fabricated / unknown product name is skipped without creating findings
    findings_unknown_prod = corr.correlate_target("org-1", "dev-1", "UNKNOWN_PRODUCT", "1.0.0")
    assert findings_unknown_prod == []

    # Invariant 3: Unknown / unparseable version NEVER creates VULNERABLE or KNOWN_EXPLOITED
    findings_unknown_ver = corr.correlate_target("org-1", "dev-1", "7-zip", "UNKNOWN_VERSION")
    assert len(findings_unknown_ver) == 1
    assert findings_unknown_ver[0].finding_state == FindingState.POTENTIAL_MATCH
    assert findings_unknown_ver[0].cve_id is None

    # Invariant 4: Fixed version is NEVER marked vulnerable
    findings_fixed = corr.correlate_target("org-1", "dev-1", "7-zip", "24.01", vendor="7-zip")
    assert len(findings_fixed) == 1
    assert findings_fixed[0].finding_state == FindingState.NO_CONFIRMED_VULNERABILITY
    assert findings_fixed[0].cve_id is None
