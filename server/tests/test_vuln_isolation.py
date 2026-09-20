# Drishti v0.1 — Vulnerability Isolation Tests | Phase 03
from datetime import datetime, timezone
import pytest

from app.schemas.endpoint import EndpointTelemetrySubmitRequest, SoftwareTelemetryItem
from app.services import endpoint_telemetry
from app.services.vuln_intel.cache import LocalVulnerabilityCache
from app.services.vuln_intel.correlator import VulnerabilityCorrelator
from app.services.vuln_intel.models import VersionRange, VulnerabilityRecord, FindingState, SourceStatus
from app.services.vuln_intel.sources.cisa_kev import CISAKEVSource
from app.services.vuln_intel.sources.nvd import NVDSource
from app.services.vuln_intel.sources.osv import OSVSource
from unittest.mock import MagicMock


@pytest.fixture(autouse=True)
def clean_stores():
    endpoint_telemetry.clear_telemetry_store()
    yield
    endpoint_telemetry.clear_telemetry_store()


def setup_mock_correlator_with_cve():
    cache = LocalVulnerabilityCache()
    rec = VulnerabilityRecord(
        id="CVE-2024-9999",
        summary="Critical vulnerability in 7-Zip",
        cvss=9.8,
        severity="critical",
        vendor="7-zip",
        product="7-zip",
        affected_ranges=[VersionRange(end_excluding="24.01")],
        fixed_versions=["24.01"],
        in_kev=True,
        kev_date_added="2024-01-15",
        sources=["nvd", "cisa_kev"],
    )
    cache.put(rec)

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


def test_device_telemetry_and_vulnerability_isolation():
    setup_mock_correlator_with_cve()
    now_utc = datetime.now(timezone.utc)

    # Device A has vulnerable 7-Zip 23.01
    payload_a = EndpointTelemetrySubmitRequest(
        agent_id="agent-A",
        device_id="device-A",
        timestamp=now_utc,
        installed_software=[
            SoftwareTelemetryItem(name="7-Zip 23.01", version="23.01", vendor="7-zip")
        ],
    )
    endpoint_telemetry.record_telemetry("org-1", "agent-A", "device-A", payload_a)

    # Device B has non-vulnerable (clean) software
    payload_b = EndpointTelemetrySubmitRequest(
        agent_id="agent-B",
        device_id="device-B",
        timestamp=now_utc,
        installed_software=[
            SoftwareTelemetryItem(name="Python 3.12.2", version="3.12.2", vendor="python")
        ],
    )
    endpoint_telemetry.record_telemetry("org-1", "agent-B", "device-B", payload_b)

    # Retrieve findings for Device A
    findings_a = endpoint_telemetry.get_vulnerability_findings_for_device("org-1", "device-A")
    assert len(findings_a) >= 1
    assert any(f.cve_id == "CVE-2024-9999" and f.finding_state == FindingState.KNOWN_EXPLOITED for f in findings_a)
    for f in findings_a:
        assert f.device_id == "device-A"

    # Retrieve findings for Device B
    findings_b = endpoint_telemetry.get_vulnerability_findings_for_device("org-1", "device-B")
    # Device B MUST NOT have CVE-2024-9999
    assert not any(f.cve_id == "CVE-2024-9999" for f in findings_b)
    for f in findings_b:
        assert f.device_id == "device-B"


def test_same_cve_on_multiple_devices_remains_distinct():
    setup_mock_correlator_with_cve()
    now_utc = datetime.now(timezone.utc)

    # Both Device A and Device B have the same vulnerable software
    sw_item = SoftwareTelemetryItem(name="7-Zip 23.01", version="23.01", vendor="7-zip")
    payload_a = EndpointTelemetrySubmitRequest(
        agent_id="agent-A",
        device_id="device-A",
        timestamp=now_utc,
        installed_software=[sw_item],
    )
    payload_b = EndpointTelemetrySubmitRequest(
        agent_id="agent-B",
        device_id="device-B",
        timestamp=now_utc,
        installed_software=[sw_item],
    )

    endpoint_telemetry.record_telemetry("org-1", "agent-A", "device-A", payload_a)
    endpoint_telemetry.record_telemetry("org-1", "agent-B", "device-B", payload_b)

    findings_a = endpoint_telemetry.get_vulnerability_findings_for_device("org-1", "device-A")
    findings_b = endpoint_telemetry.get_vulnerability_findings_for_device("org-1", "device-B")

    cve_a = next(f for f in findings_a if f.cve_id == "CVE-2024-9999")
    cve_b = next(f for f in findings_b if f.cve_id == "CVE-2024-9999")

    # Invariant: Distinct devices MUST have distinct finding records and distinct finding_ids
    assert cve_a.device_id == "device-A"
    assert cve_b.device_id == "device-B"
    assert cve_a.finding_id != cve_b.finding_id


def test_cross_organization_isolation():
    setup_mock_correlator_with_cve()
    now_utc = datetime.now(timezone.utc)

    # Org 1 registers telemetry for dev-1
    payload_org1 = EndpointTelemetrySubmitRequest(
        agent_id="agent-1",
        device_id="dev-shared-name",
        timestamp=now_utc,
        installed_software=[
            SoftwareTelemetryItem(name="7-Zip 23.01", version="23.01", vendor="7-zip")
        ],
    )
    endpoint_telemetry.record_telemetry("org-ALPHA", "agent-1", "dev-shared-name", payload_org1)

    # Org 2 attempts to retrieve findings for the same device ID
    findings_org2 = endpoint_telemetry.get_vulnerability_findings_for_device("org-BETA", "dev-shared-name")
    # Org 2 must see NOTHING because dev-shared-name does not belong to org-BETA
    assert findings_org2 == []
