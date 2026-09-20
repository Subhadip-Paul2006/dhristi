# Drishti v0.1 — Vulnerability Sources Integration Tests | Phase 03
import time
from unittest.mock import patch
import pytest

from app.services.vuln_intel.models import VulnerabilityRecord, VersionRange
from app.services.vuln_intel.sources.nvd import NVDSource
from app.services.vuln_intel.sources.cisa_kev import CISAKEVSource
from app.services.vuln_intel.sources.osv import OSVSource


def test_nvd_parse_configurations():
    source = NVDSource()
    cve_data = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "18.00",
                                "versionEndExcluding": "24.01",
                            }
                        ]
                    }
                ]
            }
        ]
    }
    ranges = source.parse_configurations(cve_data)
    assert len(ranges) == 1
    assert ranges[0].start_including == "18.00"
    assert ranges[0].end_excluding == "24.01"


def test_nvd_outage_handling():
    source = NVDSource()
    with patch("app.services.vuln_intel.sources.nvd.fetch_nvd", return_value=(None, "Connection timed out (mock)")):
        recs, status = source.lookup("apache", "2.4.49")
        assert recs == []
        assert status.available is False
        assert "Connection timed out" in (status.error_reason or "")


def test_cisa_kev_sync_and_enrich():
    kev = CISAKEVSource()
    mock_payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2023-38831",
                "dateAdded": "2023-08-28",
                "vulnerabilityName": "WinRAR Code Execution",
                "requiredAction": "Apply vendor patch",
            }
        ]
    }
    with patch("app.services.vuln_intel.sources.cisa_kev.fetch_kev_catalog", return_value=(mock_payload, None)):
        kev.sync_catalog()

    # Verify is_in_kev
    in_kev, entry = kev.is_in_kev("CVE-2023-38831")
    assert in_kev is True
    assert entry is not None
    assert entry["date_added"] == "2023-08-28"

    # Verify negative case
    in_kev_neg, _ = kev.is_in_kev("CVE-9999-0000")
    assert in_kev_neg is False

    # Verify enrich method
    rec = VulnerabilityRecord(
        id="CVE-2023-38831",
        summary="Exploited flaw",
        cvss=7.8,
        severity="high",
        sources=["nvd"],
    )
    enriched = kev.enrich(rec)
    assert enriched is True
    assert rec.in_kev is True
    assert rec.kev_date_added == "2023-08-28"
    assert "cisa_kev" in rec.sources


def test_osv_parse_advisory():
    osv = OSVSource()
    mock_vuln = {
        "id": "GHSA-1234-5678",
        "aliases": ["CVE-2024-9999"],
        "summary": "Sample advisory",
        "affected": [
            {
                "package": {"name": "urllib3", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.26.0"},
                            {"fixed": "1.26.18"},
                        ],
                    }
                ],
            }
        ],
    }
    rec = osv.parse_osv_advisory(mock_vuln)
    assert rec is not None
    # Primary canonical ID defaults to CVE if present
    assert rec.id == "CVE-2024-9999"
    assert "GHSA-1234-5678" in rec.aliases
    assert rec.package == "urllib3"
    assert rec.ecosystem == "PyPI"
    assert len(rec.affected_ranges) == 1
    assert rec.affected_ranges[0].start_including == "1.26.0"
    assert rec.affected_ranges[0].end_excluding == "1.26.18"
    assert "1.26.18" in rec.fixed_versions


def test_osv_outage_handling():
    osv = OSVSource()
    with patch("app.services.vuln_intel.sources.osv.fetch_osv_package", return_value=(None, "HTTP 500 Internal Error")):
        recs, status = osv.lookup("requests", "2.25.0", ecosystem="PyPI")
        assert recs == []
        assert status.available is False
        assert "HTTP 500" in (status.error_reason or "")
