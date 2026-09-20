# Drishti v0.1 — Vulnerability Intelligence Models & Cache Tests | Phase 03
import pytest
from app.services.vuln_intel.models import (
    VersionRange,
    VulnerabilityRecord,
    FindingState,
    SourceStatus,
    CorrelatedFinding,
)
from app.services.vuln_intel.cache import LocalVulnerabilityCache


def test_version_range_serialization():
    vr = VersionRange(start_including="1.0.0", end_excluding="2.0.0")
    d = vr.to_dict()
    assert d["start_including"] == "1.0.0"
    assert d["end_excluding"] == "2.0.0"
    assert d["start_excluding"] is None
    assert d["end_including"] is None

    restored = VersionRange.from_dict(d)
    assert restored.start_including == "1.0.0"
    assert restored.end_excluding == "2.0.0"
    assert ">=1.0.0" in vr.summary_text()
    assert "<2.0.0" in vr.summary_text()


def test_vulnerability_record_contract():
    rec = VulnerabilityRecord(
        id="CVE-2024-1234",
        summary="Test vulnerability in 7-Zip",
        cvss=7.8,
        severity="high",
        vendor="7-zip",
        product="7-zip",
        affected_ranges=[VersionRange(end_excluding="24.01")],
        fixed_versions=["24.01"],
        in_kev=True,
        kev_date_added="2024-01-15",
        sources=["nvd", "cisa_kev"],
        aliases=["GHSA-xxxx-yyyy"],
    )
    d = rec.to_dict()
    assert d["id"] == "CVE-2024-1234"
    assert d["in_kev"] is True
    assert len(d["affected_ranges"]) == 1
    assert d["affected_ranges"][0]["end_excluding"] == "24.01"


def test_cache_put_and_query_by_id_and_alias():
    cache = LocalVulnerabilityCache()
    rec = VulnerabilityRecord(
        id="CVE-2023-9999",
        summary="Test vulnerability",
        cvss=6.5,
        severity="medium",
        vendor="apache",
        product="http_server",
        aliases=["GHSA-test-alias"],
        sources=["nvd"],
    )
    assert cache.put(rec) is True

    # Query by primary ID
    res1 = cache.get_by_id("CVE-2023-9999")
    assert res1 is not None
    assert res1.id == "CVE-2023-9999"

    # Query by alias
    res2 = cache.get_by_id("GHSA-test-alias")
    assert res2 is not None
    assert res2.id == "CVE-2023-9999"

    # Query non-existent
    assert cache.get_by_id("CVE-NON-EXISTENT") is None


def test_cache_query_by_product_and_package():
    cache = LocalVulnerabilityCache()
    rec1 = VulnerabilityRecord(
        id="CVE-2024-0001",
        summary="Product vuln",
        cvss=9.8,
        severity="critical",
        vendor="google",
        product="chrome",
        sources=["nvd"],
    )
    rec2 = VulnerabilityRecord(
        id="GHSA-pkg-123",
        summary="Package vuln",
        cvss=5.0,
        severity="medium",
        package="requests",
        ecosystem="PyPI",
        sources=["osv"],
    )
    cache.put(rec1)
    cache.put(rec2)

    # Query product with vendor
    prods = cache.query_by_product("google", "chrome")
    assert len(prods) == 1
    assert prods[0].id == "CVE-2024-0001"

    # Query product without vendor (fallback)
    prods_fallback = cache.query_by_product(None, "chrome")
    assert len(prods_fallback) == 1
    assert prods_fallback[0].id == "CVE-2024-0001"

    # Query package
    pkgs = cache.query_by_package("PyPI", "requests")
    assert len(pkgs) == 1
    assert pkgs[0].id == "GHSA-pkg-123"


def test_cache_downgrade_protection():
    cache = LocalVulnerabilityCache()
    newer_rec = VulnerabilityRecord(
        id="CVE-2024-5555",
        summary="Newer summary",
        cvss=8.0,
        severity="high",
        modified_at="2024-06-01T12:00:00Z",
        sources=["nvd"],
    )
    cache.put(newer_rec)

    older_rec = VulnerabilityRecord(
        id="CVE-2024-5555",
        summary="Older summary",
        cvss=7.0,
        severity="high",
        modified_at="2024-01-01T12:00:00Z",
        sources=["nvd"],
    )
    # Attempt to put older record
    accepted = cache.put(older_rec)
    assert accepted is False
    current = cache.get_by_id("CVE-2024-5555")
    assert current.summary == "Newer summary"
    assert current.cvss == 8.0


def test_cache_source_status_tracking():
    cache = LocalVulnerabilityCache()
    status_nvd = SourceStatus(source_name="nvd", available=True, last_sync="2026-09-21T00:00:00Z")
    status_osv = SourceStatus(
        source_name="osv",
        available=False,
        error_reason="HTTP 503 Service Unavailable",
        is_stale=True,
    )
    cache.set_source_status(status_nvd)
    cache.set_source_status(status_osv)

    assert cache.get_source_status("nvd").available is True
    assert cache.get_source_status("osv").available is False
    assert cache.get_source_status("osv").error_reason == "HTTP 503 Service Unavailable"

    all_statuses = cache.all_source_statuses()
    assert len(all_statuses) == 2
