# Drishti v0.1 — Version Matcher & Range Evaluation Tests | Phase 03
import pytest
from app.services.vuln_intel.models import VersionRange
from app.services.vuln_intel.version_matcher import VersionMatcher, UNKNOWN_VERSION


def test_parse_components():
    assert VersionMatcher.parse_components("1.2.3") == [1, 2, 3]
    assert VersionMatcher.parse_components("v2.4.52") == [2, 4, 52]
    assert VersionMatcher.parse_components("1.0.0-beta.1") == [1, 0, 0, "beta", 1]
    assert VersionMatcher.parse_components("24.01") == [24, 1]
    assert VersionMatcher.parse_components("unknown") is None
    assert VersionMatcher.parse_components(UNKNOWN_VERSION) is None
    assert VersionMatcher.parse_components("") is None
    assert VersionMatcher.parse_components(None) is None


def test_compare_versions():
    # Equal
    assert VersionMatcher.compare("1.2.3", "1.2.3") == 0
    assert VersionMatcher.compare("1.2", "1.2.0") == 0

    # Less than
    assert VersionMatcher.compare("1.2.3", "1.2.4") == -1
    assert VersionMatcher.compare("1.1.9", "1.2.0") == -1
    assert VersionMatcher.compare("23.01", "24.01") == -1

    # Greater than
    assert VersionMatcher.compare("2.0.1", "2.0.0") == 1
    assert VersionMatcher.compare("10.0.1", "9.9.9") == 1

    # Numeric precedence over prerelease
    assert VersionMatcher.compare("1.0.0", "1.0.0-beta") == 1

    # Malformed / inconclusive
    assert VersionMatcher.compare("invalid", "1.0.0") is None
    assert VersionMatcher.compare(None, "1.0.0") is None


def test_is_in_range():
    # Range: [1.0.0, 2.0.0)
    r1 = VersionRange(start_including="1.0.0", end_excluding="2.0.0")
    assert VersionMatcher.is_in_range("1.0.0", r1) is True
    assert VersionMatcher.is_in_range("1.9.9", r1) is True
    assert VersionMatcher.is_in_range("2.0.0", r1) is False
    assert VersionMatcher.is_in_range("0.9.9", r1) is False

    # Range: (1.0.0, 2.0.0]
    r2 = VersionRange(start_excluding="1.0.0", end_including="2.0.0")
    assert VersionMatcher.is_in_range("1.0.0", r2) is False
    assert VersionMatcher.is_in_range("1.0.1", r2) is True
    assert VersionMatcher.is_in_range("2.0.0", r2) is True
    assert VersionMatcher.is_in_range("2.0.1", r2) is False


def test_fixed_version_exclusion():
    # Advisory affects versions < 4.0.0, fixed in 4.0.0
    ranges = [VersionRange(end_excluding="4.0.0")]
    fixed = ["4.0.0"]

    # Exactly fixed version MUST NOT be marked vulnerable
    is_vuln, reason = VersionMatcher.evaluate_vulnerability("4.0.0", ranges, fixed)
    assert is_vuln is False
    assert reason == "FIXED_VERSION"

    # Newer than fixed version MUST NOT be marked vulnerable
    is_vuln, reason = VersionMatcher.evaluate_vulnerability("4.0.1", ranges, fixed)
    assert is_vuln is False
    assert reason == "FIXED_VERSION"

    # Older affected version IS marked vulnerable
    is_vuln, reason = VersionMatcher.evaluate_vulnerability("3.9.9", ranges, fixed)
    assert is_vuln is True
    assert reason == "AFFECTED_RANGE"


def test_multiple_ranges():
    # Affected: [1.0, 1.5) and [2.0, 2.5)
    ranges = [
        VersionRange(start_including="1.0", end_excluding="1.5"),
        VersionRange(start_including="2.0", end_excluding="2.5"),
    ]
    # In range 1
    assert VersionMatcher.evaluate_vulnerability("1.2", ranges)[0] is True
    # In gap between ranges
    assert VersionMatcher.evaluate_vulnerability("1.8", ranges)[0] is False
    # In range 2
    assert VersionMatcher.evaluate_vulnerability("2.1", ranges)[0] is True
    # Above range 2
    assert VersionMatcher.evaluate_vulnerability("3.0", ranges)[0] is False


def test_unknown_and_malformed_versions():
    ranges = [VersionRange(end_excluding="5.0.0")]

    # None
    is_vuln, reason = VersionMatcher.evaluate_vulnerability(None, ranges)
    assert is_vuln is False
    assert reason == "UNKNOWN_VERSION"

    # UNKNOWN_VERSION token
    is_vuln, reason = VersionMatcher.evaluate_vulnerability(UNKNOWN_VERSION, ranges)
    assert is_vuln is False
    assert reason == "UNKNOWN_VERSION"

    # Malformed unparseable string
    is_vuln, reason = VersionMatcher.evaluate_vulnerability("corrupted_version_tag", ranges)
    assert is_vuln is False
    assert reason == "UNKNOWN_VERSION"
