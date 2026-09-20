# Drishti v0.1 — Version Parsing & Range Evaluation | Phase 03
from __future__ import annotations

import re
from typing import Any

from app.services.vuln_intel.models import VersionRange

UNKNOWN_VERSION = "UNKNOWN_VERSION"


class VersionMatcher:
    """Robust version comparison engine supporting semver, numeric tuples, and vendor formats."""

    @classmethod
    def parse_components(cls, v_str: str | None) -> list[int | str] | None:
        """Parse version string into a comparable sequence of integer and string segments."""
        if not v_str or not v_str.strip() or v_str == UNKNOWN_VERSION:
            return None

        # Clean common prefixes (v, ver, release-)
        cleaned = re.sub(r"^[a-zA-Z_\-]+", "", v_str.strip())
        if not cleaned:
            return None

        # Tokenize by dots, hyphens, underscores, or transitions between digits and letters
        tokens = re.findall(r"\d+|[a-zA-Z]+", cleaned)
        if not tokens:
            return None

        components: list[int | str] = []
        for tok in tokens:
            if tok.isdigit():
                components.append(int(tok))
            else:
                components.append(tok.lower())

        return components

    @classmethod
    def compare(cls, v1: str | None, v2: str | None) -> int | None:
        """Compare two version strings.

        Returns:
            -1 if v1 < v2
             0 if v1 == v2
             1 if v1 > v2
             None if comparison is inconclusive / malformed
        """
        c1 = cls.parse_components(v1)
        c2 = cls.parse_components(v2)
        if c1 is None or c2 is None:
            return None

        # Align lengths with 0 for numeric padding
        max_len = max(len(c1), len(c2))
        pad1 = c1 + [0] * (max_len - len(c1))
        pad2 = c2 + [0] * (max_len - len(c2))

        for a, b in zip(pad1, pad2):
            if type(a) is type(b):
                if a < b:
                    return -1
                if a > b:
                    return 1
            else:
                # Numbers take precedence over letter suffixes (e.g. 1.0 > 1.0-beta)
                if isinstance(a, int) and isinstance(b, str):
                    return 1
                if isinstance(a, str) and isinstance(b, int):
                    return -1

        return 0

    @classmethod
    def is_in_range(cls, version: str, r: VersionRange) -> bool | None:
        """Evaluate if version satisfies a single VersionRange boundary."""
        # 1. Lower boundary
        if r.start_including:
            cmp = cls.compare(version, r.start_including)
            if cmp is None:
                return None
            if cmp < 0:
                return False
        elif r.start_excluding:
            cmp = cls.compare(version, r.start_excluding)
            if cmp is None:
                return None
            if cmp <= 0:
                return False

        # 2. Upper boundary
        if r.end_including:
            cmp = cls.compare(version, r.end_including)
            if cmp is None:
                return None
            if cmp > 0:
                return False
        elif r.end_excluding:
            cmp = cls.compare(version, r.end_excluding)
            if cmp is None:
                return None
            if cmp >= 0:
                return False

        return True

    @classmethod
    def evaluate_vulnerability(
        cls,
        observed_version: str | None,
        affected_ranges: list[VersionRange],
        fixed_versions: list[str] | None = None,
    ) -> tuple[bool, str]:
        """Evaluate if an observed version is vulnerable based on ranges and fixed versions.

        Returns:
            (True, "AFFECTED_RANGE") if confirmed vulnerable
            (False, "FIXED_VERSION") if fixed/newer
            (False, "NOT_IN_RANGE") if not vulnerable
            (False, "UNKNOWN_VERSION") if version is unknown/malformed
        """
        if not observed_version or observed_version == UNKNOWN_VERSION:
            return False, "UNKNOWN_VERSION"

        comp = cls.parse_components(observed_version)
        if comp is None:
            return False, "UNKNOWN_VERSION"

        # 1. Check fixed version exclusions
        for fix in fixed_versions or []:
            cmp = cls.compare(observed_version, fix)
            if cmp is not None and cmp >= 0:
                return False, "FIXED_VERSION"

        # 2. If affected ranges are explicitly defined, check all ranges
        if affected_ranges:
            for r in affected_ranges:
                in_rng = cls.is_in_range(observed_version, r)
                if in_rng is True:
                    return True, "AFFECTED_RANGE"
            return False, "NOT_IN_RANGE"

        # If no explicit ranges but fixed versions exist and observed_version < fix
        if fixed_versions:
            for fix in fixed_versions:
                cmp = cls.compare(observed_version, fix)
                if cmp is not None and cmp < 0:
                    return True, "AFFECTED_BELOW_FIX"

        return False, "NO_BOUNDS_DEFINED"
