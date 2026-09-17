# Drishti v0.1 — shared signal types | 11-Jul-2026
"""Shared signal type + status constants for the analyzer."""
from __future__ import annotations

from dataclasses import dataclass

# Statuses that COUNT toward the score (an evaluated signal).
PASS = "pass"
WARN = "warn"
FAIL = "fail"
# Statuses that DO NOT count — the signal could not be evaluated.
UNKNOWN = "unknown"
NOT_CONFIGURED = "not_configured"
UNREACHABLE = "unreachable"

EVALUATED = {PASS, WARN, FAIL}

# Score contribution of each evaluated status, in [0, 1].
STATUS_VALUE: dict[str, float] = {PASS: 1.0, WARN: 0.5, FAIL: 0.0}


@dataclass
class Signal:
    key: str
    label: str
    status: str
    detail: str
    weight: float

    @property
    def counted(self) -> bool:
        return self.status in EVALUATED
