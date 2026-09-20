# Drishti v0.1 — Base Vulnerability Source Interface | Phase 03
from __future__ import annotations

import abc
from datetime import datetime, timezone
from app.services.vuln_intel.models import SourceStatus, VulnerabilityRecord


class BaseVulnerabilitySource(abc.ABC):
    """Abstract interface for external vulnerability intelligence providers."""

    def __init__(self, name: str):
        self.name = name
        self._available = True
        self._last_error: str | None = None
        self._last_sync: str | None = None

    @property
    def status(self) -> SourceStatus:
        return SourceStatus(
            source_name=self.name,
            available=self._available,
            last_sync=self._last_sync,
            error_reason=self._last_error,
        )

    def mark_success(self) -> None:
        self._available = True
        self._last_error = None
        self._last_sync = datetime.now(timezone.utc).isoformat()

    def mark_failure(self, reason: str) -> None:
        self._available = False
        self._last_error = reason

    @abc.abstractmethod
    def lookup(
        self,
        product: str,
        version: str | None,
        vendor: str | None = None,
        cpe: str | None = None,
        ecosystem: str | None = None,
    ) -> tuple[list[VulnerabilityRecord], SourceStatus]:
        """Query the source for advisories matching the given target."""
        raise NotImplementedError
