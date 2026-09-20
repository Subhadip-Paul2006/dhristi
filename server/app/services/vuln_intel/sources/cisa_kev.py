# Drishti v0.1 — CISA KEV Vulnerability Intelligence Source | Phase 03
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from app.services.deepscan.intel_correlate import _KEV_TTL_S, fetch_kev_catalog
from app.services.vuln_intel.models import (
    SourceStatus,
    VulnerabilityRecord,
)
from app.services.vuln_intel.sources.base import BaseVulnerabilitySource

logger = logging.getLogger("drishti.vuln_intel.cisa_kev")


class CISAKEVSource(BaseVulnerabilitySource):
    """Integrates with CISA Known Exploited Vulnerabilities (KEV) Catalog."""

    def __init__(self, timeout: float = 6.0):
        super().__init__(name="cisa_kev")
        self.timeout = timeout
        self._lock = threading.Lock()
        self._kev_map: dict[str, dict[str, Any]] = {}
        self._last_fetched_mono = 0.0

    def sync_catalog(self) -> None:
        """Fetch and parse official CISA KEV catalog if empty or expired."""
        now_mono = time.monotonic()
        with self._lock:
            if self._kev_map and (now_mono - self._last_fetched_mono) < _KEV_TTL_S:
                return

        payload, err = fetch_kev_catalog(self.timeout)
        if err or not payload:
            self.mark_failure(err or "CISA KEV payload empty")
            return

        items = payload.get("vulnerabilities") or []
        parsed_map: dict[str, dict[str, Any]] = {}
        for item in items:
            cve_id = (item.get("cveID") or "").strip().upper()
            if cve_id.startswith("CVE-"):
                parsed_map[cve_id] = {
                    "date_added": item.get("dateAdded"),
                    "vulnerability_name": item.get("vulnerabilityName"),
                    "required_action": item.get("requiredAction"),
                    "notes": item.get("notes"),
                }

        with self._lock:
            self._kev_map = parsed_map
            self._last_fetched_mono = time.monotonic()
        self.mark_success()

    def is_in_kev(self, cve_id: str) -> tuple[bool, dict[str, Any] | None]:
        """Check if a specific CVE is registered in the CISA KEV catalog."""
        self.sync_catalog()
        key = cve_id.strip().upper()
        with self._lock:
            entry = self._kev_map.get(key)
        return bool(entry is not None), entry

    def enrich(self, record: VulnerabilityRecord) -> bool:
        """Enrich a verified vulnerability record with CISA KEV intelligence."""
        candidate_ids = [record.id] + [a for a in record.aliases if a.startswith("CVE-")]
        for cid in candidate_ids:
            in_kev, entry = self.is_in_kev(cid)
            if in_kev and entry:
                record.in_kev = True
                record.kev_date_added = entry.get("date_added")
                if "cisa_kev" not in record.sources:
                    record.sources.append("cisa_kev")
                return True
        return False

    def lookup(
        self,
        product: str,
        version: str | None,
        vendor: str | None = None,
        cpe: str | None = None,
        ecosystem: str | None = None,
    ) -> tuple[list[VulnerabilityRecord], SourceStatus]:
        """Lookup KEV by product (CISA KEV is an enrichment catalog, not primary search)."""
        self.sync_catalog()
        return [], self.status
