# Drishti v0.1 — NVD Vulnerability Intelligence Source | Phase 03
from __future__ import annotations

import logging
import time
from typing import Any

from app.config import get_settings
from app.services.deepscan.cve_lookup import (
    _MIN_SPACING_S,
    _nvd_metrics,
    _severity_from_cvss,
    _state_lock,
    fetch_nvd,
    fetch_nvd_cpe,
)
from app.services.vuln_intel.models import (
    SourceStatus,
    VersionRange,
    VulnerabilityRecord,
)
from app.services.vuln_intel.sources.base import BaseVulnerabilitySource

logger = logging.getLogger("drishti.vuln_intel.nvd")


class NVDSource(BaseVulnerabilitySource):
    """Integrates with NIST National Vulnerability Database (NVD) 2.0 REST API."""

    def __init__(self, timeout: float = 6.0):
        super().__init__(name="nvd")
        self.timeout = timeout
        self._last_call_at = 0.0

    def _rate_limit_spacing(self) -> None:
        with _state_lock:
            now = time.monotonic()
            elapsed = now - self._last_call_at
            if elapsed < _MIN_SPACING_S:
                time.sleep(_MIN_SPACING_S - elapsed)
            self._last_call_at = time.monotonic()

    def parse_configurations(self, cve_item: dict[str, Any]) -> list[VersionRange]:
        """Extract explicit version ranges from NVD configurations cpeMatch nodes."""
        ranges: list[VersionRange] = []
        configurations = cve_item.get("configurations") or []
        for config in configurations:
            nodes = config.get("nodes") or []
            for node in nodes:
                cpe_matches = node.get("cpeMatch") or []
                for match in cpe_matches:
                    v_start_inc = match.get("versionStartIncluding")
                    v_start_exc = match.get("versionStartExcluding")
                    v_end_inc = match.get("versionEndIncluding")
                    v_end_exc = match.get("versionEndExcluding")

                    if any([v_start_inc, v_start_exc, v_end_inc, v_end_exc]):
                        ranges.append(
                            VersionRange(
                                start_including=v_start_inc,
                                start_excluding=v_start_exc,
                                end_including=v_end_inc,
                                end_excluding=v_end_exc,
                            )
                        )
        return ranges

    def lookup(
        self,
        product: str,
        version: str | None,
        vendor: str | None = None,
        cpe: str | None = None,
        ecosystem: str | None = None,
    ) -> tuple[list[VulnerabilityRecord], SourceStatus]:
        """Query NVD by CPE or keyword with version constraints."""
        settings = get_settings()
        api_key = getattr(settings, "NVD_API_KEY", "")

        self._rate_limit_spacing()

        payload: dict[str, Any] | None = None
        err_msg: str | None = None

        if cpe:
            payload, err_msg = fetch_nvd_cpe(cpe, self.timeout, api_key)
        else:
            search_token = f"{vendor} {product}" if vendor else product
            payload, err_msg = fetch_nvd(search_token, version or "", self.timeout, api_key)

        if err_msg or payload is None:
            self.mark_failure(err_msg or "NVD returned no payload")
            return [], self.status

        self.mark_success()
        records: list[VulnerabilityRecord] = []

        token = product.lower().strip()
        version_token = (version or "").lower().strip()

        for item in payload.get("vulnerabilities", []) or []:
            cve = item.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue

            summary = ""
            for d in cve.get("descriptions", []) or []:
                if d.get("lang") == "en":
                    summary = d.get("value", "")
                    break

            hay = f"{summary} {cve_id}".lower()
            # If doing keyword match (no precise CPE), verify tokens exist in text
            if not cpe:
                if token and token not in hay:
                    continue
                if version_token and version_token not in hay:
                    continue

            cvss, severity, expl_score, expl_max = _nvd_metrics(cve.get("metrics") or {})
            if cvss is None:
                continue

            affected_ranges = self.parse_configurations(cve)

            # References
            refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")]

            records.append(
                VulnerabilityRecord(
                    id=cve_id,
                    summary=summary[:600],
                    cvss=round(float(cvss), 1),
                    severity=(severity or _severity_from_cvss(cvss)).lower(),
                    vendor=vendor,
                    product=product,
                    cpe23=cpe,
                    affected_ranges=affected_ranges,
                    exploitability=expl_score,
                    published_at=cve.get("published"),
                    modified_at=cve.get("lastModified"),
                    sources=["nvd"],
                    references=refs[:5],
                )
            )

        records.sort(key=lambda r: r.cvss, reverse=True)
        return records, self.status
