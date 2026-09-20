# Drishti v0.1 — Local Vulnerability Cache | Phase 03
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from app.services.vuln_intel.models import SourceStatus, VulnerabilityRecord

logger = logging.getLogger("drishti.vuln_intel.cache")


class LocalVulnerabilityCache:
    """Thread-safe, source-aware local vulnerability intelligence cache."""

    def __init__(self, ttl_seconds: float = 3600.0):
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        # id -> VulnerabilityRecord
        self._records: dict[str, VulnerabilityRecord] = {}
        # (vendor, product) -> set[id]
        self._product_index: dict[tuple[str | None, str], set[str]] = {}
        # (ecosystem, package) -> set[id]
        self._package_index: dict[tuple[str, str], set[str]] = {}
        # source_name -> SourceStatus
        self._source_status: dict[str, SourceStatus] = {}

    def put(self, record: VulnerabilityRecord) -> bool:
        """Insert or update a record, avoiding overwriting newer data with older data."""
        with self._lock:
            existing = self._records.get(record.id)
            if existing:
                # If existing has modified_at and record has modified_at, do not downgrade
                if existing.modified_at and record.modified_at:
                    if record.modified_at < existing.modified_at:
                        return False

                # Merge aliases, sources, references, and ranges
                merged_aliases = sorted(set(existing.aliases + record.aliases))
                merged_sources = sorted(set(existing.sources + record.sources))
                merged_refs = sorted(set(existing.references + record.references))
                merged_fixed = sorted(set(existing.fixed_versions + record.fixed_versions))
                merged_ranges = existing.affected_ranges + [
                    r for r in record.affected_ranges if r not in existing.affected_ranges
                ]

                record.aliases = merged_aliases
                record.sources = merged_sources
                record.references = merged_refs
                record.fixed_versions = merged_fixed
                record.affected_ranges = merged_ranges
                record.in_kev = existing.in_kev or record.in_kev
                record.kev_date_added = record.kev_date_added or existing.kev_date_added

            self._records[record.id] = record

            # Index by product
            if record.product:
                key = (record.vendor.lower() if record.vendor else None, record.product.lower())
                self._product_index.setdefault(key, set()).add(record.id)
                if record.vendor:
                    # Also index by product alone
                    self._product_index.setdefault((None, record.product.lower()), set()).add(record.id)

            # Index by package
            if record.package and record.ecosystem:
                pkg_key = (record.ecosystem.lower(), record.package.lower())
                self._package_index.setdefault(pkg_key, set()).add(record.id)

            return True

    def get_by_id(self, vuln_id: str) -> VulnerabilityRecord | None:
        key = vuln_id.strip().upper()
        with self._lock:
            # Check primary ID
            if key in self._records:
                return self._records[key]
            # Check aliases
            for rec in self._records.values():
                if key in [a.upper() for a in rec.aliases]:
                    return rec
            return None

    def query_by_product(self, vendor: str | None, product: str) -> list[VulnerabilityRecord]:
        prod_key = (vendor.lower() if vendor else None, product.lower())
        fallback_key = (None, product.lower())
        with self._lock:
            ids = set(self._product_index.get(prod_key, set()))
            if not ids and vendor:
                ids = set(self._product_index.get(fallback_key, set()))

            records: list[VulnerabilityRecord] = []
            for vid in ids:
                rec = self._records.get(vid)
                if rec:
                    records.append(rec)
            return records

    def query_by_package(self, ecosystem: str, package: str) -> list[VulnerabilityRecord]:
        key = (ecosystem.lower(), package.lower())
        with self._lock:
            ids = self._package_index.get(key, set())
            return [self._records[vid] for vid in ids if vid in self._records]

    def set_source_status(self, status: SourceStatus) -> None:
        with self._lock:
            self._source_status[status.source_name] = status

    def get_source_status(self, source_name: str) -> SourceStatus:
        with self._lock:
            return self._source_status.get(
                source_name,
                SourceStatus(source_name=source_name, available=True, last_sync=None, error_reason=None),
            )

    def all_source_statuses(self) -> list[SourceStatus]:
        with self._lock:
            return list(self._source_status.values())

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._product_index.clear()
            self._package_index.clear()
            self._source_status.clear()
