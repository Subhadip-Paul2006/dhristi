# Drishti v0.1 — Endpoint Telemetry Ingestion & Storage Service | Phase 02
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from app.schemas.endpoint import (
    EndpointTelemetryOut,
    EndpointTelemetrySubmitRequest,
)
from app.services.vuln_intel.correlator import VulnerabilityCorrelator
from app.services.vuln_intel.models import CorrelatedFinding, SourceStatus

logger = logging.getLogger("drishti.server.endpoint_telemetry")

# Telemetry TTL constants in seconds
VOLATILE_TELEMETRY_TTL_SECONDS: float = 60.0
SOFTWARE_TELEMETRY_TTL_SECONDS: float = 300.0
PURGE_EXPIRATION_SECONDS: float = 600.0  # complete eviction after 10m without update

_TELEMETRY_LOCK = threading.Lock()
# Key: (org_id, device_id) -> telemetry record dict
_DEVICE_TELEMETRY_STORE: dict[tuple[str, str], dict[str, Any]] = {}
# Key: (org_id, device_id) -> list of CorrelatedFinding
_DEVICE_VULN_FINDINGS: dict[tuple[str, str], list[CorrelatedFinding]] = {}
_DEFAULT_CORRELATOR: VulnerabilityCorrelator = VulnerabilityCorrelator()


def record_telemetry(
    org_id: str,
    agent_id: str,
    device_id: str,
    payload: EndpointTelemetrySubmitRequest,
) -> dict[str, Any]:
    """Ingest, validate, and store endpoint telemetry strictly isolated by (org_id, device_id)."""
    now_utc = datetime.now(timezone.utc)
    now_mono = time.monotonic()
    key = (org_id, device_id)

    with _TELEMETRY_LOCK:
        existing = _DEVICE_TELEMETRY_STORE.get(key)

        # Merge or initialize software and OS info (which update on slow cycle)
        software = (
            [item.model_dump() for item in payload.installed_software]
            if payload.installed_software is not None
            else (existing.get("installed_software", []) if existing else [])
        )
        software_mono = (
            now_mono
            if payload.installed_software is not None
            else (existing.get("last_software_updated_mono", now_mono) if existing else now_mono)
        )
        software_dt = (
            now_utc
            if payload.installed_software is not None
            else (existing.get("last_software_updated", now_utc) if existing else now_utc)
        )

        # If payload has applications (e.g. from Android) and installed_software was not explicitly passed,
        # map packages into installed_software so the vulnerability correlator seamlessly evaluates them.
        if payload.applications and payload.installed_software is None:
            synth_software = []
            for app_item in payload.applications:
                pkg_name = app_item.get("package_name") or app_item.get("name")
                label = app_item.get("label") or pkg_name
                ver_name = app_item.get("version_name") or app_item.get("version")
                classification = app_item.get("classification", "USER_APP")
                if pkg_name:
                    synth_software.append({
                        "name": label or pkg_name,
                        "version": ver_name,
                        "vendor": classification,
                        "source": "android_package",
                        "observed_at": now_utc.isoformat(),
                    })
            if synth_software:
                software = synth_software
                software_mono = now_mono
                software_dt = now_utc

        record: dict[str, Any] = {
            "org_id": org_id,
            "agent_id": agent_id,
            "device_id": device_id,
            "hostname": payload.hostname or (existing.get("hostname") if existing else None),
            "os_name": payload.os_name or (existing.get("os_name") if existing else None),
            "os_version": payload.os_version or (existing.get("os_version") if existing else None),
            "os_info": payload.os_info or (existing.get("os_info") if existing else None),
            "endpoint_processes": [p.model_dump() for p in (payload.endpoint_processes or [])],
            "active_apps": list(payload.active_apps or []),
            "installed_software": software,
            "services": [s.model_dump() for s in (payload.services or [])],
            "listening_ports": [lp.model_dump() for lp in (payload.listening_ports or [])],
            "process_connections": [pc.model_dump() for pc in (payload.process_connections or [])],
            "installed_browsers": list(payload.installed_browsers or []),
            "browser_processes": [bp.model_dump() for bp in (payload.browser_processes or [])],
            # Android & extended platform telemetry fields
            "device_model": payload.device_model or (existing.get("device_model") if existing else None),
            "manufacturer": payload.manufacturer or (existing.get("manufacturer") if existing else None),
            "sdk_version": payload.sdk_version if payload.sdk_version is not None else (existing.get("sdk_version") if existing else None),
            "cpu_info": payload.cpu_info or (existing.get("cpu_info") if existing else None),
            "memory_info": payload.memory_info or (existing.get("memory_info") if existing else None),
            "storage_info": payload.storage_info or (existing.get("storage_info") if existing else None),
            "battery_info": payload.battery_info or (existing.get("battery_info") if existing else None),
            "network_info": payload.network_info or (existing.get("network_info") if existing else None),
            "security_posture": payload.security_posture or (existing.get("security_posture") if existing else None),
            "applications": [dict(a) for a in (payload.applications or (existing.get("applications", []) if existing else []))],
            "last_updated_mono": now_mono,
            "last_updated": now_utc,
            "last_software_updated_mono": software_mono,
            "last_software_updated": software_dt,
        }

        _DEVICE_TELEMETRY_STORE[key] = record

    if payload.installed_software is not None or (payload.applications and software):
        try:
            correlate_device_software(org_id, device_id)
        except Exception as exc:
            logger.warning("[Vuln Correlation] Error during telemetry ingestion: %s", exc)

    logger.info(
        "[Telemetry Ingestion] Processed for device %s (org: %s, procs: %d, ports: %d, software: %d, svcs: %d)",
        device_id,
        org_id,
        len(record["endpoint_processes"]),
        len(record["listening_ports"]),
        len(record["installed_software"]),
        len(record["services"]),
    )

    return {
        "success": True,
        "accepted_at": now_utc,
        "processes_count": len(record["endpoint_processes"]),
        "software_count": len(record["installed_software"]),
        "services_count": len(record["services"]),
        "ports_count": len(record["listening_ports"]),
    }



def get_telemetry_for_device(
    org_id: str,
    device_id: str,
    reference_mono: float | None = None,
) -> EndpointTelemetryOut | None:
    """Retrieve device-scoped telemetry, calculating TTL stale indicators.

    Strict device isolation: returns None if no telemetry exists for the given (org_id, device_id).
    """
    key = (org_id, device_id)
    with _TELEMETRY_LOCK:
        record = _DEVICE_TELEMETRY_STORE.get(key)
        if not record:
            return None

        # Copy shallow container to avoid mutating inside lock
        rec = dict(record)

    now_mono = reference_mono if reference_mono is not None else time.monotonic()
    volatile_age = now_mono - rec.get("last_updated_mono", now_mono)
    software_age = now_mono - rec.get("last_software_updated_mono", now_mono)

    is_stale = volatile_age > VOLATILE_TELEMETRY_TTL_SECONDS
    is_software_stale = software_age > SOFTWARE_TELEMETRY_TTL_SECONDS

    return EndpointTelemetryOut(
        device_id=rec["device_id"],
        agent_id=rec["agent_id"],
        hostname=rec.get("hostname"),
        os_name=rec.get("os_name"),
        os_version=rec.get("os_version"),
        endpoint_processes=rec.get("endpoint_processes", []),
        active_apps=rec.get("active_apps", []),
        installed_software=rec.get("installed_software", []),
        services=rec.get("services", []),
        listening_ports=rec.get("listening_ports", []),
        process_connections=rec.get("process_connections", []),
        installed_browsers=rec.get("installed_browsers", []),
        browser_processes=rec.get("browser_processes", []),
        os_info=rec.get("os_info"),
        device_model=rec.get("device_model"),
        manufacturer=rec.get("manufacturer"),
        sdk_version=rec.get("sdk_version"),
        cpu_info=rec.get("cpu_info"),
        memory_info=rec.get("memory_info"),
        storage_info=rec.get("storage_info"),
        battery_info=rec.get("battery_info"),
        network_info=rec.get("network_info"),
        security_posture=rec.get("security_posture"),
        applications=rec.get("applications", []),
        last_updated=rec.get("last_updated"),
        is_stale=is_stale,
        is_software_stale=is_software_stale,
        source="endpoint_agent",
    )


def get_correlator() -> VulnerabilityCorrelator:
    """Return the global vulnerability correlator instance."""
    global _DEFAULT_CORRELATOR
    return _DEFAULT_CORRELATOR


def set_correlator(correlator: VulnerabilityCorrelator) -> None:
    """Override the global vulnerability correlator instance (useful for test isolation)."""
    global _DEFAULT_CORRELATOR
    _DEFAULT_CORRELATOR = correlator


_ENDPOINT_FINDING_STATUSES: dict[tuple[str, str], str] = {}


def get_endpoint_finding_by_id(org_id: str, finding_id: str) -> tuple[CorrelatedFinding, dict[str, Any]] | None:
    """Lookup a CorrelatedFinding and its associated device telemetry strictly within org_id.
    Returns (finding, device_telemetry_dict) or None.
    """
    with _TELEMETRY_LOCK:
        for (k_org, k_dev), findings in _DEVICE_VULN_FINDINGS.items():
            if k_org != org_id:
                continue
            for f in findings:
                if f.finding_id == finding_id:
                    telemetry = _DEVICE_TELEMETRY_STORE.get((k_org, k_dev), {})
                    return f, telemetry

        # If not in cached findings, check active devices in telemetry store
        for (k_org, k_dev), telemetry in _DEVICE_TELEMETRY_STORE.items():
            if k_org != org_id:
                continue
            software = telemetry.get("installed_software", [])
            if software:
                try:
                    findings = _DEFAULT_CORRELATOR.correlate_endpoint_software(k_org, k_dev, software)
                    _DEVICE_VULN_FINDINGS[(k_org, k_dev)] = findings
                    for f in findings:
                        if f.finding_id == finding_id:
                            return f, telemetry
                except Exception:
                    pass
    return None


def list_endpoint_findings_for_org(org_id: str) -> list[tuple[CorrelatedFinding, dict[str, Any]]]:
    """List all correlated endpoint vulnerability findings for an organization."""
    results: list[tuple[CorrelatedFinding, dict[str, Any]]] = []
    with _TELEMETRY_LOCK:
        for (k_org, k_dev), findings in _DEVICE_VULN_FINDINGS.items():
            if k_org != org_id:
                continue
            telemetry = _DEVICE_TELEMETRY_STORE.get((k_org, k_dev), {})
            for f in findings:
                results.append((f, telemetry))
    return results


def update_endpoint_finding_status(org_id: str, finding_id: str, status: str) -> bool:
    """Update mutable triage status for an endpoint finding."""
    key = (org_id, finding_id)
    with _TELEMETRY_LOCK:
        _ENDPOINT_FINDING_STATUSES[key] = status
    return True


def get_endpoint_finding_status(org_id: str, finding_id: str) -> str:
    """Retrieve triage status for an endpoint finding, defaulting to 'open'."""
    key = (org_id, finding_id)
    with _TELEMETRY_LOCK:
        return _ENDPOINT_FINDING_STATUSES.get(key, "open")


def correlate_device_software(org_id: str, device_id: str) -> list[CorrelatedFinding]:
    """Execute vulnerability correlation on a device's genuine installed software."""
    key = (org_id, device_id)
    with _TELEMETRY_LOCK:
        rec = _DEVICE_TELEMETRY_STORE.get(key)
        if not rec:
            return []
        software = list(rec.get("installed_software", []))

    findings = _DEFAULT_CORRELATOR.correlate_endpoint_software(org_id, device_id, software)
    with _TELEMETRY_LOCK:
        _DEVICE_VULN_FINDINGS[key] = findings
    return findings


def get_vulnerability_findings_for_device(org_id: str, device_id: str) -> list[CorrelatedFinding]:
    """Retrieve isolated vulnerability findings for a specific device, running correlation if needed."""
    key = (org_id, device_id)
    with _TELEMETRY_LOCK:
        cached = _DEVICE_VULN_FINDINGS.get(key)
        if cached is not None:
            return list(cached)
    return correlate_device_software(org_id, device_id)


def purge_stale_telemetry(max_idle_seconds: float = PURGE_EXPIRATION_SECONDS) -> int:
    """Purge records that have exceeded complete expiration window."""
    now_mono = time.monotonic()
    purged = 0
    with _TELEMETRY_LOCK:
        expired_keys = [
            k
            for k, v in _DEVICE_TELEMETRY_STORE.items()
            if (now_mono - v.get("last_updated_mono", 0.0)) > max_idle_seconds
        ]
        for k in expired_keys:
            del _DEVICE_TELEMETRY_STORE[k]
            _DEVICE_VULN_FINDINGS.pop(k, None)
            purged += 1
    return purged


def clear_telemetry_store() -> None:
    """Reset the telemetry store and vulnerability cache for test isolation."""
    with _TELEMETRY_LOCK:
        _DEVICE_TELEMETRY_STORE.clear()
        _DEVICE_VULN_FINDINGS.clear()
        _ENDPOINT_FINDING_STATUSES.clear()
    _DEFAULT_CORRELATOR.cache.clear()


