# Drishti v0.1 — deep-scan orchestrator | 12-Jul-2026
"""Orchestrate a consented deep scan: validate consent + target, run the real
nmap scan, match real CVEs, feed them into the existing risk engine, and
persist the result.

Defensive + consent-gated by construction:
  • the caller MUST pass consent=true (else 422);
  • the target MUST be a private/LAN (RFC1918/loopback) address (public IPs are
    refused, 422) — this scans a device the user owns/authorizes, never the
    wider internet.
Nothing is fabricated: a scan or lookup that can't run is persisted and returned
as available:false with a truthful reason."""
from __future__ import annotations

import ipaddress
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.errors import DomainError, NotFoundError
from app.models import DeepScan
from app.models.base import utcnow
from app.schemas.live import (
    DeepScanCve,
    DeepScanRangeResult,
    DeepScanResult,
    DeepScanService,
)
from app.services.deepscan import cve_lookup, integration, scanner

logger = logging.getLogger("drishti")


def _validation_error(message: str) -> DomainError:
    err = DomainError(message)
    err.status = 422
    err.code = "validation_error"
    return err


def _require_private_ip(ip: str) -> str:
    """Parse `ip` and require a private/LAN address. Refuse public IPs (defensive
    scope) and anything unparseable."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise _validation_error(f"'{ip}' is not a valid IP address")
    # require an RFC1918-style private address; reject loopback (127/8) and
    # link-local (169.254/16, incl. the 169.254.169.254 metadata endpoint) even
    # though ipaddress counts those as "private".
    if not (addr.is_private and not (addr.is_loopback or addr.is_link_local)):
        raise _validation_error(
            "Deep scan is restricted to private/LAN devices (RFC1918/loopback). "
            "Refusing to scan a public address."
        )
    return str(addr)


def deep_scan(db: Session, org_id: str, ip: str, consent: bool) -> DeepScanResult:
    if consent is not True:
        raise _validation_error(
            "Explicit consent is required. Only scan devices you own or are "
            "authorized to test."
        )
    target = _require_private_ip(ip)

    scan = scanner.scan(target)
    if not scan.get("available"):
        return _persist_unavailable(db, org_id, target, scan.get("reason") or "scan unavailable")

    cve_result = cve_lookup.lookup_for_services(scan.get("services", []))
    applied = integration.apply_scan(db, org_id, target, scan, cve_result)

    result = DeepScanResult(
        available=True,
        target=target,
        os=applied.get("os"),
        ports=applied.get("ports", []),
        services=[DeepScanService(**s) for s in applied.get("services", [])],
        cves=[DeepScanCve(**c) for c in applied.get("cves", [])],
        cve_lookup_unavailable=not cve_result.get("available", False),
        cve_lookup_reason=cve_result.get("reason"),
        asset_id=applied.get("asset_id"),
        risk_score=applied.get("risk_score"),
        top_path_risk=applied.get("top_path_risk"),
        top_path_formed=applied.get("top_path_formed", False),
        scanned_at=utcnow(),
    )
    _persist(db, org_id, result)
    db.commit()
    return result


def _require_private_cidr(cidr: str) -> str:
    """Parse `cidr` and require a private/LAN range. Refuse public ranges and
    anything unreasonably large (a huge sweep is neither fast nor kind)."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        raise _validation_error(f"'{cidr}' is not a valid CIDR range")
    if not (net.is_private and not (net.is_loopback or net.is_link_local)):
        raise _validation_error(
            "Deep scan is restricted to private/LAN ranges (RFC1918). "
            "Refusing to scan a public range."
        )
    if net.num_addresses > 1024:
        raise _validation_error(
            f"Range {net} is too large ({net.num_addresses} addresses). "
            "Use a /22 or smaller subnet."
        )
    return str(net)


def deep_scan_range(db: Session, org_id: str, cidr: str, consent: bool) -> DeepScanRangeResult:
    """Consented subnet scan: discover live hosts, version-scan them (capped),
    match real CVEs, feed ALL of them into ONE engine recompute so cross-host
    attack paths form on real data. Direct Nmap on the local subnet — no NAT,
    routing, port-forwarding, or traffic interception."""
    if consent is not True:
        raise _validation_error(
            "Explicit consent is required. Only scan networks you own or are "
            "authorized to test."
        )
    net = _require_private_cidr(cidr)
    cap = get_settings().deepscan_max_total_hosts

    rng = scanner.scan_range(net)
    if not rng.get("available"):
        result = DeepScanRangeResult(
            available=False, cidr=net, unavailable_reason=rng.get("reason") or "scan unavailable",
            host_cap=cap, scanned_at=utcnow(),
        )
        _persist(db, org_id, DeepScanResult(available=False, target=net,
                 unavailable_reason=result.unavailable_reason, scanned_at=utcnow()))
        db.commit()
        return result

    # real CVE lookup per discovered host, then ONE recompute for the batch
    payload = [
        {"scan": h, "cve_result": cve_lookup.lookup_for_services(h.get("services", []))}
        for h in rng["hosts"]
    ]
    summaries = integration.apply_range(db, org_id, payload)

    host_results: list[DeepScanResult] = []
    for summ, hp in zip(summaries, payload):
        cve_res = hp["cve_result"]
        r = DeepScanResult(
            available=True,
            target=summ["target"],
            os=summ.get("os"),
            ports=summ.get("ports", []),
            services=[DeepScanService(**s) for s in summ.get("services", [])],
            cves=[DeepScanCve(**c) for c in summ.get("cves", [])],
            cve_lookup_unavailable=not cve_res.get("available", False),
            cve_lookup_reason=cve_res.get("reason"),
            asset_id=summ.get("asset_id"),
            risk_score=summ.get("risk_score"),
            top_path_risk=summ.get("top_path_risk"),
            top_path_formed=summ.get("top_path_formed", False),
            scanned_at=utcnow(),
        )
        _persist(db, org_id, r)
        host_results.append(r)

    db.commit()
    return DeepScanRangeResult(
        available=True,
        cidr=net,
        hosts_discovered=rng.get("discovered", 0),
        hosts_scanned=len(host_results),
        host_cap=cap,
        capped=rng.get("capped", False),
        hosts=host_results,
        scanned_at=utcnow(),
    )


def _persist_unavailable(db: Session, org_id: str, target: str, reason: str) -> DeepScanResult:
    result = DeepScanResult(
        available=False,
        target=target,
        unavailable_reason=reason,
        scanned_at=utcnow(),
    )
    _persist(db, org_id, result)
    db.commit()
    return result


def _persist(db: Session, org_id: str, result: DeepScanResult) -> None:
    db.add(
        DeepScan(
            org_id=org_id,
            asset_id=result.asset_id,
            target_ip=result.target,
            available=result.available,
            unavailable_reason=result.unavailable_reason,
            result_json=result.model_dump(mode="json"),
        )
    )


def get_last(db: Session, org_id: str, asset_id: str) -> DeepScanResult:
    """Re-fetch the most recent deep-scan result for an asset."""
    row = db.scalar(
        select(DeepScan)
        .where(DeepScan.org_id == org_id, DeepScan.asset_id == asset_id)
        .order_by(DeepScan.created_at.desc())
    )
    if row is None:
        raise NotFoundError("No deep scan found for this asset")
    return DeepScanResult(**row.result_json)
