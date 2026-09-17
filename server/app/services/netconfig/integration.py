# Drishti v0.1 — netconfig findings → engine integration | 12-Jul-2026
"""Map REAL network-config findings into the existing domain objects so the risk
engine reasons over them with no special-casing.

Each real finding becomes a Vulnerability (a synthetic, CVE-less 'config' vuln
whose severity/exploitability come from the finding's own severity model) plus an
AssetVulnerability on every affected asset. Then the caller runs the SAME
recompute_org — so these misconfigurations raise the affected nodes' risk,
strengthen the attack paths through them, and move the $-impact. Unknown/passed
checks create NOTHING (no fabrication)."""
from __future__ import annotations

from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AssetVulnerability, Vulnerability
from app.services.netconfig.detectors import severity_to_engine


def _config_vuln(db: Session, finding: dict) -> Vulnerability:
    """Upsert a CVE-less Vulnerability for a config finding, keyed by title."""
    title = f"[NET-CONFIG/{finding['category']}] {finding['title']}"[:255]
    vuln = db.scalar(
        select(Vulnerability).where(
            Vulnerability.cve_id.is_(None), Vulnerability.title == title
        )
    )
    cvss, exploitability = severity_to_engine(finding["severity"])
    if vuln is None:
        vuln = Vulnerability(
            cve_id=None,  # not a CVE — a configuration weakness
            title=title,
            description=finding.get("evidence") or None,
            cvss=Decimal(str(cvss)),
            severity=finding["severity"] if finding["severity"] in (
                "low", "medium", "high", "critical") else "medium",
            exploitability=Decimal(str(exploitability)),
            cwe="CWE-1188",  # insecure default / network config weakness class
        )
        db.add(vuln)
        db.flush()
    return vuln


def map_findings_to_engine(db: Session, org_id: str, findings: list[dict]) -> int:
    """Create engine records for every REAL finding with an affected asset.

    Mutates each mapped finding in place to carry `finding_id` (the first
    AssetVulnerability id) so the UI can route it into AI remediation. Returns the
    number of engine findings created/attached. Caller recomputes + commits."""
    created = 0
    current: set[tuple[str, str]] = set()  # (asset_id, vuln_id) attached this run
    for f in findings:
        if f.get("status") != "real" or not f.get("affected_ids"):
            continue
        vuln = _config_vuln(db, f)
        for asset_id in f["affected_ids"]:
            current.add((asset_id, vuln.id))
            row = db.scalar(
                select(AssetVulnerability).where(
                    AssetVulnerability.asset_id == asset_id,
                    AssetVulnerability.vulnerability_id == vuln.id,
                )
            )
            if row is None:
                row = AssetVulnerability(
                    org_id=org_id,
                    asset_id=asset_id,
                    vulnerability_id=vuln.id,
                    service_id=None,
                    status="open",
                )
                db.add(row)
                db.flush()
                created += 1
            elif row.status not in ("resolved", "accepted"):
                row.status = "open"  # a re-detected misconfig re-opens its finding
            if not f.get("finding_id"):
                f["finding_id"] = row.id  # first affected asset → remediation link

    # Reconcile: config findings this analysis no longer produces mean the misconfig
    # was fixed — close the org's still-open NET-CONFIG findings absent from this run
    # so remediation actually lowers risk (mirrors ingest._upsert_findings).
    stale = db.scalars(
        select(AssetVulnerability)
        .join(Vulnerability, Vulnerability.id == AssetVulnerability.vulnerability_id)
        .where(
            AssetVulnerability.org_id == org_id,
            AssetVulnerability.status == "open",
            Vulnerability.cve_id.is_(None),
            Vulnerability.title.like("[NET-CONFIG/%"),
        )
    ).all()
    for row in stale:
        if (row.asset_id, row.vulnerability_id) not in current:
            row.status = "resolved"
    db.flush()
    return created
