# Drishti v0.1 — network-config analysis orchestrator | 12-Jul-2026
"""Run all network-config detectors on the org's real topology (+ optional
declared config), map real findings into the existing engine, recompute, and
persist the result.

Defensive + consent-gated: this READS configuration/topology to help secure the
network. It never attacks or intercepts traffic. Consent is required; findings
are derived from real observed/declared data or marked 'unknown' — never faked."""
from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import DomainError
from app.models import Asset, AttackPath, NetconfigAnalysis
from app.models.base import utcnow
from app.schemas.netconfig import (
    NetconfigAnalysisOut,
    NetconfigFinding,
    NetconfigInput,
    RiskSummary,
)
from app.services.engine_loader import load_engine
from app.services.netconfig import detectors, facts, integration

logger = logging.getLogger("drishti")


def _validation_error(message: str) -> DomainError:
    err = DomainError(message)
    err.status = 422
    err.code = "validation_error"
    return err


def analyze(db: Session, org_id: str, consent: bool, config: NetconfigInput | None) -> NetconfigAnalysisOut:
    if consent is not True:
        raise _validation_error(
            "Explicit consent is required. Only analyze networks you own or are "
            "authorized to assess."
        )

    net_facts = facts.gather(db, org_id, config)
    engine = load_engine(db, org_id)
    findings = detectors.run_all(engine, net_facts)

    # map the REAL findings into the existing engine, then recompute ONCE
    integration.map_findings_to_engine(db, org_id, findings)
    from app.services.recompute import recompute_org

    recompute_org(db, org_id)
    db.flush()

    summary = _risk_summary(db, org_id, findings)
    out = NetconfigAnalysisOut(
        available=True,
        findings=[_to_schema(f) for f in findings],
        recomputed_risk=summary,
        used_declared_config=net_facts.used_declared_config,
        generated_at=utcnow(),
    )
    db.add(
        NetconfigAnalysis(
            org_id=org_id,
            used_declared_config=net_facts.used_declared_config,
            real_findings=summary.real_findings,
            result_json=out.model_dump(mode="json"),
        )
    )
    db.commit()
    return out


def last(db: Session, org_id: str) -> NetconfigAnalysisOut:
    """Most recent stored analysis, or an empty available:false shell if none."""
    row = db.scalar(
        select(NetconfigAnalysis)
        .where(NetconfigAnalysis.org_id == org_id)
        .order_by(NetconfigAnalysis.created_at.desc())
    )
    if row is None:
        total = db.scalar(select(func.count()).select_from(Asset).where(Asset.org_id == org_id)) or 0
        return NetconfigAnalysisOut(
            available=False,
            findings=[],
            recomputed_risk=RiskSummary(
                total_assets=int(total), average_risk=0.0,
                real_findings=0, unknown_findings=0, passed_checks=0,
            ),
        )
    return NetconfigAnalysisOut(**row.result_json)


def _risk_summary(db: Session, org_id: str, findings: list[dict]) -> RiskSummary:
    assets = db.scalars(select(Asset).where(Asset.org_id == org_id)).all()
    scores = [float(a.risk_score) for a in assets if a.risk_score is not None]
    avg = round(sum(scores) / len(scores), 2) if scores else 0.0
    top = db.scalar(
        select(func.max(AttackPath.path_risk)).where(AttackPath.org_id == org_id)
    )
    return RiskSummary(
        # count ALL assets (not just risk-scored ones) to match the last() path
        total_assets=len(assets),
        average_risk=avg,
        real_findings=sum(1 for f in findings if f["status"] == "real"),
        unknown_findings=sum(1 for f in findings if f["status"] == "unknown"),
        passed_checks=sum(1 for f in findings if f["status"] == "passed"),
        top_path_risk=round(float(top), 2) if top is not None else None,
    )


def _to_schema(f: dict) -> NetconfigFinding:
    return NetconfigFinding(
        id=f["id"],
        category=f["category"],
        title=f["title"],
        severity=f["severity"],
        status=f["status"],
        source=f["source"],
        evidence=f["evidence"],
        affected=f["affected"],
        remediation_hint=f["remediation_hint"],
        finding_id=f.get("finding_id"),
    )
