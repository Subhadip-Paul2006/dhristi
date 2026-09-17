# Drishti v0.1 — network intelligence analytics | 11-Jul-2026
"""Network-wide intelligence over cached engine output: CVE aggregation, risk-band
distribution, and unsupervised ML (IsolationForest anomalies + KMeans segments).

The ML path imports scikit-learn lazily and degrades gracefully (available=False)
if the dependency is missing or there are too few assets — it must never raise to
the router (ERROR_HANDLING.md §2).
"""
from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Asset, AssetVulnerability, AttackPath, Service, Vulnerability
from app.schemas.report import (
    AffectedHost,
    AnomalousNode,
    CveRow,
    Distribution,
    MlAnalysis,
    NetworkSummaryOut,
    RiskBand,
    SecuritySegment,
)

logger = logging.getLogger("drishti")

_CRITICALITY_ORDINAL = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# ── A1: high-severity CVE aggregation ────────────────────────────────────────
def cve_report(db: Session, org_id: str) -> list[CveRow]:
    """Aggregate every open finding by CVE → CVSS, severity, affected hosts."""
    rows = db.execute(
        select(Vulnerability, Asset)
        .join(AssetVulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
        .join(Asset, Asset.id == AssetVulnerability.asset_id)
        .where(AssetVulnerability.org_id == org_id, AssetVulnerability.status == "open")
    ).all()

    by_vuln: dict[str, dict] = {}
    for vuln, asset in rows:
        entry = by_vuln.setdefault(
            vuln.id,
            {
                "cve_id": vuln.cve_id,
                "title": vuln.title,
                "cvss": float(vuln.cvss),
                "severity": vuln.severity,
                "hosts": {},
            },
        )
        entry["hosts"][asset.id] = AffectedHost(hostname=asset.hostname, ip=asset.ip)

    out = [
        CveRow(
            cve_id=e["cve_id"],
            title=e["title"],
            cvss=e["cvss"],
            severity=e["severity"],
            affected_count=len(e["hosts"]),
            affected=list(e["hosts"].values()),
        )
        for e in by_vuln.values()
    ]
    out.sort(key=lambda r: (r.cvss, r.affected_count), reverse=True)
    return out


# ── A2: risk-band distribution ───────────────────────────────────────────────
def _band(score: float) -> str:
    # Mirrors web/src/lib/format.ts riskBucket thresholds (0..100).
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "safe"


def distribution(db: Session, org_id: str) -> Distribution:
    assets = db.scalars(select(Asset).where(Asset.org_id == org_id)).all()
    scores = [float(a.risk_score or 0.0) for a in assets]
    total = len(assets)
    counts = {"critical": 0, "high": 0, "medium": 0, "safe": 0}
    for s in scores:
        counts[_band(s)] += 1
    avg = round(sum(scores) / total, 1) if total else 0.0
    bands = [
        RiskBand(band=b, count=counts[b], pct=round(100 * counts[b] / total, 1) if total else 0.0)
        for b in ("critical", "high", "medium", "safe")
    ]
    return Distribution(total_assets=total, average_risk=avg, bands=bands)


# ── B1/B2: ML anomaly + segmentation ─────────────────────────────────────────
def _feature_rows(db: Session, org_id: str) -> tuple[list[Asset], list[list[float]]]:
    assets = db.scalars(select(Asset).where(Asset.org_id == org_id)).all()

    # batch the per-asset aggregates so we don't fan out a query per asset/finding
    open_counts: dict[str, int] = {
        asset_id: count
        for asset_id, count in db.execute(
            select(AssetVulnerability.asset_id, func.count())
            .where(AssetVulnerability.org_id == org_id, AssetVulnerability.status == "open")
            .group_by(AssetVulnerability.asset_id)
        ).all()
    }
    max_cvss_by_asset: dict[str, float] = {
        asset_id: float(mx)
        for asset_id, mx in db.execute(
            select(AssetVulnerability.asset_id, func.max(Vulnerability.cvss))
            .join(Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
            .where(AssetVulnerability.org_id == org_id, AssetVulnerability.status == "open")
            .group_by(AssetVulnerability.asset_id)
        ).all()
        if mx is not None
    }
    service_counts: dict[str, int] = {
        asset_id: count
        for asset_id, count in db.execute(
            select(Service.asset_id, func.count())
            .where(Service.org_id == org_id)
            .group_by(Service.asset_id)
        ).all()
    }

    features: list[list[float]] = []
    for a in assets:
        features.append(
            [
                float(a.risk_score or 0.0),
                float(open_counts.get(a.id, 0)),
                max_cvss_by_asset.get(a.id, 0.0),
                float(service_counts.get(a.id, 0)),
                float(a.blast_radius_count or 0),
                float(_CRITICALITY_ORDINAL.get(a.criticality, 1)),
                1.0 if a.internet_facing else 0.0,
            ]
        )
    return assets, features


def ml_analysis(db: Session, org_id: str) -> MlAnalysis:
    assets, features = _feature_rows(db, org_id)
    n = len(assets)
    if n < 4:
        return MlAnalysis(
            available=False,
            algorithm_note=f"Not enough assets for ML analysis (need ≥4, have {n}).",
        )
    try:
        import numpy as np
        from sklearn.cluster import KMeans
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except Exception as exc:  # sklearn missing
        logger.warning("ml analysis unavailable: %s", exc)
        return MlAnalysis(available=False, algorithm_note="scikit-learn not installed.")

    X = StandardScaler().fit_transform(np.array(features, dtype=float))

    # IsolationForest — outlier nodes (unusual risk/exposure fingerprint).
    iso = IsolationForest(random_state=42, contamination="auto")
    iso.fit(X)
    raw = iso.score_samples(X)  # higher = more normal; lower = more anomalous
    preds = iso.predict(X)  # -1 = outlier
    anomalies: list[AnomalousNode] = []
    for a, score, pred in zip(assets, raw, preds):
        if pred == -1:
            anomalies.append(
                AnomalousNode(
                    hostname=a.hostname,
                    ip=a.ip,
                    anomaly_score=round(float(score), 3),
                    risk_score=round(float(a.risk_score or 0.0), 1),
                    reason=_anomaly_reason(a),
                )
            )
    anomalies.sort(key=lambda x: x.anomaly_score)  # most anomalous first

    # KMeans — group assets into security segments, label by mean risk.
    k = min(4, n)
    labels = KMeans(n_clusters=k, random_state=42, n_init=10).fit_predict(X)
    segments: list[SecuritySegment] = []
    for seg in range(k):
        members = [a for a, lbl in zip(assets, labels) if lbl == seg]
        if not members:
            continue
        mean_risk = sum(float(m.risk_score or 0.0) for m in members) / len(members)
        segments.append(
            SecuritySegment(
                segment=seg,
                risk_pct=round(mean_risk, 1),
                label=_seg_label(mean_risk),
                members=[m.hostname or m.ip for m in members],
            )
        )
    segments.sort(key=lambda s: s.risk_pct, reverse=True)

    return MlAnalysis(
        available=True,
        algorithm_note="IsolationForest (anomalies) + KMeans (segments) over 7 asset features.",
        anomalies=anomalies,
        segments=segments,
    )


def _anomaly_reason(a: Asset) -> str:
    bits = []
    if a.internet_facing:
        bits.append("internet-facing")
    if (a.blast_radius_count or 0) >= 3:
        bits.append(f"wide blast radius ({a.blast_radius_count})")
    if a.criticality in ("high", "critical"):
        bits.append(f"{a.criticality} criticality")
    if float(a.risk_score or 0) >= 60:
        bits.append(f"risk {float(a.risk_score):.0f}")
    return ", ".join(bits) or "unusual feature profile vs the fleet"


def _seg_label(mean_risk: float) -> str:
    if mean_risk >= 60:
        return "HIGH"
    if mean_risk >= 40:
        return "MEDIUM"
    return "LOW"


# ── A3: AI executive threat-narrative ────────────────────────────────────────
def network_summary(db: Session, org_id: str) -> NetworkSummaryOut:
    """Build a whole-network context from cached engine output and ask the model
    for an executive threat narrative. Never recomputes numbers — explains them."""
    from app.services.ai import prompts
    from app.services.ai.client import generate

    dist = distribution(db, org_id)
    cves = cve_report(db, org_id)
    top_cves = [
        {
            "cve_id": c.cve_id,
            "title": c.title,
            "cvss": c.cvss,
            "affected": [h.hostname or h.ip for h in c.affected][:5],
        }
        for c in cves[:6]
    ]
    exposed = db.scalars(
        select(Asset).where(Asset.org_id == org_id, Asset.internet_facing.is_(True))
    ).all()
    gateways = []
    for a in exposed:
        svcs = db.scalars(select(Service).where(Service.asset_id == a.id)).all()
        gateways.append(
            {
                "hostname": a.hostname or a.ip,
                "ip": a.ip,
                "criticality": a.criticality,
                "blast_radius": a.blast_radius_count,
                "services": [f"{s.name}:{s.port}" for s in svcs][:6],
            }
        )
    top_paths = db.scalars(
        select(AttackPath).where(AttackPath.org_id == org_id).order_by(AttackPath.path_risk.desc()).limit(3)
    ).all()
    paths_ctx = [
        {"entry": p.entry_label, "hops": p.hop_count, "impact_usd": float(p.impact_usd)}
        for p in top_paths
    ]
    # single canonical definition of network exposure (dedupe to the max cached
    # path impact per unique target) — shared with the dashboard so both agree.
    from app.services.dashboard_service import _total_exposure_from_cache

    total_exposure = _total_exposure_from_cache(db, org_id)

    ctx = {
        "total_assets": dist.total_assets,
        "average_risk": dist.average_risk,
        "risk_bands": [{"band": b.band, "count": b.count, "pct": b.pct} for b in dist.bands],
        "top_cves": top_cves,
        "internet_facing": gateways,
        "top_attack_paths": paths_ctx,
        "total_exposure_usd": total_exposure,
    }

    fallback = _templated_summary(ctx)
    system, user_json, schema = prompts.build_network_summary_messages(ctx)
    data = generate(system, user_json, "network_summary", fallback, schema)

    if data.get("refused"):
        return NetworkSummaryOut(refused=True, reason=data.get("reason") or "Not supported")
    return NetworkSummaryOut(
        headline=data.get("headline") or fallback["headline"],
        narrative=data.get("narrative") or fallback["narrative"],
        top_risks=data.get("top_risks") or fallback["top_risks"],
        priority_actions=data.get("priority_actions") or fallback["priority_actions"],
    )


def _templated_summary(ctx: dict) -> dict:
    crit = next((b["count"] for b in ctx["risk_bands"] if b["band"] == "critical"), 0)
    gw = ctx["internet_facing"][0]["hostname"] if ctx["internet_facing"] else "the perimeter"
    top_cve = ctx["top_cves"][0]["cve_id"] if ctx["top_cves"] else "the top finding"
    return {
        "refused": False,
        "headline": (
            f"{crit} critical-risk assets and an internet-facing entry at {gw} give an "
            f"attacker a foothold into the network."
        ),
        "narrative": (
            f"Across {ctx['total_assets']} assets the average risk is {ctx['average_risk']}/100, "
            f"with {crit} in the critical band. The internet-facing {gw} is the most dangerous "
            f"exposure, and reachable attack paths chain to high-value assets for roughly "
            f"${ctx['total_exposure_usd']:,.0f} of exposure. Closing the highest-leverage step "
            "would break the chain and materially reduce this figure."
        ),
        "top_risks": [
            f"Internet-facing {gw}",
            f"{top_cve} on multiple hosts",
            f"{crit} assets in the critical risk band",
        ],
        "priority_actions": [
            f"Harden and segment the internet-facing {gw}",
            "Patch the highest-CVSS CVEs on affected hosts",
            "Restrict lateral movement between high-value assets",
        ],
    }
