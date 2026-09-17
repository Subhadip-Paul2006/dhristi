# Drishti v0.1 — AI orchestration service | 11-Jul-2026
"""AI orchestration: assemble real context → call model/mock → persist/echo.

The engine computes the dollar figure; the AI explains it (never recomputes).
"""
from __future__ import annotations

import shlex
from decimal import Decimal

import yaml
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.errors import NotFoundError
from app.models import (
    Asset,
    AssetVulnerability,
    AttackPath,
    Connection,
    Remediation,
    RiskZone,
    Service,
    Vulnerability,
)
from app.schemas.ai import ImpactOut, PredictOut, RemediationOut
from app.services.ai import prompts
from app.services.ai.client import generate

# Phrases that only appear in genuinely OFFENSIVE output — never in a defensive
# CVE description or a hardening fix. Deliberately NOT "exploit"/"payload"/
# "malware": those are normal in real CVE text ("can be exploited via a crafted
# payload", "detects malware") and were false-refusing legitimate findings from
# real scans. This guard only ever runs on model OUTPUT, so it stays a backstop
# against the model emitting an attack, not a filter on the input vuln context.
_OFFENSIVE_MARKERS = (
    "reverse shell",
    "bind shell",
    "how to exploit",
    "weaponize",
    "establish persistence",
    "exfiltrate",
    "attack the target",
    "ransomware",
)


def _guard_offensive(*texts: str | None) -> bool:
    joined = " ".join(t.lower() for t in texts if t)
    return any(m in joined for m in _OFFENSIVE_MARKERS)


def remediate(db: Session, org_id: str, finding_id: str, preferred_kind: str, regenerate: bool) -> RemediationOut:
    finding = db.get(AssetVulnerability, finding_id)
    if finding is None or finding.org_id != org_id:
        raise NotFoundError("Finding not found")

    # cache: return the last remediation unless regenerate requested
    if not regenerate:
        existing = db.scalar(
            select(Remediation)
            .where(Remediation.asset_vulnerability_id == finding_id)
            .order_by(Remediation.created_at.desc())
        )
        if existing is not None and existing.kind == preferred_kind:
            return _remediation_from_row(existing)

    asset = db.get(Asset, finding.asset_id)
    vuln = db.get(Vulnerability, finding.vulnerability_id)
    zone = db.get(RiskZone, asset.zone_id) if asset and asset.zone_id else None
    service = db.get(Service, finding.service_id) if finding.service_id else None

    ctx = {
        "asset": {
            "hostname": asset.hostname,
            "ip": asset.ip,
            "os": asset.os,
            "asset_type": asset.asset_type,
            "zone": zone.name if zone else None,
            "criticality": asset.criticality,
            "internet_facing": asset.internet_facing,
        },
        "service": (
            {"name": service.name, "version": service.version, "port": service.port}
            if service
            else None
        ),
        "vulnerability": {
            "cve_id": vuln.cve_id,
            "title": vuln.title,
            "cvss": float(vuln.cvss),
            "severity": vuln.severity,
            "description": vuln.description,
        },
        "preferred_kind": preferred_kind,
    }

    # NOTE: no input-side guard on the CVE title/description — describing a real
    # vulnerability is legitimate defensive context, not an offensive request.
    # The output guard below still ensures we never emit an offensive fix.
    fallback = _templated_remediation(ctx)
    system, user_json, schema = prompts.build_remediation_messages(ctx)
    # Mock fixture only for the hero example (the PostgreSQL priv-esc, ansible);
    # every other finding/kind gets the context-specific template so mocked
    # output references the real hostname + CVE and changes with the kind tab.
    is_postgres_hero = (vuln.cve_id or "").endswith("0005") and preferred_kind == "ansible"
    mock_key = "remediate_postgres" if is_postgres_hero else None
    data = generate(system, user_json, mock_key, fallback, schema)

    if data.get("refused"):
        return RemediationOut(refused=True, reason=data.get("reason") or "Not supported")
    if not data.get("script"):
        # never persist an empty fix — fall back to the deterministic checklist
        data = fallback

    if _guard_offensive(data.get("title"), data.get("summary"), data.get("script")):
        return RemediationOut(refused=True, reason="Request could not be answered defensively.")

    settings = get_settings()
    # schema says 0-100 but clamp anyway — the DB column and UI assume a percentage
    risk_reduction = min(max(float(data.get("estimated_risk_reduction") or 0), 0.0), 100.0)
    row = Remediation(
        org_id=org_id,
        asset_vulnerability_id=finding_id,
        kind=data.get("kind", preferred_kind),
        title=data.get("title", "")[:255],
        summary=data.get("summary", ""),
        script=data.get("script", ""),
        risk_reduction=Decimal(str(risk_reduction)),
        generated_by="ai",
        model=("mock" if settings.ai_mock else settings.resolved_ai_model),
        reviewed=False,
        details_json={
            "steps": data.get("steps", []),
            "requires_restart": bool(data.get("requires_restart", False)),
            "disclaimer": data.get("disclaimer"),
        },
    )
    db.add(row)
    db.commit()

    out = _remediation_from_row(row)
    out.context = ctx  # exact input handed to the model (UI inspector) — not persisted
    return out


def _remediation_from_row(row: Remediation) -> RemediationOut:
    out = RemediationOut(
        id=row.id,
        refused=False,
        kind=row.kind,
        title=row.title,
        summary=row.summary,
        script=row.script,
        estimated_risk_reduction=float(row.risk_reduction) if row.risk_reduction is not None else None,
        reviewed=row.reviewed,
        model=row.model,
    )
    details = row.details_json or {}
    out.steps = details.get("steps", [])
    out.requires_restart = bool(details.get("requires_restart", False))
    if details.get("disclaimer"):
        out.disclaimer = details["disclaimer"]
    return out


def _templated_remediation(ctx: dict) -> dict:
    """Deterministic hardening fix built from the real finding context.

    Used when the model is unavailable, and as the mock-mode output for every
    finding except the hero fixture — so title/summary/script reference the
    actual hostname + CVE and the script matches the requested kind.
    """
    svc = ctx.get("service") or {}
    name = svc.get("name") or "the affected service"
    host = ctx["asset"]["hostname"] or ctx["asset"]["ip"]
    vuln = ctx.get("vulnerability") or {}
    cve = vuln.get("cve_id") or "the reported finding"
    vuln_title = vuln.get("title") or "the reported vulnerability"
    kind = ctx.get("preferred_kind", "ansible")

    if kind == "shell":
        host_sh = shlex.quote(str(host))
        name_sh = shlex.quote(str(name))
        script = (
            "#!/usr/bin/env bash\n"
            f"# Defensive hardening for {cve} ({vuln_title}) on {host_sh}\n"
            "# Review each step before running in production.\n"
            "set -euo pipefail\n\n"
            "# 1. Apply vendor security updates\n"
            "sudo apt-get update && sudo apt-get upgrade -y   # or: sudo dnf upgrade -y\n\n"
            f"# 2. Restrict network access to {name_sh} (scope to your trusted subnet)\n"
            f"# sudo ufw allow from <trusted-subnet> to any port {svc.get('port', '<port>')}\n\n"
            "# 3. Rotate credentials used by the service and enforce least privilege\n"
            f"echo {shlex.quote(f'Rotate credentials and review privileges for {name} on {host}')}\n"
        )
    elif kind == "cloud_cli":
        host_sh = shlex.quote(str(host))
        name_sh = shlex.quote(str(name))
        port = svc.get("port", "<port>")
        inet = ctx["asset"].get("internet_facing")
        if inet:
            # Internet-facing asset: DO NOT close the public service port — that
            # breaks legitimate traffic. Keep it public, front it with a WAF, and
            # only lock down management access.
            access_block = (
                f"# 1. {name_sh} is internet-facing — keep port {port} public but put a\n"
                "#    WAF in front and rate-limit; do NOT restrict it to an internal CIDR.\n"
                f"aws wafv2 associate-web-acl --web-acl-arn <waf-acl-arn> --resource-arn <alb-arn>\n"
                "#    Restrict only management ports (e.g. SSH 22) to the admin network:\n"
                "aws ec2 authorize-security-group-ingress --group-id <sg-id> \\\n"
                "  --protocol tcp --port 22 --cidr <admin-network-cidr>\n\n"
            )
        else:
            access_block = (
                f"# 1. Restrict the security group exposing {name_sh} to trusted CIDRs only\n"
                "aws ec2 revoke-security-group-ingress --group-id <sg-id> \\\n"
                f"  --protocol tcp --port {port} --cidr 0.0.0.0/0\n"
                "aws ec2 authorize-security-group-ingress --group-id <sg-id> \\\n"
                f"  --protocol tcp --port {port} --cidr <trusted-cidr>\n\n"
            )
        script = (
            f"# Defensive hardening for {cve} ({vuln_title}) on {host_sh}\n"
            "# Review each command and substitute your resource IDs before running.\n\n"
            f"{access_block}"
            "# 2. Apply pending patches via your managed patch baseline\n"
            "aws ssm send-command --document-name 'AWS-RunPatchBaseline' \\\n"
            f"  --targets {shlex.quote(f'Key=tag:Name,Values={host}')} --parameters 'Operation=Install'\n\n"
            "# 3. Rotate credentials referenced by the workload\n"
            "aws secretsmanager rotate-secret --secret-id <secret-id>\n"
        )
    elif kind == "manual":
        script = (
            f"Manual remediation plan for {cve} ({vuln_title}) on {host}:\n"
            "1. Apply the vendor security patch for the affected version.\n"
            f"2. Restrict network access to {name} to trusted sources only.\n"
            "3. Rotate any credentials the service uses and enforce least privilege.\n"
            "4. Re-scan the host and verify the finding no longer reproduces.\n"
        )
    else:  # ansible (default)
        # default_style='"' + a huge width forces a single-line, double-quoted
        # scalar no matter what host/name contain (quotes, colons, newlines),
        # so it can't fold into extra lines or break the surrounding indentation.
        def _yaml_kv(key: str, value: str) -> str:
            return yaml.safe_dump(
                {key: value}, default_flow_style=False, default_style='"',
                width=1 << 20, allow_unicode=True,
            ).strip()

        hosts_line = _yaml_kv("hosts", host)
        name_line = _yaml_kv("name", f"Harden {name} on {host}")
        msg_line = _yaml_kv("msg", f"Restrict firewall rules and rotate credentials for {name}")
        script = (
            "---\n"
            f"# Defensive hardening for {cve} ({vuln_title}) — review before applying\n"
            f"- {name_line}\n"
            f"  {hosts_line}\n"
            "  become: true\n"
            "  tasks:\n"
            "    - name: Apply latest security updates\n"
            "      ansible.builtin.package:\n"
            "        name: '*'\n"
            "        state: latest\n"
            "    # NOTE: review and scope the following to the affected service\n"
            "    - name: Restrict service to trusted subnet (review before applying)\n"
            "      ansible.builtin.debug:\n"
            f"        {msg_line}\n"
        )

    return {
        "refused": False,
        "kind": kind,
        "title": f"Harden {name} on {host} ({cve})",
        "summary": (
            f"Defensive fix for {vuln_title} on {host}: apply vendor patches, restrict "
            f"network access to {name}, rotate credentials, and enforce least privilege."
        ),
        "script": script,
        "steps": [
            "Apply vendor security patches",
            f"Restrict network access to {name} on {host}",
            "Rotate credentials and enforce least privilege",
            "Re-scan to verify the finding is closed",
        ],
        "estimated_risk_reduction": 15.0,
        "requires_restart": False,
        "disclaimer": "Generated suggestion — review and test before running in production.",
    }


def impact(db: Session, org_id: str, path_id: str) -> ImpactOut:
    path = db.scalar(select(AttackPath).where(AttackPath.org_id == org_id, AttackPath.id == path_id))
    if path is None:
        raise NotFoundError("Attack path not found")

    computed_impact = float(path.impact_usd)
    target = db.get(Asset, path.target_asset_id)

    step_vulns = []
    for step in path.steps:
        if step.via_vulnerability_id:
            v = db.get(Vulnerability, step.via_vulnerability_id)
            if v:
                step_vulns.append(v.title)

    ctx = {
        "path": {
            "entry": path.entry_label,
            "target": target.hostname if target else "crown jewel",
            "hop_count": path.hop_count,
            "steps": [s.asset_id for s in path.steps],
        },
        "impact_usd": computed_impact,
        "likelihood": float(path.likelihood),
        "drivers": step_vulns[:3],
    }

    # No input-side guard: attack-path context (labels, CVE titles) is real threat
    # data and must always be analyzable. The output guard below is the backstop.
    fallback = _templated_impact(computed_impact, target, step_vulns)
    system, user_json, schema = prompts.build_impact_messages(ctx)
    data = generate(system, user_json, "impact_hero_path", fallback, schema)

    if data.get("refused"):
        return ImpactOut(refused=True, reason=data.get("reason") or "Not supported",
                         impact_usd=computed_impact)

    # The AI explains; it must never change the number. Force the computed figure.
    # `or` (not .get default) so empty strings from the model also fall back.
    narrative = data.get("narrative") or fallback["narrative"]
    out = ImpactOut(
        impact_usd=computed_impact,
        headline=data.get("headline") or fallback["headline"],
        narrative=narrative,
        drivers=data.get("drivers") or fallback["drivers"],
        highest_leverage_action=data.get("highest_leverage_action") or fallback["highest_leverage_action"],
    )

    if _guard_offensive(out.headline, out.narrative, *out.drivers, out.highest_leverage_action):
        return ImpactOut(refused=True, reason="Request could not be answered defensively.",
                         impact_usd=computed_impact)

    # cache the narrative on the path
    path.narrative = narrative
    db.commit()
    return out


def _templated_impact(computed: float, target, step_vulns: list[str]) -> dict:
    tgt = target.hostname if target else "the crown-jewel asset"
    return {
        "refused": False,
        "impact_usd": computed,
        "headline": f"A reachable breach path to {tgt} represents roughly ${computed:,.0f} of exposure.",
        "narrative": (
            f"An attacker entering from the internet could chain several weaknesses to reach {tgt}. "
            f"Given the ease of the chained steps and the value of the data at risk, the estimated "
            f"exposure is approximately ${computed:,.0f}. Closing the highest-leverage step would "
            "break the chain and materially reduce this figure."
        ),
        "drivers": step_vulns[:3] or ["Chained lateral movement to a high-value asset"],
        "highest_leverage_action": f"Remediate the key vulnerability on {tgt} to sever the final hop.",
    }


def predict(db: Session, org_id: str, asset_id: str) -> PredictOut:
    asset = db.scalar(select(Asset).where(Asset.org_id == org_id, Asset.id == asset_id))
    if asset is None:
        raise NotFoundError("Asset not found")

    neighbors = db.scalars(
        select(Connection).where(Connection.from_asset_id == asset_id)
    ).all()
    neighbor_ctx = []
    for c in neighbors:
        n = db.get(Asset, c.to_asset_id)
        if n is None:
            continue
        neighbor_ctx.append(
            {
                "hostname": n.hostname,
                "asset_type": n.asset_type,
                "criticality": n.criticality,
                "relation": c.relation,
                "weight": float(c.weight) if c.weight is not None else None,
            }
        )

    ctx = {
        "from_asset": asset.hostname or asset.ip,
        "neighbors": neighbor_ctx,
    }

    # No input-side guard: asset/neighbor names are real inventory data and must
    # always be analyzable. The output guard below is the backstop.
    fallback = _templated_predict(asset, neighbor_ctx)
    system, user_json, schema = prompts.build_predict_messages(ctx)
    data = generate(system, user_json, "predict_jump01", fallback, schema)

    if data.get("refused"):
        return PredictOut(refused=True, reason=data.get("reason") or "Not supported",
                          from_asset=ctx["from_asset"])
    merged = {**fallback, **data, "from_asset": ctx["from_asset"]}
    if not merged.get("predictions"):
        merged["predictions"] = fallback["predictions"]
    try:
        out = PredictOut(**merged)
    except ValidationError:
        # malformed model output must never surface as a 500 — use the template
        return PredictOut(**fallback)

    pred_texts = [t for p in out.predictions for t in (p.asset, p.reason, p.defensive_action)]
    if _guard_offensive(out.from_asset, *pred_texts):
        return PredictOut(refused=True, reason="Request could not be answered defensively.",
                          from_asset=ctx["from_asset"])
    return out


def _templated_predict(asset, neighbor_ctx: list[dict]) -> dict:
    preds = []
    for n in sorted(neighbor_ctx, key=lambda x: x.get("weight") or 1.0)[:3]:
        preds.append(
            {
                "asset": n["hostname"] or "neighbor",
                "likelihood": round(1.0 - min(0.9, (n.get("weight") or 0.5)), 2),
                "reason": f"{n['relation']} link to a {n['criticality']}-criticality {n['asset_type']}.",
                "defensive_action": "Segment access, patch known issues, and monitor for lateral movement.",
            }
        )
    return {
        "refused": False,
        "from_asset": asset.hostname or asset.ip,
        "predictions": preds,
    }
