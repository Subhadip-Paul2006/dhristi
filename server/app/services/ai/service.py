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
from dataclasses import dataclass, field

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


@dataclass
class RemediationContext:
    finding_id: str
    device_id: str
    org_id: str
    source: str  # "network" | "endpoint"
    hostname: str | None = None
    ip: str | None = None
    os: str | None = None
    asset_type: str = "workstation"
    criticality: int = 1
    internet_facing: bool = False
    product: str | None = None
    version: str | None = None
    service_name: str | None = None
    port: int | None = None
    protocol: str = "tcp"
    cve_id: str | None = None
    title: str | None = None
    summary: str | None = None
    cvss: float = 0.0
    severity: str = "medium"
    affected_range: str | None = None
    fixed_version: str | None = None
    in_kev: bool = False
    evidence: str | None = None
    finding_state: str = "CONFIRMED_VULNERABLE"
    zone: str | None = None


# Memory cache for endpoint remediations (avoids inserting invalid foreign keys into DB)
_ENDPOINT_REMEDIATIONS: dict[tuple[str, str, str], RemediationOut] = {}


def resolve_remediation_context(db: Session, org_id: str, finding_id: str) -> RemediationContext:
    """Resolve finding context from either database AssetVulnerability or endpoint CorrelatedFinding."""
    # 1. Try DB AssetVulnerability
    finding = db.get(AssetVulnerability, finding_id)
    if finding is not None and finding.org_id == org_id:
        asset = db.get(Asset, finding.asset_id)
        vuln = db.get(Vulnerability, finding.vulnerability_id)
        zone = db.get(RiskZone, asset.zone_id) if asset and asset.zone_id else None
        service = db.get(Service, finding.service_id) if finding.service_id else None
        return RemediationContext(
            finding_id=finding.id,
            device_id=asset.id if asset else finding.asset_id,
            org_id=org_id,
            source="network",
            hostname=asset.hostname if asset else None,
            ip=asset.ip if asset else "0.0.0.0",
            os=asset.os if asset else None,
            asset_type=asset.asset_type if asset else "workstation",
            criticality=asset.criticality if asset else 1,
            internet_facing=asset.internet_facing if asset else False,
            product=service.name if service else None,
            version=service.version if service else None,
            service_name=service.name if service else None,
            port=service.port if service else None,
            cve_id=vuln.cve_id if vuln else None,
            title=vuln.title if vuln else "Unknown vulnerability",
            summary=vuln.description if vuln else None,
            cvss=float(vuln.cvss) if vuln else 0.0,
            severity=vuln.severity if vuln else "medium",
            zone=zone.name if zone else None,
            finding_state="CONFIRMED_VULNERABLE",
        )

    # 2. Try Phase 03/04 Endpoint CorrelatedFinding
    from app.services.endpoint_telemetry import get_endpoint_finding_by_id

    res = get_endpoint_finding_by_id(org_id, finding_id)
    if res is not None:
        c_finding, telemetry = res
        from app.models import NetworkDevice

        row = db.scalar(
            select(NetworkDevice).where(
                NetworkDevice.org_id == org_id,
                (NetworkDevice.id == c_finding.device_id)
                | (NetworkDevice.mac == c_finding.device_id)
                | (NetworkDevice.ip == c_finding.device_id),
            )
        )
        ip_val = (
            row.ip
            if row
            else (
                telemetry.get("ip")
                or (c_finding.device_id if "." in c_finding.device_id else "127.0.0.1")
            )
        )
        host_val = telemetry.get("hostname") or (
            row.hostname if row else c_finding.device_id
        )
        os_val = telemetry.get("os_name") or telemetry.get("os_info")
        f_state = (
            c_finding.finding_state.value
            if hasattr(c_finding.finding_state, "value")
            else str(c_finding.finding_state)
        )

        return RemediationContext(
            finding_id=c_finding.finding_id,
            device_id=c_finding.device_id,
            org_id=org_id,
            source="endpoint",
            hostname=host_val,
            ip=ip_val,
            os=os_val,
            asset_type="endpoint",
            criticality=2,
            internet_facing=False,
            product=c_finding.observed_product,
            version=c_finding.observed_version,
            service_name=c_finding.observed_product,
            port=None,
            cve_id=c_finding.cve_id,
            title=c_finding.title
            or c_finding.summary
            or f"Vulnerability in {c_finding.observed_product}",
            summary=c_finding.summary or c_finding.affected_range_text,
            cvss=float(c_finding.cvss),
            severity=c_finding.severity,
            affected_range=c_finding.affected_range_text,
            fixed_version=c_finding.fixed_version_text,
            in_kev=c_finding.in_kev,
            evidence=f"Endpoint inventory: {c_finding.observed_product} {c_finding.observed_version or ''}".strip(),
            finding_state=f_state,
        )

    # 3. Neither exists: deterministic 404
    raise NotFoundError("Finding not found")


def _guard_offensive(*texts: str | None) -> bool:
    joined = " ".join(t.lower() for t in texts if t)
    return any(m in joined for m in _OFFENSIVE_MARKERS)


def remediate(db: Session, org_id: str, finding_id: str, preferred_kind: str, regenerate: bool) -> RemediationOut:
    rem_ctx = resolve_remediation_context(db, org_id, finding_id)

    # Guard: If no confirmed vulnerability exists, do not generate a false patch
    if rem_ctx.finding_state == "NO_CONFIRMED_VULNERABILITY":
        return RemediationOut(
            refused=True,
            reason="No confirmed vulnerability detected on this component.",
            kind=preferred_kind,
            title=f"No Action Required for {rem_ctx.product or 'component'}",
            summary=f"Component {rem_ctx.product or 'unknown'} has no confirmed CVE to remediate.",
            script="# No defensive patch required — component is verified clean.",
            steps=["Verify component version", "No security updates currently required"],
            estimated_risk_reduction=0.0,
            requires_restart=False,
            disclaimer="Validated: No confirmed CVE found for this software artifact.",
            model="guardrail",
            remediation_state="REMEDIATION_UNAVAILABLE",
            source=rem_ctx.source,
            in_kev=rem_ctx.in_kev,
            context={
                "remediation_state": "REMEDIATION_UNAVAILABLE",
                "finding_state": rem_ctx.finding_state,
                "product": rem_ctx.product,
            },
        )

    # Cache check
    if not regenerate:
        if rem_ctx.source == "network":
            existing = db.scalar(
                select(Remediation)
                .where(Remediation.asset_vulnerability_id == finding_id)
                .order_by(Remediation.created_at.desc())
            )
            if existing is not None and existing.kind == preferred_kind:
                out = _remediation_from_row(existing)
                out.remediation_state = "REMEDIATION_AVAILABLE"
                out.source = rem_ctx.source
                out.in_kev = rem_ctx.in_kev
                return out
        else:
            cached_ep = _ENDPOINT_REMEDIATIONS.get((org_id, finding_id, preferred_kind))
            if cached_ep is not None:
                return cached_ep

    # Clean versions: Never guess or invent version
    safe_version = (
        rem_ctx.version
        if rem_ctx.version and rem_ctx.version != "UNKNOWN_VERSION"
        else "Not available"
    )
    safe_fixed_version = (
        rem_ctx.fixed_version if rem_ctx.fixed_version else "<patched-version>"
    )

    ctx = {
        "asset": {
            "hostname": rem_ctx.hostname,
            "ip": rem_ctx.ip,
            "os": rem_ctx.os,
            "asset_type": rem_ctx.asset_type,
            "zone": rem_ctx.zone,
            "criticality": rem_ctx.criticality,
            "internet_facing": rem_ctx.internet_facing,
        },
        "service": (
            {
                "name": rem_ctx.product or rem_ctx.service_name or "service",
                "version": safe_version,
                "port": rem_ctx.port or ("<port>" if rem_ctx.source == "network" else None),
            }
            if (rem_ctx.product or rem_ctx.port or rem_ctx.service_name)
            else None
        ),
        "vulnerability": {
            "cve_id": rem_ctx.cve_id or "N/A",
            "title": rem_ctx.title or "Vulnerability",
            "cvss": rem_ctx.cvss,
            "severity": rem_ctx.severity,
            "description": rem_ctx.summary,
            "fixed_version": safe_fixed_version,
            "in_kev": rem_ctx.in_kev,
            "finding_state": rem_ctx.finding_state,
        },
        "source": rem_ctx.source,
        "preferred_kind": preferred_kind,
    }

    fallback = _templated_remediation(ctx)
    system, user_json, schema = prompts.build_remediation_messages(ctx)

    is_postgres_hero = (
        (rem_ctx.cve_id or "").endswith("0005") and preferred_kind == "ansible"
    )
    mock_key = "remediate_postgres" if is_postgres_hero else None
    data = generate(system, user_json, mock_key, fallback, schema)

    if data.get("refused"):
        return RemediationOut(
            refused=True,
            reason=data.get("reason") or "Not supported",
            remediation_state="REMEDIATION_UNAVAILABLE",
            source=rem_ctx.source,
            in_kev=rem_ctx.in_kev,
            context=ctx,
        )
    if not data.get("script"):
        data = fallback

    if _guard_offensive(data.get("title"), data.get("summary"), data.get("script")):
        return RemediationOut(
            refused=True,
            reason="Request could not be answered defensively.",
            remediation_state="REMEDIATION_UNAVAILABLE",
            source=rem_ctx.source,
            in_kev=rem_ctx.in_kev,
            context=ctx,
        )

    settings = get_settings()
    risk_reduction = min(max(float(data.get("estimated_risk_reduction") or 0), 0.0), 100.0)

    if rem_ctx.source == "network":
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
        out.context = ctx
        out.remediation_state = "REMEDIATION_AVAILABLE"
        out.source = rem_ctx.source
        out.in_kev = rem_ctx.in_kev
        return out
    else:
        # Endpoint finding: cache in-memory
        out = RemediationOut(
            id=finding_id,
            refused=False,
            kind=data.get("kind", preferred_kind),
            title=data.get("title", f"Defensive Remediation for {rem_ctx.product}"),
            summary=data.get("summary", ""),
            script=data.get("script", ""),
            steps=data.get("steps", []),
            estimated_risk_reduction=risk_reduction,
            requires_restart=bool(data.get("requires_restart", False)),
            disclaimer=data.get("disclaimer")
            or "Generated suggestion — review and test before running in production.",
            reviewed=False,
            model=("mock" if settings.ai_mock else settings.resolved_ai_model),
            context=ctx,
            remediation_state="REMEDIATION_AVAILABLE",
            source=rem_ctx.source,
            in_kev=rem_ctx.in_kev,
        )
        _ENDPOINT_REMEDIATIONS[(org_id, finding_id, preferred_kind)] = out
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
    in_kev = bool(vuln.get("in_kev"))
    fixed_ver = vuln.get("fixed_version")
    has_fixed = bool(fixed_ver and fixed_ver != "<patched-version>")

    kev_header = (
        "# 🚨 Known Exploited Vulnerability — CISA KEV listed (prioritize defensive patch application)\n"
        if in_kev
        else ""
    )
    ver_directive = (
        f"# Fixed version confirmed from advisory: {fixed_ver}\n"
        if has_fixed
        else "# Exact patched version could not be verified from advisory — substitute <patched-version>\n"
    )

    if kind == "shell":
        host_sh = shlex.quote(str(host))
        name_sh = shlex.quote(str(name))
        target_pkg = f"{name_sh}={fixed_ver}" if has_fixed else f"{name_sh}=<patched-version>"
        script = (
            "#!/usr/bin/env bash\n"
            f"# Defensive hardening for {cve} ({vuln_title}) on {host_sh}\n"
            f"{kev_header}"
            f"{ver_directive}"
            "# Review each step before running in production.\n"
            "set -euo pipefail\n\n"
            f"# 1. Apply security update for {name_sh} (pinned to fixed release)\n"
            f"sudo apt-get install --only-upgrade {target_pkg} -y   # or: pip install {name_sh}=={fixed_ver or '<patched-version>'}\n\n"
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
            f"{kev_header}"
            f"{ver_directive}"
            "# Review each command and substitute your resource IDs before running.\n\n"
            f"{access_block}"
            "# 2. Apply pending patches via your managed patch baseline\n"
            "aws ssm send-command --document-name 'AWS-RunPatchBaseline' \\\n"
            f"  --targets {shlex.quote(f'Key=tag:Name,Values={host}')} --parameters 'Operation=Install'\n\n"
            "# 3. Rotate credentials referenced by the workload\n"
            "aws secretsmanager rotate-secret --secret-id <secret-id>\n"
        )
    elif kind == "manual":
        target_ver_str = fixed_ver if has_fixed else "<patched-version>"
        script = (
            f"Manual remediation plan for {cve} ({vuln_title}) on {host}:\n"
            f"{kev_header}"
            f"1. Apply the vendor security patch for {name} (target: {target_ver_str}).\n"
            f"2. Restrict network access to {name} to trusted sources only.\n"
            "3. Rotate any credentials the service uses and enforce least privilege.\n"
            "4. Re-scan the host and verify the finding no longer reproduces.\n"
        )
    else:  # ansible (default)
        def _yaml_kv(key: str, value: str) -> str:
            return yaml.safe_dump(
                {key: value}, default_flow_style=False, default_style='"',
                width=1 << 20, allow_unicode=True,
            ).strip()

        hosts_line = _yaml_kv("hosts", host)
        name_line = _yaml_kv("name", f"Harden {name} on {host}")
        msg_line = _yaml_kv("msg", f"Restrict firewall rules and rotate credentials for {name}")
        task_name_line = _yaml_kv("name", f"Apply security updates for {name}")
        pkg_target = f"{name}={fixed_ver}" if has_fixed else name
        pkg_line = _yaml_kv("name", pkg_target)
        script = (
            "---\n"
            f"# Defensive hardening for {cve} ({vuln_title}) — review before applying\n"
            f"{kev_header}"
            f"{ver_directive}"
            f"- {name_line}\n"
            f"  {hosts_line}\n"
            "  become: true\n"
            "  tasks:\n"
            f"    - {task_name_line}\n"
            "      ansible.builtin.package:\n"
            f"        {pkg_line}\n"
            "        state: present\n"
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
            f"Apply vendor security patches for {name} (target: {fixed_ver or '<patched-version>'})",
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
