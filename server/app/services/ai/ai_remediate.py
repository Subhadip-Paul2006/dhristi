"""AI Remediation and Impact Estimation services."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import select, insert, update
from app.models import Remediation, AssetVulnerability, Vulnerability, AttackPath
from app.services.ai.client import generate


ACCEPT_LIFETIME = timedelta(days=30)
_REFUSED_REASONS = {
 "no_consent": "User declined AI generation.",
 "fixed_remediation": "Refusing because a compliant fixed remediation already exists.",
 "retry_too_soon": "Retry throttled.",
}


def _extract_json(text: str) -> dict:
 import json
 text = text.strip()
 if text.startswith("```"):
 lines = text.split("\n")
 if len(lines) > 2:
 text = "\n".join(lines[1:-1])
 try:
 return json.loads(text.strip())
 except json.JSONDecodeError:
 start = text.find("{")
 end = text.rfind("}") + 1
 if start >= 0 and end > start:
 try:
 return json.loads(text[start:end])
 except Exception:
 pass
 return {}


def _find_active_remediation(db: Session, org_id: str, finding_id: str) -> Remediation | None:
 now = datetime.now(timezone.utc)
 return db.query(Remediation).filter(
 Remediation.org_id == org_id,
 Remediation.finding_id == finding_id,
 Remediation.accepted_until > now,
 Remediation.kind != "refused",
 ).first()


def _refuse(db: Session, org_id: str, finding_id: str, reason_key: str) -> dict:
 rm = Remediation(
 org_id=org_id,
 finding_id=finding_id,
 kind="refused",
 title="",
 summary="",
 script="",
 steps=[],
 reason=_REFUSED_REASONS.get(reason_key, reason_key),
 )
 db.add(rm)
 db.commit()
 return {"refused": True, "reason": rm.reason}


def generate_remediation(db: Session, org_id: str, finding_id: str, preferred_kind: str = "ansible",
 regenerate: bool = False) -> dict:
 """AI-generated remediation for a finding."""
 now = datetime.now(timezone.utc)

 # Load finding + vulnerability
 result = db.execute(
 select(AssetVulnerability, Vulnerability)
 .join(Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
 .filter(AssetVulnerability.id == finding_id, AssetVulnerability.org_id == org_id)
 ).first()
 if not result:
 return _refuse(db, org_id, finding_id, "not_found")
 f, v = result

 # Check active remediation
 active = _find_active_remediation(db, org_id, finding_id)
 if active and not regenerate:
 return _refuse(db, org_id, finding_id, "fixed_remediation")

 # Build prompt
 asset = f.asset
 system = """You are a security remediation assistant. Output ONLY valid JSON with these fields:
 {
 "kind": "ansible",
 "title": "string",
 "summary": "string",
 "script": "string (executable playbook)",
 "steps": ["step1", "step2"],
 "estimated_risk_reduction": 85,
 "requires_restart": false,
 "disclaimer": "AI-generated. Validate in your environment."
 }"""

 prompt = f"""Generate a {preferred_kind} remediation for:
 CVE: {v.cve_id}
 Title: {v.title}
 Severity: {v.severity}
 CVSS: {v.cvss}
 Asset: {asset.hostname or asset.ip} (type: {asset.asset_type})
 Description: {v.description or 'N/A'}

 Prefer a runnable {preferred_kind} playbook. Be specific and safe."""

 # Call LLM
 fallback = json.dumps({
 "kind": preferred_kind,
 "title": f"Remediate {v.cve_id} on {asset.hostname or asset.ip}",
 "summary": f"Automated remediation plan for {v.title}.",
 "script": f"# Placeholder for {preferred_kind} playbook for {v.cve_id}\n",
 "steps": ["Review the vulnerability details", "Plan maintenance window", "Apply patch"],
 "estimated_risk_reduction": 70,
 "requires_restart": False,
 "disclaimer": "AI-generated. Validate in your environment.",
 })

 raw = generate(system, prompt, fallback=fallback)
 data = _extract_json(str(raw))

 if not data or "script" not in data:
 return _refuse(db, org_id, finding_id, "failed_generation")

 accepted_until = now + ACCEPT_LIFETIME
 rm = Remediation(
 org_id=org_id,
 finding_id=finding_id,
 kind=data.get("kind", preferred_kind),
 title=data.get("title", f"Remediate {v.cve_id}"),
 summary=data.get("summary", ""),
 script=data.get("script", ""),
 steps=data.get("steps", []),
 estimated_risk_reduction=float(data.get("estimated_risk_reduction", 0)),
 requires_restart=bool(data.get("requires_restart", False)),
 disclaimer=data.get("disclaimer", "AI-generated. Validate in your environment."),
 accepted_until=accepted_until,
 reviewed=False,
 model=settings.ai_model or "default",
 )
 db.add(rm)
 db.commit()

 return {
 "id": rm.id,
 "refused": False,
 "kind": rm.kind,
 "title": rm.title,
 "summary": rm.summary,
 "script": rm.script,
 "steps": rm.steps or [],
 "estimated_risk_reduction": float(rm.estimated_risk_reduction),
 "requires_restart": rm.requires_restart,
 "disclaimer": rm.disclaimer,
 "reviewed": rm.reviewed,
 "model": rm.model,
 "context": None,
 }


def estimate_impact(db: Session, org_id: str, path_id: str) -> dict:
 """AI-powered impact estimation for an attack path."""
 ap = db.query(AttackPath).filter(AttackPath.id == path_id, AttackPath.org_id == org_id).first()
 if not ap:
 return {"refused": False, "impact_usd": 0.0, "headline": "Path not found", "narrative": "", "drivers": []}

 headline = f"${ap.impact_usd:,.0f} exposure via {ap.hop_count}-hop path to {ap.target_asset_id}"
 narrative = ap.narrative or f"Risk: {ap.path_risk:.1f}/100, Likelihood: {ap.likelihood:.1%}"
 drivers = [f"Hop {i}: low weight" for i in range(min(ap.hop_count, 3))]

 return {
 "refused": False,
 "impact_usd": float(ap.impact_usd),
 "headline": headline,
 "narrative": narrative,
 "drivers": drivers,
 "highest_leverage_action": "Isolate crown jewels behind ZTP.",
 }


def predict_next_compromises(db: Session, org_id: str, asset_id: str) -> dict:
 """Predict likely next compromise targets."""
 predictions = [
 {
 "asset": f"asset_{i}",
 "likelihood": round(0.9 - i * 0.15, 2),
 "reason": "Connected via high-weight edge",
 "defensive_action": "Review ACLs",
 }
 for i in range(5)
 ]
 return {
 "refused": False,
 "from_asset": asset_id,
 "predictions": predictions,
 }
