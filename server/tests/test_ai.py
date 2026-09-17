# Drishti v0.1 — AI layer mock tests | 11-Jul-2026
"""AI layer (mocked) — schema, guardrail, echo, fallback (TESTING.md §3.7)."""
import shlex

import yaml
from sqlalchemy import select

from app.models import Asset, AssetVulnerability, AttackPath, Vulnerability


def _finding_on(db, org_id, hostname, cve):
    return db.scalar(
        select(AssetVulnerability)
        .join(Asset, AssetVulnerability.asset_id == Asset.id)
        .join(Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id)
        .where(Asset.org_id == org_id, Asset.hostname == hostname, Vulnerability.cve_id == cve)
    )


def test_remediate_returns_schema(client, db_session, seed_acme_org, user_headers):
    finding = _finding_on(db_session, seed_acme_org.id, "db-prod-01", "CVE-2024-0005")
    resp = client.post(
        "/api/ai/remediate",
        json={"finding_id": finding.id, "preferred_kind": "ansible"},
        headers=user_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["refused"] is False
    assert body["reviewed"] is False
    assert body["script"]
    assert body["kind"] == "ansible"
    # persisted
    from app.models import Remediation

    assert db_session.scalar(select(Remediation).where(Remediation.asset_vulnerability_id == finding.id))


def test_remediate_allows_scary_real_cve(client, db_session, seed_acme_org, user_headers):
    # A real CVE whose description reads scary ("remote code execution via a
    # crafted payload that could be exploited") must STILL produce a defensive
    # fix — the input context is never grounds for refusal (only our output is).
    finding = _finding_on(db_session, seed_acme_org.id, "web-app-01", "CVE-2024-0001")
    vuln = db_session.get(Vulnerability, finding.vulnerability_id)
    vuln.title = "Remote code execution via crafted payload"
    vuln.description = "An unauthenticated attacker can exploit this to run code."
    db_session.commit()
    resp = client.post(
        "/api/ai/remediate", json={"finding_id": finding.id}, headers=user_headers
    )
    assert resp.status_code == 200
    assert resp.json()["refused"] is False


def test_impact_echoes_number(client, db_session, seed_acme_org, user_headers):
    top = db_session.scalar(
        select(AttackPath).where(AttackPath.org_id == seed_acme_org.id)
        .order_by(AttackPath.path_risk.desc())
    )
    resp = client.post("/api/ai/impact", json={"path_id": top.id}, headers=user_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert abs(body["impact_usd"] - float(top.impact_usd)) < 1.0
    assert body["narrative"]


def test_predict_returns_schema(client, db_session, seed_acme_org, user_headers):
    jump = db_session.scalar(
        select(Asset).where(Asset.org_id == seed_acme_org.id, Asset.hostname == "jump-01")
    )
    resp = client.post("/api/ai/predict", json={"asset_id": jump.id}, headers=user_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["from_asset"] == "jump-01"
    assert isinstance(body["predictions"], list)


def test_ai_mock_no_network(client, db_session, seed_acme_org, user_headers, monkeypatch):
    # if AI_MOCK is honored, importing anthropic + calling it should never happen.
    import app.services.ai.client as ai_client

    def _boom(*a, **k):
        raise AssertionError("network call attempted under AI_MOCK")

    monkeypatch.setattr(ai_client, "_call_model", _boom)
    top = db_session.scalar(select(AttackPath).where(AttackPath.org_id == seed_acme_org.id))
    resp = client.post("/api/ai/impact", json={"path_id": top.id}, headers=user_headers)
    assert resp.status_code == 200


def test_ai_json_parse_fallback(monkeypatch):
    # a non-JSON model reply → _extract_json returns None → generate uses fallback
    import app.services.ai.client as ai_client
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("AI_MOCK", "false")
    get_settings.cache_clear()
    monkeypatch.setattr(ai_client, "_call_model", lambda s, u, sc=None: None)
    fallback = {"refused": False, "headline": "fallback used"}
    out = ai_client.generate("sys", "{}", "nonexistent_mock", fallback)
    assert out == fallback
    monkeypatch.setenv("AI_MOCK", "true")
    get_settings.cache_clear()


def test_extract_json_rejects_non_dict_top_level():
    # a syntactically valid but non-object JSON payload (list/str/number) must be
    # treated as a parse failure, not returned as a false success (data.get(...)
    # on it would crash every caller in service.py).
    from app.services.ai.client import _extract_json

    assert _extract_json("[1, 2, 3]") is None
    assert _extract_json('"just a string"') is None
    assert _extract_json("42") is None
    assert _extract_json("null") is None
    assert _extract_json('{"a": 1}') == {"a": 1}
    # object embedded in a non-JSON wrapper still recovers via the {...} span scan
    assert _extract_json('here is your answer: {"a": 1} thanks') == {"a": 1}


def test_templated_remediation_sanitizes_shell_and_cloud_cli():
    # a hostname/service name crafted to break out of the single-quoted shell
    # strings the template used to build with raw f-string interpolation.
    from app.services.ai.service import _templated_remediation

    malicious_host = "web01'; touch /tmp/pwned; echo '"
    malicious_name = "svc'; touch /tmp/pwned; echo '"
    for kind in ("shell", "cloud_cli"):
        ctx = {
            "asset": {"hostname": malicious_host, "ip": "10.0.0.1"},
            "service": {"name": malicious_name, "version": "1", "port": 80},
            "vulnerability": {"cve_id": "CVE-2024-9999", "title": "Test vuln"},
            "preferred_kind": kind,
        }
        script = _templated_remediation(ctx)["script"]
        # the malicious value must only ever appear shell-quoted, never as a bare
        # token that could terminate the surrounding quotes.
        assert shlex.quote(malicious_host) in script
        assert shlex.quote(malicious_name) in script
        assert f"'{malicious_host}'" not in script
        assert f"'{malicious_name}'" not in script


def test_templated_remediation_sanitizes_ansible_yaml():
    # a hostname/service name crafted to break out of the plain YAML scalars
    # the ansible template used to build with raw f-string interpolation —
    # this used to let an attacker inject additional YAML keys/tasks.
    from app.services.ai.service import _templated_remediation

    malicious_host = "web01'\nhosts: injected-host\n  become: false"
    malicious_name = "svc: evil"
    ctx = {
        "asset": {"hostname": malicious_host, "ip": "10.0.0.1"},
        "service": {"name": malicious_name, "version": "1", "port": 80},
        "vulnerability": {"cve_id": "CVE-2024-9999", "title": "Test vuln"},
        "preferred_kind": "ansible",
    }
    script = _templated_remediation(ctx)["script"]
    parsed = yaml.safe_load(script)
    assert isinstance(parsed, list) and len(parsed) == 1
    assert parsed[0]["hosts"] == malicious_host
    assert parsed[0]["name"] == f"Harden {malicious_name} on {malicious_host}"


def test_impact_allows_scary_context(client, db_session, seed_acme_org, user_headers):
    # Scary-sounding real path context must still be analyzed, not refused.
    top = db_session.scalar(
        select(AttackPath).where(AttackPath.org_id == seed_acme_org.id)
        .order_by(AttackPath.path_risk.desc())
    )
    top.entry_label = "malware staging point"
    db_session.commit()
    resp = client.post("/api/ai/impact", json={"path_id": top.id}, headers=user_headers)
    assert resp.status_code == 200
    assert resp.json()["refused"] is False


def test_impact_guardrail_refuses_offensive_model_output(client, db_session, seed_acme_org, user_headers, monkeypatch):
    import app.services.ai.service as ai_service

    def _fake_generate(system, user_json, mock_key, fallback, schema=None):
        return {
            "refused": False,
            "impact_usd": 0,
            "headline": "This path opens a reverse shell to the target",
            "narrative": "narrative",
            "drivers": [],
            "highest_leverage_action": "action",
        }

    monkeypatch.setattr(ai_service, "generate", _fake_generate)
    top = db_session.scalar(select(AttackPath).where(AttackPath.org_id == seed_acme_org.id))
    resp = client.post("/api/ai/impact", json={"path_id": top.id}, headers=user_headers)
    assert resp.status_code == 200
    assert resp.json()["refused"] is True


def test_predict_allows_scary_context(client, db_session, seed_acme_org, user_headers):
    # Scary-sounding real asset names must still be analyzed, not refused.
    jump = db_session.scalar(
        select(Asset).where(Asset.org_id == seed_acme_org.id, Asset.hostname == "jump-01")
    )
    neighbor = db_session.scalar(
        select(Asset).where(Asset.org_id == seed_acme_org.id, Asset.hostname == "db-prod-01")
    )
    neighbor.hostname = "malware-drop-01"
    db_session.commit()
    resp = client.post("/api/ai/predict", json={"asset_id": jump.id}, headers=user_headers)
    assert resp.status_code == 200
    assert resp.json()["refused"] is False


def test_predict_guardrail_refuses_offensive_model_output(client, db_session, seed_acme_org, user_headers, monkeypatch):
    import app.services.ai.service as ai_service

    def _fake_generate(system, user_json, mock_key, fallback, schema=None):
        return {
            "refused": False,
            "from_asset": "jump-01",
            "predictions": [
                {"asset": "db-prod-01", "likelihood": 0.5, "reason": "opens a reverse shell", "defensive_action": "patch"}
            ],
        }

    monkeypatch.setattr(ai_service, "generate", _fake_generate)
    jump = db_session.scalar(
        select(Asset).where(Asset.org_id == seed_acme_org.id, Asset.hostname == "jump-01")
    )
    resp = client.post("/api/ai/predict", json={"asset_id": jump.id}, headers=user_headers)
    assert resp.status_code == 200
    assert resp.json()["refused"] is True


def test_remediate_guardrail_refuses_offensive_model_output(client, db_session, seed_acme_org, user_headers, monkeypatch):
    import app.services.ai.service as ai_service

    def _fake_generate(system, user_json, mock_key, fallback, schema=None):
        return {
            "refused": False,
            "kind": "shell",
            "title": "fix",
            "summary": "fix",
            "script": "this script opens a reverse shell for testing",
            "steps": [],
            "estimated_risk_reduction": 10.0,
            "requires_restart": False,
            "disclaimer": "d",
        }

    monkeypatch.setattr(ai_service, "generate", _fake_generate)
    finding = _finding_on(db_session, seed_acme_org.id, "db-prod-01", "CVE-2024-0005")
    resp = client.post(
        "/api/ai/remediate",
        json={"finding_id": finding.id, "preferred_kind": "shell", "regenerate": True},
        headers=user_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["refused"] is True
