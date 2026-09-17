# Drishti v0.1 — live network watch tests | 11-Jul-2026
"""Live watch: agent observes a domain → real-shaped verdict → dedup node →
threat list → defensive block. The analyzer is stubbed so tests never hit the
network; the verdict shape is exactly what the real analyzer returns."""
from app.models.base import utcnow
from app.schemas.urltrust import UrlAnalysisResult


def _fake_result(url: str, band: str, score: float, malicious: int = 0) -> UrlAnalysisResult:
    return UrlAnalysisResult(
        url=url,
        final_url=url,
        score=score,
        band=band,
        evaluated_count=6,
        signals=[
            {
                "key": "virustotal",
                "label": "VirusTotal",
                "status": "fail" if malicious else "pass",
                "detail": f"{malicious} security vendors flagged this URL as malicious."
                if malicious
                else "No security vendors flagged this URL.",
                "weight": 4.0,
                "counted": True,
            }
        ],
        website={"scheme": "https", "host": url, "https": True, "tls": {"valid": True},
                 "domain_age_days": 30, "registrar": None, "http_status": 200,
                 "redirect_chain": [], "redirects_offsite": False},
        providers={
            "safe_browsing": {"configured": True, "verdict": "flagged" if malicious else "clean"},
            "virustotal": {"configured": True, "malicious": malicious},
        },
        ai_summary=None,
        generated_at=utcnow(),
        disclaimer="",
    )


def _agent_headers():
    # the acme seed registers an agent with this well-known demo token
    return {"authorization": "Bearer agent-demo-token"}


def test_observe_scores_and_lists_threat(client, seed_acme_org, user_headers, monkeypatch):
    import app.services.live as live_svc

    monkeypatch.setattr(
        live_svc.analyzer, "analyze",
        lambda db, org_id, url: _fake_result(url, "High Risk", 20.0, malicious=1),
    )
    resp = client.post(
        "/api/live/observe",
        json={"domain": "evil-example.test", "source_host": "judge-laptop"},
        headers=_agent_headers(),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["band"] == "High Risk"
    assert body["is_threat"] is True

    # appears in the live threat list with its concrete reason
    threats = client.get("/api/live/threats", headers=user_headers).json()
    match = [t for t in threats if t["domain"] == "evil-example.test"]
    assert match and match[0]["band"] == "High Risk"
    assert any("flagged" in r for r in match[0]["reasons"])


def test_observe_dedupes_and_counts_hits(client, seed_acme_org, user_headers, monkeypatch):
    import app.services.live as live_svc

    monkeypatch.setattr(
        live_svc.analyzer, "analyze",
        lambda db, org_id, url: _fake_result(url, "Trusted", 100.0),
    )
    for _ in range(3):
        client.post("/api/live/observe", json={"domain": "repeat.test"}, headers=_agent_headers())
    threats = client.get("/api/live/threats", headers=user_headers).json()
    row = [t for t in threats if t["domain"] == "repeat.test"][0]
    assert row["hit_count"] == 3  # deduped, not three rows


def test_block_fix_returns_commands(client, seed_acme_org, user_headers, monkeypatch):
    import app.services.live as live_svc

    monkeypatch.setattr(
        live_svc.analyzer, "analyze",
        lambda db, org_id, url: _fake_result(url, "High Risk", 15.0, malicious=2),
    )
    obs = client.post(
        "/api/live/observe", json={"domain": "bad.test"}, headers=_agent_headers()
    ).json()
    # AI_MOCK=true in tests → templated block (no network), still real commands
    resp = client.post(f"/api/live/block/{obs['id']}", headers=user_headers)
    assert resp.status_code == 200, resp.text
    fix = resp.json()
    assert fix["refused"] is False
    assert fix["domain"] == "bad.test"
    platforms = {c["platform"] for c in fix["commands"]}
    assert "hosts" in platforms
    assert any("bad.test" in c["command"] for c in fix["commands"])


def test_device_discovery_upsert_dedup_and_flags(client, seed_acme_org, user_headers):
    batch = {
        "devices": [
            {"ip": "192.168.1.1", "mac": "04:d9:f5:95:b8:38"},
            {"ip": "192.168.1.40", "mac": "1e:30:70:16:c5:40"},
            # duplicate MAC (e.g. link-local) must not blow the unique constraint
            {"ip": "169.254.1.5", "mac": "1e:30:70:16:c5:40"},
        ],
        "self_mac": "1e:30:70:16:c5:40",
        "gateway_ip": "192.168.1.1",
    }
    r = client.post("/api/live/devices", json=batch, headers=_agent_headers())
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 2  # deduped by MAC

    devices = client.get("/api/live/devices", headers=user_headers).json()
    assert len(devices) == 2
    gw = [d for d in devices if d["ip"] == "192.168.1.1"][0]
    me = [d for d in devices if d["mac"] == "1e:30:70:16:c5:40"][0]
    assert gw["is_gateway"] is True
    assert me["is_self"] is True
    # locally-administered MAC is flagged as a private/randomized device
    assert "Private" in (me["vendor"] or "")

    # a second sweep without the gateway marks it offline → the live view hides
    # it (row is kept, not deleted)
    client.post(
        "/api/live/devices",
        json={"devices": [{"ip": "192.168.1.40", "mac": "1e:30:70:16:c5:40"}]},
        headers=_agent_headers(),
    )
    devices = client.get("/api/live/devices", headers=user_headers).json()
    assert all(d["ip"] != "192.168.1.1" for d in devices)

    # it reappears as soon as a sweep sees it again (reconnect case)
    client.post("/api/live/devices", json=batch, headers=_agent_headers())
    devices = client.get("/api/live/devices", headers=user_headers).json()
    gw = [d for d in devices if d["ip"] == "192.168.1.1"][0]
    assert gw["online"] is True


def test_observe_rejects_bare_hostname(client, seed_acme_org, monkeypatch):
    import app.services.live as live_svc

    # a single-label / local name must be ignored, not analyzed
    called = {"n": 0}

    def _boom(*a, **k):
        called["n"] += 1
        return _fake_result("x", "Trusted", 100.0)

    monkeypatch.setattr(live_svc.analyzer, "analyze", _boom)
    resp = client.post("/api/live/observe", json={"domain": "localhost"}, headers=_agent_headers())
    assert resp.status_code == 404
    assert called["n"] == 0
