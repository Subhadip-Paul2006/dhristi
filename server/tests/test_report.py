# Drishti v0.1 — network intelligence report tests | 11-Jul-2026
"""Report endpoints: CVE aggregation, risk distribution, ML analysis, AI summary."""


def test_cve_report_aggregates_and_sorts(client, seed_acme_org, user_headers):
    resp = client.get("/api/report/cves", headers=user_headers)
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert len(rows) > 0
    # sorted by CVSS descending
    cvsses = [r["cvss"] for r in rows]
    assert cvsses == sorted(cvsses, reverse=True)
    # each row carries its affected hosts and a matching count
    for r in rows:
        assert r["affected_count"] == len(r["affected"])
        assert r["affected_count"] >= 1


def test_distribution_bands_sum_to_total(client, seed_acme_org, user_headers):
    resp = client.get("/api/report/distribution", headers=user_headers)
    assert resp.status_code == 200, resp.text
    d = resp.json()
    assert d["total_assets"] > 0
    assert sum(b["count"] for b in d["bands"]) == d["total_assets"]
    assert {b["band"] for b in d["bands"]} == {"critical", "high", "medium", "safe"}
    assert 0.0 <= d["average_risk"] <= 100.0


def test_ml_analysis_returns_anomalies_and_segments(client, seed_acme_org, user_headers):
    resp = client.get("/api/report/ml", headers=user_headers)
    assert resp.status_code == 200, resp.text
    m = resp.json()
    # the acme seed has ≥4 assets and scikit-learn is installed
    assert m["available"] is True
    # segments partition the assets; each has a label and members
    assert len(m["segments"]) >= 1
    for s in m["segments"]:
        assert s["label"] in ("HIGH", "MEDIUM", "LOW")
        assert len(s["members"]) >= 1
    # anomalies are sorted most-anomalous (lowest score) first
    scores = [a["anomaly_score"] for a in m["anomalies"]]
    assert scores == sorted(scores)


def test_hardening_deltas_are_real_and_reduce_risk(client, seed_acme_org, user_headers):
    resp = client.get("/api/report/hardening", headers=user_headers)
    assert resp.status_code == 200, resp.text
    nodes = resp.json()
    assert len(nodes) > 0
    for n in nodes:
        # projected score must be a genuine reduction, not invented
        assert n["projected_score"] <= n["current_score"]
        assert 0.0 <= n["reduction_pct"] <= 100.0
        assert len(n["actions"]) >= 1
        for a in n["actions"]:
            assert a["kind"] in ("CLOSE_PORT", "PATCH", "VLAN_SEGMENT", "ISOLATE_CONNECTION")
            assert a["risk_reduction_pct"] >= 0.0


def test_network_summary_returns_narrative_in_mock(client, seed_acme_org, user_headers):
    # AI_MOCK=true in tests → templated fallback, never a network call
    resp = client.post("/api/report/summary", headers=user_headers)
    assert resp.status_code == 200, resp.text
    s = resp.json()
    assert s["refused"] is False
    assert s["headline"]
    assert s["narrative"]
    assert len(s["top_risks"]) >= 1
    assert len(s["priority_actions"]) >= 1
