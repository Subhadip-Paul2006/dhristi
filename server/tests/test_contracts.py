# Drishti v0.1 — API contract tests | 11-Jul-2026
"""Contract tests: ingestion payload ↔ schema, graph payload ↔ React Flow (TESTING.md §3.8)."""
import json
from pathlib import Path

from app.schemas.ingest import IngestPayload

FIXTURE = json.loads(
    (Path(__file__).parent.parent / "app/seed/fixtures/db-prod-01.json").read_text()
)


def test_ingest_payload_schema():
    # the agent's sample payload validates against the server model
    payload = IngestPayload.model_validate(FIXTURE)
    assert payload.host.hostname == "db-prod-01"
    assert payload.vulnerabilities[0].cvss == 8.8


def test_graph_payload_shape(client, user_headers):
    resp = client.get("/api/graph", headers=user_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["nodes"] and body["edges"]
    for node in body["nodes"]:
        assert set(node.keys()) >= {"id", "type", "data", "position"}
        assert "x" in node["position"] and "y" in node["position"]
    for edge in body["edges"]:
        assert set(edge.keys()) >= {"id", "source", "target", "data"}
    node_ids = {n["id"] for n in body["nodes"]}
    for edge in body["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
    assert "INTERNET" in node_ids


def test_openapi_generates(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    assert "/api/graph" in resp.json()["paths"]


def test_dashboard_totals(client, user_headers):
    resp = client.get("/api/dashboard", headers=user_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_exposure_usd"] > 0
    assert len(body["top_paths"]) >= 1
    assert body["open_findings"] > 0


def test_graph_focus_blast_radius(client, user_headers):
    graph = client.get("/api/graph", headers=user_headers).json()
    db_node = next(n for n in graph["nodes"] if n["data"]["label"] == "web-app-01")
    focused = client.get(f"/api/graph?focus={db_node['id']}", headers=user_headers).json()
    assert focused["meta"]["focus"] == db_node["id"]
    assert len(focused["meta"]["blast_radius_ids"]) > 0
