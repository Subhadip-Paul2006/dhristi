# Drishti v0.1 — edge agent filtering tests | 11-Jul-2026
"""Edge agent filtering (the Edge-Filtering pillar, ARCHITECTURE.md §3.5)."""
import argparse
import importlib.util
from pathlib import Path

import pytest

_AGENT_PATH = Path(__file__).parent.parent.parent / "agent" / "drishti_agent.py"
_spec = importlib.util.spec_from_file_location("drishti_agent", _AGENT_PATH)
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


def _raw():
    return {
        "agent_id": "a1",
        "org_slug": "acme-retail",
        "collected_at": "2026-07-06T10:00:00Z",
        "host": {
            "hostname": "h1",
            "ip": "10.0.0.5",
            "os": "Ubuntu",
            "asset_type": "server",
            "secret_field": "should be dropped",
        },
        "services": [{"port": 22, "protocol": "tcp", "name": "ssh", "version": "8.9", "junk": 1}],
        "vulnerabilities": [
            {"cve_id": "C1", "title": "low one", "cvss": 3.0, "severity": "low", "exploitability": 0.1},
            {"cve_id": "C2", "title": "high one", "cvss": 8.0, "severity": "high", "exploitability": 0.7},
        ],
        "connectivity": [{"to_ip": "10.0.0.6", "via": "network", "note": "same subnet"}],
    }


def test_filter_drops_below_severity_floor():
    out = agent.apply_filters(_raw(), severity_floor="high", batch_size=100)
    sevs = [v["severity"] for v in out["vulnerabilities"]]
    assert sevs == ["high"]  # low dropped


def test_filter_whitelists_fields():
    out = agent.apply_filters(_raw(), severity_floor="low", batch_size=100)
    assert "secret_field" not in out["host"]
    assert "junk" not in out["services"][0]
    # schema fields preserved
    assert out["host"]["hostname"] == "h1"
    assert out["services"][0]["port"] == 22


def test_filter_caps_batch_size():
    raw = _raw()
    raw["vulnerabilities"] = raw["vulnerabilities"] * 50
    out = agent.apply_filters(raw, severity_floor="low", batch_size=5)
    assert len(out["vulnerabilities"]) <= 5


def test_filter_keeps_connectivity():
    out = agent.apply_filters(_raw(), severity_floor="low", batch_size=100)
    assert out["connectivity"][0]["to_ip"] == "10.0.0.6"


def _run_once_args(**overrides):
    base = dict(
        fixture=None,
        agent_id="a1",
        org_slug="acme-retail",
        severity_floor="low",
        batch_size=100,
        server="http://localhost:8000",
        token="t",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_run_once_rejects_non_dict_response(monkeypatch):
    monkeypatch.setattr(agent, "post_payload", lambda *a, **k: ["not", "a", "dict"])
    with pytest.raises(SystemExit, match="unexpected response shape"):
        agent.run_once(_run_once_args())


def test_main_loop_survives_unexpected_exception(monkeypatch):
    calls = []

    def fake_run_once(args):
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("boom")
        raise KeyboardInterrupt

    monkeypatch.setattr(agent, "run_once", fake_run_once)
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        agent.sys, "argv", ["drishti_agent.py", "--interval", "0", "--token", "t"]
    )
    with pytest.raises(KeyboardInterrupt):
        agent.main()
    assert len(calls) == 2  # loop kept going after the unexpected ValueError


def test_main_requires_token_when_none_given(monkeypatch):
    monkeypatch.delenv("DRISHTI_AGENT_TOKEN", raising=False)
    monkeypatch.setattr(agent.sys, "argv", ["drishti_agent.py", "--once"])
    with pytest.raises(SystemExit):
        agent.main()


def test_main_reads_token_from_env_when_flag_omitted(monkeypatch):
    monkeypatch.setenv("DRISHTI_AGENT_TOKEN", "env-token")
    captured = {}

    def fake_run_once(args):
        captured["token"] = args.token

    monkeypatch.setattr(agent, "run_once", fake_run_once)
    monkeypatch.setattr(agent.sys, "argv", ["drishti_agent.py", "--once"])
    agent.main()
    assert captured["token"] == "env-token"
