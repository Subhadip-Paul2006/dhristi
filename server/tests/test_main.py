# Drishti v0.1 — ASGI middleware hardening tests | 11-Jul-2026
"""ASGI-level request hardening in app/main.py: MaxBodySizeMiddleware (body
size limits that survive a missing Content-Length / chunked body, unlike the
Content-Length-only check in core.deps.reject_oversized) and structured_log's
crash-path logging + request_id threading (TESTING.md conventions).
"""
import json
import types
from pathlib import Path

from app.main import MaxBodySizeMiddleware, structured_log

import pytest

FIXTURE = json.loads(
    (Path(__file__).parent.parent / "app/seed/fixtures/db-prod-01.json").read_text()
)


def test_ingest_rejects_oversized_body_with_no_content_length(client, seed_acme_org, agent_headers):
    """The literal DoS from the finding: chunked/no Content-Length must not
    bypass the size limit the way it bypasses core.deps.reject_oversized."""
    huge = dict(FIXTURE, vulnerabilities=FIXTURE["vulnerabilities"] * 6000)
    body = json.dumps(huge).encode()

    def stream():
        step = 64_000
        for i in range(0, len(body), step):
            yield body[i : i + step]

    resp = client.post("/api/ingest", content=stream(), headers=agent_headers)
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "validation_error"


@pytest.mark.asyncio
async def test_max_body_size_middleware_rejects_before_calling_app():
    called = False

    async def downstream(scope, receive, send):
        nonlocal called
        called = True

    middleware = MaxBodySizeMiddleware(downstream, max_bytes=10)
    chunks = [
        {"type": "http.request", "body": b"a" * 6, "more_body": True},
        {"type": "http.request", "body": b"b" * 6, "more_body": False},
    ]

    async def receive():
        return chunks.pop(0)

    sent = []

    async def send(message):
        sent.append(message)

    await middleware({"type": "http"}, receive, send)

    assert called is False
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413


@pytest.mark.asyncio
async def test_max_body_size_middleware_replays_body_within_limit():
    received = []

    async def downstream(scope, receive, send):
        while True:
            message = await receive()
            received.append(message)
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = MaxBodySizeMiddleware(downstream, max_bytes=100)
    chunks = [
        {"type": "http.request", "body": b"a" * 6, "more_body": True},
        {"type": "http.request", "body": b"b" * 6, "more_body": False},
    ]

    async def receive():
        return chunks.pop(0)

    sent = []

    async def send(message):
        sent.append(message)

    await middleware({"type": "http"}, receive, send)

    assert [m["body"] for m in received] == [b"a" * 6, b"b" * 6]
    assert sent[0]["status"] == 200


@pytest.mark.asyncio
async def test_structured_log_logs_on_crash_with_correlated_request_id(caplog):
    class FakeURL:
        path = "/api/ingest"

    class FakeRequest:
        method = "POST"
        url = FakeURL()
        state = types.SimpleNamespace()

    async def call_next(request):
        raise RuntimeError("boom")

    request = FakeRequest()
    with caplog.at_level("INFO", logger="drishti"):
        try:
            await structured_log(request, call_next)
        except RuntimeError:
            pass

    access_lines = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    assert len(access_lines) == 1
    assert access_lines[0]["status"] == 500
    assert access_lines[0]["method"] == "POST"
    assert access_lines[0]["path"] == "/api/ingest"
    # request_id is threaded onto request.state so core/errors.py's crash
    # handler can log/return the same id instead of minting its own.
    assert request.state.request_id == access_lines[0]["request_id"]
