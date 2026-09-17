# Drishti v0.1 — LLM API client wrapper | 11-Jul-2026
"""LLM client wrapper. The backend is the ONLY caller of the LLM API.

Provider is selected by AI_PROVIDER: "groq" (default) or "anthropic". Both
paths return parsed JSON or None; the service layer is provider-agnostic.

Respects AI_MOCK (canned fixtures, no network). JSON shape is enforced
server-side via structured outputs (Groq response_format json_schema /
Anthropic output_config json_schema); the fence-strip/json.loads path remains
as a defensive net. Transport retries (429/5xx) are handled by each SDK. Never
raises to the router (AI_INSTRUCTIONS.md §7, ERROR_HANDLING.md §2).
"""
from __future__ import annotations

import json
import logging
import re
import time

from app.config import get_settings

logger = logging.getLogger("drishti")

_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

# in-memory AI call telemetry for GET /api/stats
_AI_STATS: dict[str, object] = {
    "calls": 0,
    "mock_calls": 0,
    "fallbacks": 0,
    "total_latency_ms": 0.0,
}

_client = None


def _get_client():
    """Build the provider client once and reuse it (connection pooling)."""
    global _client
    if _client is None:
        settings = get_settings()
        if settings.ai_provider == "anthropic":
            import anthropic

            _client = anthropic.Anthropic(
                api_key=settings.anthropic_api_key,
                timeout=settings.ai_timeout_seconds,
            )
        elif settings.ai_provider == "nvidia":
            from openai import OpenAI

            _client = OpenAI(
                base_url=settings.nvidia_base_url or "https://integrate.api.nvidia.com/v1",
                api_key=settings.nvidia_api_key,
                timeout=settings.ai_timeout_seconds,
                max_retries=1,
            )
        else:  # groq
            from groq import Groq

            _client = Groq(
                api_key=settings.groq_api_key,
                timeout=settings.ai_timeout_seconds,
                max_retries=1,
            )
    return _client


def _extract_json(text: str) -> dict | None:
    cleaned = _FENCE.sub("", text).strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        return parsed
    # try to locate the first {...} span
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        try:
            parsed = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError:
            return None
        if isinstance(parsed, dict):
            return parsed
    return None


def _call_model(system: str, user_json: str, schema: dict | None = None) -> dict | None:
    """Single LLM call → parsed JSON, or None on parse/API failure.

    Dispatches on AI_PROVIDER. With a schema the provider constrains the
    response to valid JSON of that shape (structured outputs), so the parse net
    almost never has to work.
    """
    settings = get_settings()
    try:
        client = _get_client()
    except Exception as exc:  # SDK import or client init failed
        logger.warning("ai client init failed: %s", exc)
        return None

    if settings.ai_provider == "anthropic":
        return _call_anthropic(client, settings, system, user_json, schema)
    return _call_groq(client, settings, system, user_json, schema)


def _call_anthropic(client, settings, system, user_json, schema) -> dict | None:
    kwargs: dict = {
        "model": settings.resolved_ai_model,
        "max_tokens": settings.ai_max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user_json}],
        # Fast, deterministic JSON tasks — skip thinking for demo latency.
        # (Sonnet 5 defaults to adaptive thinking when the field is omitted.)
        "thinking": {"type": "disabled"},
    }
    if schema is not None:
        kwargs["output_config"] = {"format": {"type": "json_schema", "schema": schema}}

    for attempt in range(2):
        try:
            resp = client.messages.create(**kwargs)
        except Exception as exc:
            logger.warning("ai api call failed (attempt %d): %s", attempt, exc)
            return None
        if resp.stop_reason == "refusal":
            return {"refused": True, "reason": "The model declined this request for safety reasons."}
        if resp.stop_reason == "max_tokens":
            logger.warning("ai response truncated at max_tokens=%d", settings.ai_max_tokens)
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        parsed = _extract_json(text)
        if parsed is not None:
            return parsed
        logger.warning("ai response was not valid JSON (attempt %d)", attempt)
    return None


def _call_groq(client, settings, system, user_json, schema) -> dict | None:
    # Groq is OpenAI-compatible: system + user messages, chat.completions.
    # json_schema mode needs a strict schema (additionalProperties:false, all
    # keys required); our task schemas aren't strict, so use json_object mode
    # and lean on the _extract_json net. Unlike Anthropic's output_config, that
    # mode only guarantees *valid* JSON, not the right KEYS — so we inline the
    # schema into the system prompt to steer the model to the exact shape (and
    # the literal word "JSON", which json_object mode requires in the prompt).
    if schema is not None:
        system = (
            f"{system}\n\nRespond with ONLY a single JSON object — no prose, no "
            "markdown code fences — that conforms exactly to this JSON Schema "
            "(use these exact keys):\n"
            f"{json.dumps(schema)}"
        )
    kwargs: dict = {
        "model": settings.resolved_ai_model,
        "max_tokens": settings.ai_max_tokens,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_json},
        ],
        "response_format": {"type": "json_object"},
    }

    for attempt in range(2):
        try:
            resp = client.chat.completions.create(**kwargs)
        except Exception as exc:
            logger.warning("ai api call failed (attempt %d): %s", attempt, exc)
            return None
        choice = resp.choices[0]
        if choice.finish_reason == "length":
            logger.warning("ai response truncated at max_tokens=%d", settings.ai_max_tokens)
        text = choice.message.content or ""
        parsed = _extract_json(text)
        if parsed is not None:
            return parsed
        logger.warning("ai response was not valid JSON (attempt %d)", attempt)
    return None


def generate(
    system: str, user_json: str, mock_key: str | None, fallback: dict, schema: dict | None = None
) -> dict:
    """Run an AI task. Returns parsed JSON or a templated fallback — never raises.

    In mock mode a None mock_key skips fixtures and uses the context-specific
    templated fallback, so mocked output still reflects the real asset/vuln.
    """
    settings = get_settings()
    start = time.perf_counter()

    if settings.ai_mock:
        result = (_load_mock(mock_key) if mock_key else None) or fallback
        _AI_STATS["mock_calls"] = int(_AI_STATS["mock_calls"]) + 1
    else:
        parsed = _call_model(system, user_json, schema)
        if parsed is None:
            _AI_STATS["fallbacks"] = int(_AI_STATS["fallbacks"]) + 1
        result = parsed if parsed is not None else fallback
        _AI_STATS["calls"] = int(_AI_STATS["calls"]) + 1

    _AI_STATS["total_latency_ms"] = float(_AI_STATS["total_latency_ms"]) + round(
        (time.perf_counter() - start) * 1000, 1
    )
    return result


def _load_mock(mock_key: str) -> dict | None:
    from pathlib import Path

    path = Path(__file__).parent / "mocks" / f"{mock_key}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def ai_stats() -> dict:
    return dict(_AI_STATS)
