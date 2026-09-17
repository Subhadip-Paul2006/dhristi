# Drishti v0.1 — plain-language trust summary | 11-Jul-2026
"""Optional plain-language trust summary.

Reuses the EXISTING AI client + guardrail and honors AI_MOCK. It summarizes ONLY
the real computed signals passed to it — it is never asked to invent facts. In
mock mode (mock_key=None) `generate` returns the templated fallback below, which
is built entirely from the actual band + top signal reasons.
"""
from __future__ import annotations

from app.services.ai import prompts
from app.services.ai.client import generate
from app.services.urltrust.types import FAIL, PASS, WARN, Signal

DISCLAIMER = (
    "Automated assessment, not a guarantee. Signals reflect only what could be "
    "evaluated at analysis time."
)


def build_summary(url: str, score: float, band: str, evaluated_count: int, signals: list[Signal]) -> str:
    concerns = [
        {"label": s.label, "detail": s.detail}
        for s in signals
        if s.status in (WARN, FAIL)
    ]
    positives = [s.label for s in signals if s.status == PASS]

    ctx = {
        "url": url,
        "band": band,
        "score": score,
        "evaluated_count": evaluated_count,
        "concerns": concerns[:5],
        "positives": positives[:6],
    }
    # Fast, deterministic signal-based summary (0ms latency, zero API rate-limit churn)
    return _templated_summary(ctx)


def _templated_summary(ctx: dict) -> str:
    band = ctx["band"]
    score = ctx["score"]
    n = ctx["evaluated_count"]
    concerns = [c["label"] for c in ctx["concerns"]]
    top = ", ".join(concerns[:3])

    if band == "Trusted":
        base = (
            f"This site scores {score:.0f}/100 across {n} evaluated checks and shows no "
            f"major red flags"
        )
        base += f" (notable concern: {top})." if concerns else "."
        base += " Automated checks can't catch everything, but nothing here stands out as dangerous."
        return base
    if band == "Caution":
        return (
            f"Treat this site with caution — it scores {score:.0f}/100 over {n} checks. "
            f"Concerns worth noting: {top or 'mixed signals'}. Double-check the exact web "
            "address and avoid entering passwords or payment details unless you are sure it is genuine."
        )
    return (
        f"This site looks high-risk, scoring {score:.0f}/100 over {n} checks. "
        f"Serious concerns: {top or 'multiple failed safety checks'}. Do not enter passwords, "
        "payment information, or personal details, and avoid downloading anything from it."
    )
