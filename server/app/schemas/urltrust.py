# Drishti v0.1 — URL trust analyzer schemas | 11-Jul-2026
"""Request/response contracts for the URL Trust Analyzer.

Mirrors the frontend types in web/src/api/types.ts exactly. Every field here is
either really computed from the URL/its response or clearly marked unavailable
(unknown / not_configured / unreachable). Nothing is fabricated.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

SignalStatus = Literal["pass", "warn", "fail", "unknown", "not_configured", "unreachable"]
Band = Literal["Trusted", "Caution", "High Risk"]


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class SignalOut(BaseModel):
    key: str
    label: str
    status: SignalStatus
    detail: str
    weight: float
    # true only for pass/warn/fail — i.e. this signal counted toward the score
    counted: bool


class TlsOut(BaseModel):
    valid: bool | None = None
    issuer: str | None = None
    expires: str | None = None


class WebsiteOut(BaseModel):
    scheme: str
    host: str
    https: bool
    tls: TlsOut
    domain_age_days: int | None = None
    registrar: str | None = None
    http_status: int | None = None
    redirect_chain: list[str] = []
    redirects_offsite: bool | None = None


class SafeBrowsingOut(BaseModel):
    configured: bool
    verdict: Literal["clean", "flagged"] | None = None
    threats: list[str] | None = None
    error: str | None = None


class VirusTotalOut(BaseModel):
    configured: bool
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    reputation: int | None = None
    error: str | None = None


class ProvidersOut(BaseModel):
    safe_browsing: SafeBrowsingOut
    virustotal: VirusTotalOut


class UrlAnalysisResult(BaseModel):
    url: str
    final_url: str | None = None
    score: float
    band: Band
    evaluated_count: int
    signals: list[SignalOut]
    website: WebsiteOut
    providers: ProvidersOut
    ai_summary: str | None = None
    generated_at: datetime
    disclaimer: str


class HistoryItem(BaseModel):
    id: str
    url: str
    score: float
    band: Band
    created_at: datetime
