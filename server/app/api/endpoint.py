# Drishti v0.1 — Endpoint Agent & Pairing Router | Phase 01
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_current_endpoint_agent, get_current_org
from app.core.errors import BadRequestError, ForbiddenError, NotFoundError
from app.core.security import hash_agent_token
from app.db import get_db
from app.models import Organization
from app.models.base import utcnow
from app.models.endpoint import (
    EndpointAgent,
    EndpointPairingSession,
)
from app.schemas.endpoint import (
    CorrelatedFindingOut,
    EndpointAgentOut,
    EndpointTelemetryOut,
    EndpointTelemetrySubmitRequest,
    EndpointTelemetrySubmitResponse,
    EndpointVulnerabilitiesResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    PairingInitRequest,
    PairingInitResponse,
    PairingStatusRequest,
    PairingStatusResponse,
    PairingSubmitRequest,
    PairingSubmitResponse,
    SourceStatusOut,
)
from app.services import endpoint_telemetry, live

router = APIRouter(prefix="/endpoint", tags=["endpoint"])

# Safe characters avoiding visual confusion (no 0/O, 1/I/L)
PAIRING_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
PAIRING_EXPIRY_MINUTES = 5


def generate_pairing_code() -> str:
    """Generate a clean 8-character dashed pairing code e.g. 'AB7X-92KF'."""
    part1 = "".join(secrets.choice(PAIRING_ALPHABET) for _ in range(4))
    part2 = "".join(secrets.choice(PAIRING_ALPHABET) for _ in range(4))
    return f"{part1}-{part2}"


def normalize_code(raw: str) -> str:
    """Normalize input pairing code: uppercase, trim, ensure single dash."""
    clean = raw.strip().upper().replace(" ", "").replace("-", "")
    if len(clean) == 8:
        return f"{clean[:4]}-{clean[4:]}"
    return clean


def hash_code(code: str) -> str:
    """Deterministic hash of normalized pairing code."""
    canonical = normalize_code(code)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _to_agent_out(agent: EndpointAgent, now: datetime | None = None) -> EndpointAgentOut:
    return EndpointAgentOut(
        id=agent.id,
        org_id=agent.org_id,
        agent_id=agent.agent_id,
        device_id=agent.device_id,
        hostname=agent.hostname,
        os=agent.os,
        os_version=agent.os_version,
        mac=agent.mac,
        current_ip=agent.current_ip,
        agent_version=agent.agent_version,
        status=agent.calculate_status(now),
        paired_at=agent.paired_at,
        registered_at=agent.registered_at,
        last_heartbeat=agent.last_heartbeat,
    )


@router.post("/pairing/init", response_model=PairingInitResponse)
def init_pairing(
    body: PairingInitRequest,
    db: Session = Depends(get_db),
) -> PairingInitResponse:
    """Initialize a short-lived pairing session for a newly launched endpoint agent."""
    code = generate_pairing_code()
    code_h = hash_code(code)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=PAIRING_EXPIRY_MINUTES)

    session = EndpointPairingSession(
        pairing_code_hash=code_h,
        agent_id=body.agent_id,
        device_id=body.device_id,
        hostname=body.hostname,
        os=body.os,
        os_version=body.os_version,
        mac=body.mac,
        current_ip=body.current_ip,
        agent_version=body.agent_version,
        status="WAITING_FOR_PAIR",
        expires_at=expires_at,
    )
    db.add(session)
    db.commit()

    return PairingInitResponse(
        session_id=session.id,
        pairing_code=code,
        expires_at=expires_at,
        poll_interval_seconds=3,
    )


@router.post("/pairing/pair", response_model=PairingSubmitResponse)
def submit_pairing(
    body: PairingSubmitRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> PairingSubmitResponse:
    """Operator enters pairing code on dashboard to verify and register endpoint agent."""
    code_h = hash_code(body.pairing_code)
    now = datetime.now(timezone.utc)

    session = db.scalar(
        select(EndpointPairingSession).where(
            EndpointPairingSession.pairing_code_hash == code_h
        )
    )
    if session is None:
        raise BadRequestError("Invalid pairing code")

    if session.is_expired(now):
        session.status = "EXPIRED"
        db.commit()
        raise BadRequestError("Pairing code has expired. Please restart agent to generate a fresh code.")

    if session.status != "WAITING_FOR_PAIR":
        raise BadRequestError(f"Pairing code is already {session.status.lower()}")

    # Issue cryptographically secure agent token
    raw_token = secrets.token_hex(32)
    token_h = hash_agent_token(raw_token)

    # Register or update EndpointAgent
    agent = db.scalar(
        select(EndpointAgent).where(
            EndpointAgent.org_id == org.id,
            EndpointAgent.agent_id == session.agent_id,
        )
    )
    if agent is None:
        agent = EndpointAgent(
            org_id=org.id,
            agent_id=session.agent_id,
            device_id=session.device_id,
            hostname=session.hostname,
            os=session.os,
            os_version=session.os_version,
            mac=session.mac,
            current_ip=session.current_ip,
            agent_version=session.agent_version,
            status="ONLINE",
            agent_token_hash=token_h,
            paired_at=now,
            registered_at=now,
            last_heartbeat=now,
        )
        db.add(agent)
    else:
        agent.device_id = session.device_id
        agent.hostname = session.hostname
        agent.os = session.os
        agent.os_version = session.os_version
        agent.mac = session.mac or agent.mac
        agent.current_ip = session.current_ip or agent.current_ip
        agent.agent_version = session.agent_version
        agent.status = "ONLINE"
        agent.agent_token_hash = token_h
        agent.paired_at = now
        agent.last_heartbeat = now

    # Update pairing session state
    session.org_id = org.id
    session.status = "PAIRED"
    session.agent_token = raw_token
    session.consumed_at = now
    db.commit()

    live.upsert_device_from_endpoint_agent(db, org.id, agent)

    return PairingSubmitResponse(
        success=True,
        message=f"Endpoint agent on '{agent.hostname}' paired successfully",
        agent=_to_agent_out(agent, now),
    )


@router.post("/pairing/status", response_model=PairingStatusResponse)
def check_pairing_status(
    body: PairingStatusRequest,
    db: Session = Depends(get_db),
) -> PairingStatusResponse:
    """Agent polls this endpoint to detect when the operator enters the pairing code."""
    now = datetime.now(timezone.utc)
    session = db.scalar(
        select(EndpointPairingSession).where(
            EndpointPairingSession.id == body.session_id,
            EndpointPairingSession.agent_id == body.agent_id,
        )
    )
    if session is None:
        raise NotFoundError("Pairing session not found")

    if session.status == "WAITING_FOR_PAIR":
        if session.is_expired(now):
            session.status = "EXPIRED"
            db.commit()
            return PairingStatusResponse(status="EXPIRED")
        return PairingStatusResponse(status="WAITING_FOR_PAIR")

    if session.status == "PAIRED":
        # One-time secret release: clear token from database immediately
        token = session.agent_token
        org_id = session.org_id
        session.status = "CONSUMED"
        session.agent_token = None
        db.commit()
        return PairingStatusResponse(
            status="PAIRED",
            agent_token=token,
            org_id=org_id,
        )

    return PairingStatusResponse(status=session.status)


@router.post("/heartbeat", response_model=HeartbeatResponse)
def agent_heartbeat(
    body: HeartbeatRequest,
    agent: EndpointAgent = Depends(get_current_endpoint_agent),
    db: Session = Depends(get_db),
) -> HeartbeatResponse:
    """Authenticated endpoint agent reports periodic health and presence."""
    if agent.agent_id != body.agent_id:
        raise ForbiddenError("Agent identity mismatch")

    now = utcnow()
    agent.last_heartbeat = now
    agent.status = "ONLINE"
    if body.agent_version:
        agent.agent_version = body.agent_version
    if body.device_id and body.device_id != agent.device_id:
        agent.device_id = body.device_id

    db.commit()

    live.upsert_device_from_endpoint_agent(db, agent.org_id, agent)

    return HeartbeatResponse(
        status="ACK",
        server_time=now,
        derived_status=agent.calculate_status(now),
    )


@router.get("/agents", response_model=List[EndpointAgentOut])
def list_endpoint_agents(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> List[EndpointAgentOut]:
    """List all registered endpoint agents in the organization with derived live status."""
    now = datetime.now(timezone.utc)
    agents = db.scalars(
        select(EndpointAgent)
        .where(EndpointAgent.org_id == org.id)
        .order_by(EndpointAgent.created_at.desc())
    ).all()
    return [_to_agent_out(a, now) for a in agents]


@router.get("/agents/{agent_id}", response_model=EndpointAgentOut)
def get_endpoint_agent(
    agent_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> EndpointAgentOut:
    """Retrieve metadata and live derived status for a specific endpoint agent."""
    now = datetime.now(timezone.utc)
    agent = db.scalar(
        select(EndpointAgent).where(
            EndpointAgent.org_id == org.id,
            EndpointAgent.agent_id == agent_id,
        )
    )
    if agent is None:
        raise NotFoundError(f"Endpoint agent '{agent_id}' not found")
    return _to_agent_out(agent, now)


@router.post("/telemetry", response_model=EndpointTelemetrySubmitResponse)
def submit_endpoint_telemetry(
    body: EndpointTelemetrySubmitRequest,
    agent: EndpointAgent = Depends(get_current_endpoint_agent),
    db: Session = Depends(get_db),
) -> EndpointTelemetrySubmitResponse:
    """Authenticated endpoint agent submits periodic telemetry batch."""
    if agent.agent_id != body.agent_id:
        raise ForbiddenError("Agent identity mismatch")
    if agent.device_id != body.device_id:
        raise ForbiddenError("Device identity mismatch")

    now = utcnow()
    agent.last_heartbeat = now
    agent.status = "ONLINE"
    db.commit()

    live.upsert_device_from_endpoint_agent(db, agent.org_id, agent)

    res = endpoint_telemetry.record_telemetry(
        org_id=agent.org_id,
        agent_id=agent.agent_id,
        device_id=agent.device_id,
        payload=body,
    )

    return EndpointTelemetrySubmitResponse(
        success=True,
        message="Telemetry ingested successfully",
        accepted_at=res["accepted_at"],
        processes_count=res["processes_count"],
        software_count=res["software_count"],
        services_count=res["services_count"],
        ports_count=res["ports_count"],
    )


@router.get("/telemetry/{device_id}", response_model=EndpointTelemetryOut)
def get_endpoint_device_telemetry(
    device_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> EndpointTelemetryOut:
    """Retrieve isolated telemetry for a specific device (by device_id, agent_id, or mapped network device)."""
    # 1. Direct device_id check in endpoint_telemetry store
    telem = endpoint_telemetry.get_telemetry_for_device(org.id, device_id)
    if telem:
        return telem

    # 2. Check if device_id maps to an EndpointAgent (e.g. agent_id or network device id)
    agent = db.scalar(
        select(EndpointAgent).where(
            EndpointAgent.org_id == org.id,
            (EndpointAgent.device_id == device_id)
            | (EndpointAgent.agent_id == device_id)
            | (EndpointAgent.id == device_id)
        )
    )
    if agent:
        telem = endpoint_telemetry.get_telemetry_for_device(org.id, agent.device_id)
        if telem:
            return telem

    # If no agent or telemetry exists for this device, return empty record with source='none'
    return EndpointTelemetryOut(
        device_id=device_id,
        agent_id="",
        source="none",
        is_stale=True,
        is_software_stale=True,
    )


@router.get("/vulnerabilities/{device_id}", response_model=EndpointVulnerabilitiesResponse)
def get_endpoint_device_vulnerabilities(
    device_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> EndpointVulnerabilitiesResponse:
    """Retrieve isolated vulnerability intelligence findings for a specific device."""
    target_device_id = device_id
    # Check if device_id maps to an EndpointAgent
    agent = db.scalar(
        select(EndpointAgent).where(
            EndpointAgent.org_id == org.id,
            (EndpointAgent.device_id == device_id)
            | (EndpointAgent.agent_id == device_id)
            | (EndpointAgent.id == device_id),
        )
    )
    if agent:
        target_device_id = agent.device_id

    findings = endpoint_telemetry.get_vulnerability_findings_for_device(org.id, target_device_id)

    findings_out = [
        CorrelatedFindingOut(
            finding_id=f.finding_id,
            device_id=f.device_id,
            org_id=f.org_id,
            finding_state=f.finding_state.value if hasattr(f.finding_state, "value") else str(f.finding_state),
            observed_product=f.observed_product,
            evidence_source=f.evidence_source,
            evidence_type=f.evidence_type,
            observed_vendor=f.observed_vendor,
            observed_version=f.observed_version,
            cve_id=f.cve_id,
            title=f.title,
            summary=f.summary,
            cvss=f.cvss,
            severity=f.severity,
            in_kev=f.in_kev,
            kev_date_added=f.kev_date_added,
            ghsa_ids=f.ghsa_ids,
            affected_range_text=f.affected_range_text,
            fixed_version_text=f.fixed_version_text,
            intel_sources=f.intel_sources,
            source_freshness=f.source_freshness,
            source_status_reason=f.source_status_reason,
            source_details=f.source_details,
            observed_at=f.observed_at,
        )
        for f in findings
    ]

    vuln_cnt = sum(1 for f in findings_out if f.finding_state in ("VULNERABLE", "KNOWN_EXPLOITED"))
    kev_cnt = sum(1 for f in findings_out if f.in_kev)
    pot_cnt = sum(1 for f in findings_out if f.finding_state == "POTENTIAL_MATCH")

    correlator = endpoint_telemetry.get_correlator()
    source_statuses = [
        SourceStatusOut(
            source_name=s.source_name,
            available=s.available,
            last_sync=s.last_sync,
            error_reason=s.error_reason,
            is_stale=s.is_stale,
        )
        for s in correlator.cache.all_source_statuses()
    ]

    return EndpointVulnerabilitiesResponse(
        device_id=device_id,
        findings=findings_out,
        total_findings=len(findings_out),
        vulnerable_count=vuln_cnt,
        known_exploited_count=kev_cnt,
        potential_match_count=pot_cnt,
        source_statuses=source_statuses,
    )


