# Drishti v0.1 — live network watch endpoints | 11-Jul-2026
"""Live network watch: the edge agent POSTs observed domains (agent-token auth);
the UI polls the live threat list and requests a defensive block on demand
(user auth). Thin router — logic in services/live.py."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_agent, get_current_org, rate_limit_ai
from app.db import get_db
from app.models import Agent, Organization
from app.schemas.live import (
    AutoScanConfigIn,
    AutoScanConfigOut,
    BlockFixOut,
    CoverageOut,
    CoverageReport,
    DeepScanRangeRequest,
    DeepScanRangeResult,
    DeepScanRequest,
    DeepScanResult,
    DeviceBatch,
    DeviceBatchResponse,
    LiveThreat,
    NetworkDeviceOut,
    ObserveRequest,
    ObserveResponse,
)
from app.schemas.live_threats import NetworkThreat
from app.services import autoscan, live
from app.services import live_threats as netthreats  # module name clashes with the /threats route fn
from app.services.deepscan import service as deepscan

router = APIRouter()


@router.post("/live/observe", response_model=ObserveResponse)
def observe_domain(
    body: ObserveRequest,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> ObserveResponse:
    return live.observe(db, agent.org_id, body.domain, body.source_host)


@router.post("/live/sync_active")
def sync_active_domains(
    body: __import__("app.schemas.live", fromlist=["SyncActiveRequest"]).SyncActiveRequest,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> dict:
    return live.sync_active(db, agent.org_id, body.domains, body.source_host, body.active_apps)


@router.post("/live/check", response_model=ObserveResponse,
             dependencies=[Depends(rate_limit_ai)])
def check_domain(
    body: ObserveRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> ObserveResponse:
    """Manual check from the UI (user-authed) — same real analysis + live node as
    the agent's observe, so a judge can test any URL instantly."""
    return live.observe(db, org.id, body.domain, body.source_host or "manual")


@router.get("/live/threats", response_model=list[LiveThreat])
def live_threats(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[LiveThreat]:
    return live.list_threats(db, org.id)


@router.delete("/live/threats")
def clear_threats(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> dict:
    return {"cleared": live.clear(db, org.id)}


@router.delete("/live/threats/{threat_id}")
@router.post("/live/threats/{threat_id}/resolve")
def resolve_threat(
    threat_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> dict:
    resolved = live.resolve_threat(db, org.id, threat_id)
    return {"resolved": resolved, "threat_id": threat_id}


@router.post("/live/devices", response_model=DeviceBatchResponse)
def observe_devices(
    body: DeviceBatch,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> DeviceBatchResponse:
    return live.observe_devices(db, agent.org_id, body)


@router.get("/live/devices", response_model=list[NetworkDeviceOut])
def list_devices(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[NetworkDeviceOut]:
    return live.list_devices(db, org.id)


@router.post("/live/coverage")
def report_coverage(
    body: CoverageReport,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
) -> dict:
    """Agent-reported coverage: networks known to exist that were NOT swept
    this run (skipped, unreachable, SSIDs seen but not joined)."""
    return {"upserted": live.report_coverage(db, agent.org_id, body)}


@router.get("/live/coverage", response_model=list[CoverageOut])
def network_coverage(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[CoverageOut]:
    """Every network known to exist for this org and whether it has actually
    been inventoried — the seen-vs-covered gap is the point of this endpoint."""
    return live.list_coverage(db, org.id)


@router.get("/live/network-threats", response_model=list[NetworkThreat])
def network_threats(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[NetworkThreat]:
    """Active defensive threat signals derived from the live inventory:
    ARP-spoofing/MITM, rogue devices, exposed risky services, and hosts
    contacting malicious domains. Computed from data we already hold — no
    traffic interception."""
    return netthreats.network_threats(db, org.id)


@router.post("/live/demo-attack", response_model=list[NetworkThreat])
def demo_attack(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> list[NetworkThreat]:
    """Inject clearly-labelled DEMO threats so the detection pipeline can be
    shown live without a second physical device: a rogue host, an ARP-spoof
    pair on the gateway, and a real High-Risk domain analysis. Everything is
    tagged DEMO and removed by DELETE /live/demo-attack."""
    netthreats.inject_demo(db, org.id)
    return netthreats.network_threats(db, org.id)


@router.delete("/live/demo-attack")
def clear_demo_attack(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> dict:
    return {"cleared": netthreats.clear_demo(db, org.id)}


@router.delete("/live/devices")
def clear_devices(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> dict:
    return {"cleared": live.clear_devices(db, org.id)}


@router.post("/live/block/{obs_id}", response_model=BlockFixOut,
             dependencies=[Depends(rate_limit_ai)])
def block_domain(
    obs_id: str,
    domain: str | None = None,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> BlockFixOut:
    return live.block_fix(db, org.id, obs_id, domain_hint=domain)


@router.post("/live/deep-scan", response_model=DeepScanResult,
             dependencies=[Depends(rate_limit_ai)])
def deep_scan(
    body: DeepScanRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> DeepScanResult:
    """Consented, defensive deep scan of a LAN device: real nmap + real CVE
    lookup fed into the existing risk engine. Requires consent=true and refuses
    public IPs (private/RFC1918 only)."""
    return deepscan.deep_scan(db, org.id, body.ip, body.consent)


@router.post("/live/deep-scan-range", response_model=DeepScanRangeResult,
             dependencies=[Depends(rate_limit_ai)])
def deep_scan_range(
    body: DeepScanRangeRequest,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> DeepScanRangeResult:
    """Consented subnet scan of a private/LAN range: real nmap discovery + a
    bounded per-host -sV, all fed into one existing-engine recompute. Requires
    consent=true and refuses public/oversized ranges. Direct Nmap on the local
    subnet — no NAT, routing, port-forwarding, or traffic interception."""
    return deepscan.deep_scan_range(db, org.id, body.cidr, body.consent)


@router.get("/live/autoscan", response_model=AutoScanConfigOut)
def get_autoscan(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> AutoScanConfigOut:
    """Autonomous deep-scan schedule for this org."""
    return autoscan.config_out(db, org.id)


@router.put("/live/autoscan", response_model=AutoScanConfigOut)
def set_autoscan(
    body: AutoScanConfigIn,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> AutoScanConfigOut:
    """Start/stop the autonomous scanner, set its interval, or grant/revoke
    authorization to scan the whole subnet (default: this host only)."""
    cfg = autoscan.update_config(
        db, org.id,
        enabled=body.enabled,
        interval_seconds=body.interval_seconds,
        scan_subnet=body.scan_subnet,
    )
    return autoscan.config_out(db, org.id, cfg)


@router.get("/live/deep-scan/{asset_id}", response_model=DeepScanResult)
def deep_scan_last(
    asset_id: str,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
) -> DeepScanResult:
    """Re-fetch the most recent deep-scan result for a scanned asset."""
    return deepscan.get_last(db, org.id, asset_id)
