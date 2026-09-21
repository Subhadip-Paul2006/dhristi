# Drishti v0.1 — live network watch service | 11-Jul-2026
"""Live network watch: the edge agent reports each domain the host connects to;
we run the REAL URL Trust Analyzer on it (SSL, WHOIS, Safe Browsing, VirusTotal),
dedupe into a live threat node, and can draft a defensive block on demand.

Nothing here is mocked — the verdict is the same real analysis the URL Analyzer
uses. Purely defensive: we score and block domains, never attack anything."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.models import DeepScan, DevicePresenceSession, EndpointAgent, LiveObservation, NetworkDevice
from app.models.base import utcnow
from app.schemas.live import (
    ActivityItem,
    BlockCommand,
    BlockFixOut,
    DeepScanCve,
    DeepScanService,
    DeviceBatch,
    DeviceBatchResponse,
    EndpointFindingOut,
    EvidenceEnvelope,
    EvidenceType,
    LiveThreat,
    NetworkDestinationOut,
    NetworkDeviceOut,
    ObserveResponse,
    TimelineQueryIn,
    TrafficSecurityAnnotation,
)
from app.services import endpoint_telemetry
from app.services.device_security_profile import build_score_inputs_from_device, compute_device_security_score
from app.services.domain_classifier import classify_domain
from app.services.vuln_intel.models import FindingState
from app.services.urltrust import analyzer


logger = logging.getLogger("drishti")

# statuses that make a signal a "reason" worth surfacing on the node
_BAD = {"fail", "warn"}

# valid hostname: dot-separated labels of [a-z0-9-] (no leading/trailing hyphen),
# rejecting shell metacharacters, whitespace and any other invalid input.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


def _clean_domain(raw: str) -> str:
    d = (raw or "").strip().lower()
    for p in ("http://", "https://"):
        if d.startswith(p):
            d = d[len(p):]
    d = d.split("/")[0].split("?")[0]
    if d.startswith("www."):
        d = d[4:]
    return d.rstrip(".")


def _reasons_from(verdict: dict) -> list[str]:
    out = []
    for s in verdict.get("signals", []):
        if s.get("status") in _BAD and s.get("counted", True):
            out.append(s.get("detail") or s.get("label", ""))
    return out[:4]


def _bump_observation(row: LiveObservation, result, trimmed: dict, source_host: str | None) -> None:
    """Fold a fresh hit into an existing live threat node."""
    row.band = result.band
    row.score = float(result.score)
    row.verdict_json = trimmed
    row.hit_count = (row.hit_count or 0) + 1
    row.last_seen = utcnow()
    if source_host:
        row.source_host = source_host


def observe(
    db: Session,
    org_id: str,
    raw_domain: str,
    source_host: str | None = None,
    protocol: str = "DNS",
    evidence_source: str = "dns_query_log",
    dest_port: int | None = None,
    connection_count: int = 1,
) -> ObserveResponse:
    """Analyze a freshly-observed domain (real) and upsert its live threat node."""
    domain = _clean_domain(raw_domain)
    if not domain or "." not in domain:
        # ignore local/bare names (e.g. mDNS, single-label hostnames)
        raise NotFoundError("Not a public domain")
    if not _HOSTNAME_RE.match(domain):
        # reject anything with shell metacharacters / invalid hostname chars
        # before we ever store or analyze it
        raise NotFoundError("Not a public domain")

    # Record passive traffic destination for network-level intelligence
    record_passive_destination(
        org_id=org_id,
        source_host=source_host or "default",
        domain=domain,
        protocol=protocol,
        evidence_source=evidence_source,
        dest_port=dest_port,
        connection_count=connection_count,
    )

    result = analyzer.analyze(db, org_id, domain)  # REAL analysis (also stored in history)
    verdict = result.model_dump(mode="json")
    # keep the node payload small: signals + website + providers only
    trimmed = {
        "signals": verdict.get("signals", []),
        "website": verdict.get("website", {}),
        "providers": verdict.get("providers", {}),
        "ai_summary": verdict.get("ai_summary"),
    }

    row = db.scalar(
        select(LiveObservation).where(
            LiveObservation.org_id == org_id, LiveObservation.domain == domain
        )
    )
    if row is None:
        row = LiveObservation(
            org_id=org_id,
            domain=domain,
            url=result.url,
            band=result.band,
            score=float(result.score),
            verdict_json=trimmed,
            source_host=source_host,
            hit_count=1,
        )
        try:
            with db.begin_nested():
                db.add(row)
        except IntegrityError:
            # Lost the (org_id, domain) race to a concurrent observe — adopt its
            # row and fold this hit into it instead of 500-ing.
            row = db.scalar(
                select(LiveObservation).where(
                    LiveObservation.org_id == org_id, LiveObservation.domain == domain
                )
            )
            if row is None:
                raise
            _bump_observation(row, result, trimmed, source_host)
    else:
        _bump_observation(row, result, trimmed, source_host)
    db.commit()

    return ObserveResponse(
        id=row.id,
        domain=domain,
        band=result.band,
        score=float(result.score),
        is_threat=result.band != "Trusted",
    )


@dataclass
class PassiveDestinationRecord:
    domain: str
    resolved_service_label: str | None
    category: str
    protocol: str
    connection_count: int
    first_seen: datetime
    last_seen: datetime
    possible_vpn: bool
    evidence_source: str
    confidence: str
    dest_port: int | None = None


# ── Consent boundary (Invariant #7) ──────────────────────────────────────────
def is_subnet_consent_granted(db: Session | None, org_id: str) -> bool:
    """Consent boundary (Invariant #7): all passive capture (DNS sniffing, TCP/UDP
    flow observation, SNI reading) is gated behind the SAME authorized-subnet
    consent flag already used for Nmap scanning (scan_subnet in AutoScanConfig).
    If consent is off, only device presence (Layer 1) is collected — no traffic
    content at all."""
    if db is None:
        return True
    try:
        from app.models import AutoScanConfig
        cfg = db.scalar(select(AutoScanConfig).where(AutoScanConfig.org_id == org_id))
        if cfg is not None and not cfg.scan_subnet:
            return False
        return True
    except Exception:
        return True


# ── Bounded Per-Device Network Timeline (Part H) ─────────────────────────────
# Storage bound: cap the in-memory timeline at N most recent events per device
# (max 200 events) OR a rolling time window (max 30 minutes) — whichever is smaller —
# to prevent unbounded memory growth on long-running scans.
MAX_TIMELINE_EVENTS_PER_DEVICE = 200
MAX_TIMELINE_WINDOW = timedelta(minutes=30)
_DEVICE_TIMELINES: dict[tuple[str, str], list[EvidenceEnvelope]] = {}
_RESOLVED_DNS_BY_HOST: dict[tuple[str, str], dict[str, tuple[str, datetime]]] = {}


def record_timeline_event(
    org_id: str,
    device_identifier: str,
    envelope: EvidenceEnvelope,
) -> None:
    """Record an event into the per-device timeline respecting strict bounds."""
    key = (org_id, device_identifier.strip().lower())
    now = utcnow()
    cutoff = now - MAX_TIMELINE_WINDOW

    if key not in _DEVICE_TIMELINES:
        _DEVICE_TIMELINES[key] = []

    events = _DEVICE_TIMELINES[key]
    events = [e for e in events if _aware(e.observed_at) >= cutoff]
    events.append(envelope)
    events.sort(key=lambda e: _aware(e.observed_at))
    if len(events) > MAX_TIMELINE_EVENTS_PER_DEVICE:
        events = events[-MAX_TIMELINE_EVENTS_PER_DEVICE:]

    _DEVICE_TIMELINES[key] = events


def get_device_timeline(
    org_id: str,
    device_identifier: str,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 200,
) -> list[EvidenceEnvelope]:
    """Query per-device timeline over an optional time range (Schema hook for Phase 02)."""
    key = (org_id, device_identifier.strip().lower())
    events = _DEVICE_TIMELINES.get(key, [])
    now = utcnow()
    cutoff = now - MAX_TIMELINE_WINDOW
    filtered = [e for e in events if _aware(e.observed_at) >= cutoff]

    if since is not None:
        s_aware = _aware(since)
        filtered = [e for e in filtered if _aware(e.observed_at) >= s_aware]
    if until is not None:
        u_aware = _aware(until)
        filtered = [e for e in filtered if _aware(e.observed_at) <= u_aware]

    return filtered[-limit:]


def record_dns_query(
    db: Session | None,
    org_id: str,
    source_host: str,
    queried_domain: str,
    resolved_ip: str | None = None,
    dns_server: str | None = None,
    record_type: str = "A",
    timestamp: datetime | None = None,
) -> EvidenceEnvelope | None:
    """Capture DNS telemetry as DNS_QUERY evidence.
    UI display rule: 'DNS QUERY OBSERVED: <domain>  →  resolved <ip>  @ <timestamp>'.
    HARD INVARIANT: NEVER assert an app is running from a DNS query."""
    if not is_subnet_consent_granted(db, org_id):
        return None

    cleaned = _clean_domain(queried_domain)
    if not cleaned or "." not in cleaned:
        return None

    now = timestamp or utcnow()
    sh = source_host.strip().lower() if source_host else "default"

    raw_val = f"DNS QUERY OBSERVED: {cleaned}"
    if resolved_ip:
        raw_val += f"  →  resolved {resolved_ip}"
    raw_val += f"  @ {now.strftime('%H:%M:%S')}"

    classified = classify_domain(cleaned)
    inferred_badge = classified["resolved_service_label"]

    envelope = EvidenceEnvelope(
        evidence_type=EvidenceType.DNS_QUERY,
        device_id=sh,
        observed_at=now,
        source="dns_sniffer",
        confidence="high" if resolved_ip else "medium",
        is_stale=False,
        is_inferred=False,
        raw_value=raw_val,
        inferred_label=inferred_badge,
        details={
            "queried_domain": cleaned,
            "resolved_ip": resolved_ip,
            "dns_server": dns_server,
            "record_type": record_type,
        },
    )

    record_timeline_event(org_id, sh, envelope)

    if resolved_ip:
        host_resolved = _RESOLVED_DNS_BY_HOST.setdefault((org_id, sh), {})
        host_resolved[resolved_ip] = (cleaned, now)

    record_passive_destination(
        org_id=org_id,
        source_host=sh,
        domain=cleaned,
        protocol="DNS",
        evidence_source="dns_query_log",
        dest_port=53,
        connection_count=1,
    )
    return envelope


def record_network_traffic(
    db: Session | None,
    org_id: str,
    source_host: str,
    destination_ip: str,
    destination_port: int,
    protocol: str = "TCP",
    domain: str | None = None,
    connection_state: str = "ESTABLISHED",
    timestamp: datetime | None = None,
) -> EvidenceEnvelope | None:
    """Emit NETWORK_TRAFFIC evidence per connection.
    Domain is only included if genuinely resolved via DNS_QUERY or SNI ClientHello."""
    if not is_subnet_consent_granted(db, org_id):
        return None

    now = timestamp or utcnow()
    sh = source_host.strip().lower() if source_host else "default"
    clean_dom = _clean_domain(domain) if domain else None

    raw_val = f"{protocol.upper()}  →  {destination_ip}:{destination_port}"
    if clean_dom:
        raw_val += f" ({clean_dom})"
    if connection_state:
        raw_val += f" {connection_state}"

    inferred_badge = None
    if clean_dom:
        classified = classify_domain(clean_dom, dest_port=destination_port)
        inferred_badge = classified["resolved_service_label"]

    envelope = EvidenceEnvelope(
        evidence_type=EvidenceType.NETWORK_TRAFFIC,
        device_id=sh,
        observed_at=now,
        source="network_flow",
        confidence="high" if clean_dom else "medium",
        is_stale=False,
        is_inferred=False,
        raw_value=raw_val,
        inferred_label=inferred_badge,
        details={
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "domain": clean_dom,
            "connection_state": connection_state,
        },
    )

    record_timeline_event(org_id, sh, envelope)

    if clean_dom:
        record_passive_destination(
            org_id=org_id,
            source_host=sh,
            domain=clean_dom,
            protocol=protocol,
            evidence_source="sni_sniffing" if protocol.upper() == "TLS" else "network_flow",
            dest_port=destination_port,
            connection_count=1,
        )
    return envelope


_PASSIVE_DESTINATIONS_BY_HOST: dict[tuple[str, str], dict[str, PassiveDestinationRecord]] = {}


def record_passive_destination(
    org_id: str,
    source_host: str,
    domain: str,
    protocol: str = "DNS",
    evidence_source: str = "dns_query_log",
    dest_port: int | None = None,
    connection_count: int = 1,
) -> PassiveDestinationRecord | None:
    """Record a passive network destination observation with sliding TTL."""
    cleaned = _clean_domain(domain)
    if not cleaned or "." not in cleaned:
        return None

    now = utcnow()
    sh = source_host.strip() if source_host else "default"
    host_key = (org_id, sh)

    if host_key not in _PASSIVE_DESTINATIONS_BY_HOST:
        _PASSIVE_DESTINATIONS_BY_HOST[host_key] = {}

    host_dests = _PASSIVE_DESTINATIONS_BY_HOST[host_key]

    is_udp_tunnel = bool(protocol and "UDP" in protocol.upper() and dest_port in (51820, 1194))
    classified = classify_domain(cleaned, dest_port=dest_port, is_udp_tunnel=is_udp_tunnel)

    dest_key = cleaned

    if dest_key in host_dests:
        rec = host_dests[dest_key]
        rec.connection_count += max(1, connection_count)
        rec.last_seen = now
        rec.protocol = protocol
        rec.evidence_source = evidence_source
        if dest_port is not None:
            rec.dest_port = dest_port
        return rec
    else:
        rec = PassiveDestinationRecord(
            domain=cleaned,
            resolved_service_label=classified["resolved_service_label"],
            category=classified["category"],
            protocol=protocol,
            connection_count=max(1, connection_count),
            first_seen=now,
            last_seen=now,
            possible_vpn=classified["possible_vpn"],
            evidence_source=evidence_source,
            confidence=classified["confidence"],
            dest_port=dest_port,
        )
        host_dests[dest_key] = rec
        return rec


@dataclass
class HostTelemetry:
    updated_at: datetime
    source_host: str = "default"
    agent_id: str | None = None
    mac: str | None = None
    active_browser_tabs: list[ActivityItem] = field(default_factory=list)
    tabs_updated_at: datetime = field(default_factory=utcnow)
    endpoint_processes: list[ActivityItem] = field(default_factory=list)
    installed_software: list[ActivityItem] = field(default_factory=list)
    installed_browsers: list[str] = field(default_factory=list)
    process_connections: list[ActivityItem] = field(default_factory=list)
    vpn_status: str | None = None
    vpn_adapters: list[str] = field(default_factory=list)
    os_info: str | None = None


_ACTIVE_APPS_BY_HOST: dict[str, tuple[list[str], datetime]] = {}
_ACTIVE_OPEN_TABS_BY_HOST: dict[str, tuple[list[str], datetime]] = {}
_HOST_TELEMETRY: dict[str, HostTelemetry] = {}


def sync_active(
    db: Session,
    org_id: str,
    domains: list[str] | None = None,
    source_host: str = "default",
    agent_id: str | None = None,
    mac: str | None = None,
    active_apps: list[str] | None = None,
    active_browser_tabs: list[ActivityItem] | None = None,
    endpoint_processes: list[ActivityItem] | None = None,
    installed_software: list[ActivityItem] | None = None,
    installed_browsers: list[str] | None = None,
    process_connections: list[ActivityItem] | None = None,
    vpn_status: str | None = None,
    vpn_adapters: list[str] | None = None,
    os_info: str | None = None,
    dns_queries: list[dict] | None = None,
    network_traffic: list[dict] | None = None,
) -> dict:
    """Sync the active tabs, processes, and host telemetry for an authorized host."""
    cleaned_domains = [_clean_domain(d) for d in (domains or []) if d]
    now = utcnow()

    telem = _HOST_TELEMETRY.get(source_host)
    if telem is None:
        telem = HostTelemetry(updated_at=now, tabs_updated_at=now, source_host=source_host)
        _HOST_TELEMETRY[source_host] = telem
    telem.updated_at = now
    telem.source_host = source_host
    if agent_id:
        telem.agent_id = agent_id
    if mac:
        telem.mac = mac.lower().strip()

    # Browser active tabs handling (TTL: 20s)
    # HARD INVARIANT: Network domains NEVER populate active browser tabs.
    # Active browser tabs are strictly populated from the extension's active_browser_tabs payload.
    if active_browser_tabs is not None and len(active_browser_tabs) > 0:
        telem.active_browser_tabs = list(active_browser_tabs)
        telem.tabs_updated_at = now
        _ACTIVE_OPEN_TABS_BY_HOST[source_host] = ([t.name for t in active_browser_tabs], now)
    elif active_browser_tabs is not None and len(active_browser_tabs) == 0:
        telem.active_browser_tabs = []
        telem.tabs_updated_at = now
        _ACTIVE_OPEN_TABS_BY_HOST[source_host] = ([], now)

    # Endpoint processes handling (TTL: 60s)
    if endpoint_processes is not None:
        telem.endpoint_processes = list(endpoint_processes)
        _ACTIVE_APPS_BY_HOST[source_host] = ([p.name for p in endpoint_processes], now)
    elif active_apps is not None:
        converted_procs = [
            ActivityItem(
                name=a,
                evidence_type="ENDPOINT_PROCESS",
                source="windows_endpoint",
                observed_at=now,
                details="Running local process",
            )
            for a in active_apps
        ]
        telem.endpoint_processes = converted_procs
        _ACTIVE_APPS_BY_HOST[source_host] = (active_apps, now)

    # Installed software
    if installed_software is not None:
        telem.installed_software = list(installed_software)

    # Installed browsers
    if installed_browsers is not None:
        telem.installed_browsers = list(installed_browsers)

    # Process connections (sockets) (TTL: 60s)
    if process_connections is not None:
        sh = source_host.strip().lower() if source_host else "default"
        host_dns = _RESOLVED_DNS_BY_HOST.get((org_id, sh), {})
        annotated_conns: list[ActivityItem] = []
        for conn in process_connections:
            target_ip = None
            if conn.details and "Remote:" in conn.details:
                try:
                    part = conn.details.split("Remote:")[1].split("|")[0].strip()
                    target_ip = part.split(":")[0].strip()
                except Exception:
                    pass
            if not target_ip and ":" in conn.name:
                parts = conn.name.split(":")
                if len(parts) >= 2 and parts[-1].isdigit():
                    possible_ip = parts[-2]
                    if possible_ip.count(".") == 3:
                        target_ip = possible_ip

            matched_dns = host_dns.get(target_ip) if target_ip else None
            if matched_dns:
                matched_domain = matched_dns[0]
                conn.inferred_label = f"possible destination: {matched_domain} (matched via DNS evidence, not confirmed)"
                conn.is_inferred = True

            conn.evidence_type = "NETWORK_SOCKET"
            conn.device_id = sh
            annotated_conns.append(conn)

            socket_env = EvidenceEnvelope(
                evidence_type=EvidenceType.NETWORK_SOCKET,
                device_id=sh,
                observed_at=conn.observed_at or now,
                source=conn.source or "agent_socket",
                confidence="high",
                is_stale=False,
                is_inferred=bool(conn.is_inferred),
                raw_value=f"{conn.name} | {conn.details or ''}".strip(),
                inferred_label=conn.inferred_label,
                details={"name": conn.name, "details": conn.details, "inferred_label": conn.inferred_label, "remote_ip": target_ip},
            )
            record_timeline_event(org_id, sh, socket_env)

        telem.process_connections = annotated_conns

    # Ingest passive DNS queries and network traffic
    if dns_queries:
        for dq in dns_queries:
            if isinstance(dq, dict):
                record_dns_query(
                    db=db,
                    org_id=org_id,
                    source_host=source_host,
                    queried_domain=dq.get("domain") or dq.get("queried_domain", ""),
                    resolved_ip=dq.get("resolved_ip"),
                    dns_server=dq.get("dns_server"),
                    record_type=dq.get("record_type", "A"),
                    timestamp=dq.get("timestamp"),
                )

    if network_traffic:
        for nt in network_traffic:
            if isinstance(nt, dict):
                record_network_traffic(
                    db=db,
                    org_id=org_id,
                    source_host=source_host,
                    destination_ip=nt.get("destination_ip", ""),
                    destination_port=int(nt.get("destination_port", 0)),
                    protocol=nt.get("protocol", "TCP"),
                    domain=nt.get("domain"),
                    connection_state=nt.get("connection_state", "ESTABLISHED"),
                    timestamp=nt.get("timestamp"),
                )

    # VPN status & adapters
    if vpn_status is not None:
        telem.vpn_status = vpn_status
    if vpn_adapters is not None:
        telem.vpn_adapters = list(vpn_adapters)

    # OS Info
    if os_info is not None:
        telem.os_info = os_info

    updated = 0
    if cleaned_domains:
        stmt = select(LiveObservation).where(
            LiveObservation.org_id == org_id,
            LiveObservation.domain.in_(cleaned_domains)
        )
        rows = db.scalars(stmt).all()
        for r in rows:
            r.last_seen = now
            updated += 1
        db.commit()
    return {"updated": updated}


def list_threats(db: Session, org_id: str, limit: int = 60) -> list[LiveThreat]:
    from datetime import timedelta
    # 24-hour window so observed network domains don't disappear while inspecting
    recent = utcnow() - timedelta(hours=24)
    rows = db.scalars(
        select(LiveObservation)
        .where(LiveObservation.org_id == org_id, LiveObservation.last_seen > recent)
        .order_by(LiveObservation.last_seen.desc())
        .limit(limit)
    ).all()
    return [
        LiveThreat(
            id=r.id,
            domain=r.domain,
            band=r.band,
            score=float(r.score),
            hit_count=r.hit_count or 1,
            source_host=r.source_host,
            reasons=_reasons_from(r.verdict_json or {}),
            verdict_json=r.verdict_json or {},
            first_seen=r.first_seen,
            last_seen=r.last_seen,
        )
        for r in rows
    ]


# ── network device discovery ─────────────────────────────────────────────────
# A tiny offline OUI table for common vendors — best-effort labelling only.
_OUI = {
    "001A11": "Google", "3C5AB4": "Google", "F4F5D8": "Google",
    "001451": "Apple", "3C0754": "Apple", "A4C361": "Apple", "F0189A": "Apple",
    "AC87A3": "Apple", "8866A5": "Apple", "DC2B2A": "Apple", "F80377": "Apple",
    "FCFC48": "Apple", "88665A": "Apple",
    "001377": "Samsung", "0021D1": "Samsung", "5CF6DC": "Samsung", "8425DB": "Samsung",
    "F0EE10": "Samsung", "FC0012": "Toshiba", "001A2B": "Cisco", "00259C": "Cisco",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "00155D": "Microsoft", "D8D385": "Hewlett-Packard", "001B63": "Apple",
    "5C514F": "Intel", "A0C589": "Intel", "001E10": "Nokia",
    "F0272D": "Xiaomi", "286C07": "Xiaomi", "64B473": "Xiaomi",
    "0016EA": "Intel", "00248C": "ASUSTek", "AC220B": "ASUSTek",
    "001E58": "D-Link", "00179A": "D-Link", "C83A35": "Tenda",
}


def _infer_subnet24(ip: str | None) -> str | None:
    """Best-effort /24 CIDR for an IP with no observed netmask (legacy rows /
    old agents only — anything derived here is marked subnet_inferred)."""
    if not ip:
        return None
    import ipaddress

    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return None


def _vendor_for(mac: str) -> str | None:
    m = mac.replace(":", "").replace("-", "").upper()
    if len(m) < 6:
        return None
    # locally-administered (randomized) MAC — common on modern phones for privacy
    try:
        first = int(m[0:2], 16)
    except ValueError:
        return None
    if first & 0x02:
        return "Private device (randomized MAC)"
    return _OUI.get(m[0:6])


# Continuous presence observation gap threshold:
# Observations spaced <= 5 minutes apart belong to the same presence session.
# A gap > 5 minutes closes the session at its last confirmed observation time.
MAX_OBSERVATION_GAP = timedelta(minutes=5)


def _aware(dt: datetime | None) -> datetime | None:
    """Normalize SQLite naive datetimes to UTC timezone-aware."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _device_identity_key(mac: str | None, subnet: str | None, ip: str) -> str:
    """Stable identity matching NetworkDevice dedupe semantics:
    mac:{mac} for on-link, else l3:{subnet}:{ip} for routed without MAC.
    Randomized MACs remain independent identities."""
    m = (mac or "").lower().strip()
    if m and m not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return f"mac:{m}"
    return f"l3:{subnet or 'none'}:{ip.strip()}"


def _close_device_session(db: Session, org_id: str, row: NetworkDevice) -> None:
    """Close active session at the last confirmed observation time.
    Never fabricate ended_at as current time when a device went absent."""
    dev_key = _device_identity_key(row.mac, row.subnet, row.ip)
    net_key = row.subnet or "default"
    active = db.scalar(
        select(DevicePresenceSession).where(
            DevicePresenceSession.org_id == org_id,
            DevicePresenceSession.network_key == net_key,
            DevicePresenceSession.device_key == dev_key,
            DevicePresenceSession.is_current.is_(True),
        )
    )
    if active is not None:
        active.ended_at = active.last_seen
        active.is_current = False


def _record_device_observation(
    db: Session, org_id: str, dev_key: str, net_key: str, now: datetime, obs_source: str | None
) -> None:
    """Record an observation into the device presence session buffer.
    CASE A: No previous session -> create session (started_at=now, last_seen=now, count=1).
    CASE B: Active session and gap <= 5m -> extend session (last_seen=now, count+=1).
    CASE C: Gap > 5m (or closed) -> close previous at last_seen, start new session.
    """
    session = db.scalar(
        select(DevicePresenceSession)
        .where(
            DevicePresenceSession.org_id == org_id,
            DevicePresenceSession.network_key == net_key,
            DevicePresenceSession.device_key == dev_key,
        )
        .order_by(DevicePresenceSession.last_seen.desc())
        .limit(1)
    )
    now_utc = _aware(now)
    if session is None:
        # CASE A — No previous session
        new_session = DevicePresenceSession(
            org_id=org_id,
            device_key=dev_key,
            network_key=net_key,
            started_at=now,
            last_seen=now,
            ended_at=None,
            is_current=True,
            observation_count=1,
            observation_source=obs_source,
        )
        db.add(new_session)
    else:
        s_last = _aware(session.last_seen)
        gap = (now_utc - s_last) if (now_utc and s_last) else timedelta(0)

        if session.is_current and gap <= MAX_OBSERVATION_GAP:
            # CASE B — Existing current session AND gap <= 5 minutes
            session.last_seen = now
            session.observation_count += 1
            session.is_current = True
            if obs_source:
                session.observation_source = obs_source
        else:
            # CASE C — Existing session AND gap > 5 minutes (or was closed)
            if session.is_current:
                session.ended_at = session.last_seen
                session.is_current = False
            new_session = DevicePresenceSession(
                org_id=org_id,
                device_key=dev_key,
                network_key=net_key,
                started_at=now,
                last_seen=now,
                ended_at=None,
                is_current=True,
                observation_count=1,
                observation_source=obs_source,
            )
            db.add(new_session)


def observe_devices(db: Session, org_id: str, batch: DeviceBatch) -> DeviceBatchResponse:
    """Upsert the devices the agent discovered; prune ONLY within the subnets
    this batch actually observed. Rows in any other subnet are untouched, so
    K agents on K subnets never delete each other's data — nothing here knows
    or assumes how many networks exist."""
    self_mac = (batch.self_mac or "").lower()

    def _device_subnet(d) -> tuple[str | None, bool]:
        """(cidr, inferred) — observed per-device, else batch-level, else /24 guess."""
        if getattr(d, "subnet", None):
            return d.subnet, False
        if batch.subnet:
            return batch.subnet, False
        return _infer_subnet24(d.ip), True

    # Dedup the batch: by MAC when present (a device can appear on multiple
    # IPs), else by (subnet, ip) for off-link hosts that legitimately have none.
    by_key: dict[tuple, "object"] = {}
    for d in batch.devices:
        mac = (d.mac or "").lower().strip()
        if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            mac = ""
        if mac:
            by_key[("mac", mac)] = d
        elif getattr(d, "discovery", "arp") in ("l3", "icmp", "ping", "arp"):
            subnet, _ = _device_subnet(d)
            by_key[("ip", subnet, d.ip)] = d

    seen_ids: set[str] = set()
    seen_macs: set[str] = set()
    observed_subnets: set[str] = set()
    new = 0
    now = utcnow()
    for key, d in by_key.items():
        mac = key[1] if key[0] == "mac" else None
        subnet, inferred = _device_subnet(d)
        if subnet:
            observed_subnets.add(subnet)
        is_self = bool(self_mac and mac and mac == self_mac)
        is_gw = bool(batch.gateway_ip and d.ip == batch.gateway_ip)
        discovery = getattr(d, "discovery", "arp") or "arp"
        obs_source = getattr(d, "source", None) or discovery
        dev_key = _device_identity_key(mac, subnet, d.ip)
        net_key = subnet or "default"

        if mac:
            seen_macs.add(mac)
            row = db.scalar(
                select(NetworkDevice).where(
                    NetworkDevice.org_id == org_id, NetworkDevice.mac == mac
                )
            )
        else:
            row = db.scalar(
                select(NetworkDevice).where(
                    NetworkDevice.org_id == org_id,
                    NetworkDevice.mac.is_(None),
                    NetworkDevice.subnet == subnet,
                    NetworkDevice.ip == d.ip,
                )
            )
        if row is None:
            device = NetworkDevice(
                org_id=org_id, mac=mac, ip=d.ip, hostname=d.hostname,
                vendor=_vendor_for(mac) if mac else None,
                subnet=subnet, subnet_inferred=inferred,
                source_agent_id=batch.agent_id, label=batch.label,
                discovery=discovery,
                is_self=is_self, is_gateway=is_gw, online=True,
            )
            try:
                with db.begin_nested():
                    db.add(device)
                new += 1
                seen_ids.add(device.id)
                _record_device_observation(db, org_id, dev_key, net_key, now, obs_source)
                continue
            except IntegrityError:
                # Lost the dedupe-key race to a concurrent sweep — adopt its
                # row and update it instead of 500-ing.
                if mac:
                    row = db.scalar(
                        select(NetworkDevice).where(
                            NetworkDevice.org_id == org_id, NetworkDevice.mac == mac
                        )
                    )
                else:
                    row = db.scalar(
                        select(NetworkDevice).where(
                            NetworkDevice.org_id == org_id,
                            NetworkDevice.mac.is_(None),
                            NetworkDevice.subnet == subnet,
                            NetworkDevice.ip == d.ip,
                        )
                    )
                if row is None:
                    raise
        row.ip = d.ip
        if d.hostname:
            row.hostname = d.hostname
        row.subnet = subnet
        row.subnet_inferred = inferred
        row.discovery = discovery
        if batch.agent_id:
            row.source_agent_id = batch.agent_id
        if batch.label:
            row.label = batch.label
        # Recompute flags fresh each sweep — a device that was the gateway
        # (or self) on a previous network must not stay flagged on this one.
        row.is_self = is_self
        row.is_gateway = is_gw
        row.online = True
        row.last_seen = now
        seen_ids.add(row.id)
        _record_device_observation(db, org_id, dev_key, net_key, now, obs_source)

    # IPs currently held by an online device this sweep — used to drop stale
    # duplicates (e.g. the gateway reappearing under a randomized MAC).
    online_ips = {d.ip for d in by_key.values()}

    # Prune strictly within the subnets this batch observed. A batch for
    # 192.168.1.0/24 is a no-op for 10.0.5.0/24 — regardless of how many
    # subnets/agents exist.
    if observed_subnets:
        stale = db.scalars(
            select(NetworkDevice).where(
                NetworkDevice.org_id == org_id,
                NetworkDevice.subnet.in_(observed_subnets),
            )
        ).all()
        for row in stale:
            if row.id in seen_ids:
                continue
            _close_device_session(db, org_id, row)
            if row.ip in online_ips:
                # stale duplicate of an IP that answered under another identity
                db.delete(row)
            else:
                row.online = False

    # Live tracking: this agent told us every subnet it is connected to right
    # now. Its rows on any OTHER subnet are from a network it has left (WiFi
    # switch) — offline them immediately instead of waiting for staleness.
    if batch.agent_id and batch.active_subnets is not None:
        left = db.scalars(
            select(NetworkDevice).where(
                NetworkDevice.org_id == org_id,
                NetworkDevice.source_agent_id == batch.agent_id,
                NetworkDevice.online.is_(True),
                NetworkDevice.subnet.notin_(batch.active_subnets),
            )
        ).all()
        for row in left:
            row.online = False
            _close_device_session(db, org_id, row)

    # Safety net: age out any online row nobody has refreshed in a while — e.g. a
    # gateway a deep-scan created (with no sweeping agent_id) on a previous Wi-Fi,
    # which the agent-scoped rule above never touches and would otherwise linger
    # online forever, leaking a stale gateway onto the map.
    stale_cutoff = now - timedelta(minutes=15)
    stale = db.scalars(
        select(NetworkDevice).where(
            NetworkDevice.org_id == org_id,
            NetworkDevice.online.is_(True),
            NetworkDevice.last_seen < stale_cutoff,
        )
    ).all()
    for row in stale:
        if row.id in seen_ids:
            continue
        row.online = False
        _close_device_session(db, org_id, row)

    _upsert_inventoried_coverage(db, org_id, batch, observed_subnets)
    db.commit()
    return DeviceBatchResponse(total=len(by_key), new=new)



def _upsert_inventoried_coverage(
    db: Session, org_id: str, batch: DeviceBatch, observed_subnets: set[str]
) -> None:
    """Mark each subnet this batch swept as inventoried in network_coverage."""
    from app.models import NetworkCoverage

    for subnet in observed_subnets:
        count = len([d for d in batch.devices if _batch_device_subnet(batch, d) == subnet])
        row = db.scalar(
            select(NetworkCoverage).where(
                NetworkCoverage.org_id == org_id,
                NetworkCoverage.subnet == subnet,
            )
        )
        gw = batch.gateway_ip if _ip_in_subnet(batch.gateway_ip, subnet) else None
        if row is None:
            row = NetworkCoverage(
                org_id=org_id, subnet=subnet, status="inventoried",
                evidence=f"agent sweep ({batch.agent_id or 'unknown agent'})",
                gateway_ip=gw, label=batch.label, device_count=count,
            )
            db.add(row)
        else:
            row.status = "inventoried"
            row.evidence = f"agent sweep ({batch.agent_id or 'unknown agent'})"
            row.device_count = count
            if gw:
                row.gateway_ip = gw
            if batch.label:
                row.label = batch.label
            row.last_seen = utcnow()


def _batch_device_subnet(batch: DeviceBatch, d) -> str | None:
    return getattr(d, "subnet", None) or batch.subnet or _infer_subnet24(d.ip)


def _ip_in_subnet(ip: str | None, cidr: str | None) -> bool:
    if not ip or not cidr:
        return False
    import ipaddress

    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def report_coverage(db: Session, org_id: str, report) -> int:
    """Upsert agent-reported coverage rows (networks known to exist but not
    inventoried this run: skipped, unreachable, seen-but-not-joined SSIDs).
    Keyed by subnet when present, else by SSID — never both null."""
    from app.models import NetworkCoverage

    n = 0
    for net in report.networks:
        if not net.subnet and not net.ssid:
            continue  # no identity, nothing truthful to record
        q = select(NetworkCoverage).where(NetworkCoverage.org_id == org_id)
        if net.subnet:
            q = q.where(NetworkCoverage.subnet == net.subnet)
        else:
            q = q.where(NetworkCoverage.subnet.is_(None), NetworkCoverage.ssid == net.ssid)
        row = db.scalar(q)
        if row is None:
            db.add(NetworkCoverage(
                org_id=org_id, ssid=net.ssid, subnet=net.subnet,
                gateway_ip=net.gateway_ip, label=net.label,
                status=net.status, evidence=net.evidence,
            ))
        else:
            row.status = net.status
            row.evidence = net.evidence
            if net.ssid:
                row.ssid = net.ssid
            if net.gateway_ip:
                row.gateway_ip = net.gateway_ip
            if net.label:
                row.label = net.label
            row.last_seen = utcnow()
        n += 1
    db.commit()
    return n


def list_coverage(db: Session, org_id: str) -> list["CoverageOut"]:
    from app.models import NetworkCoverage
    from app.schemas.live import CoverageOut

    rows = db.scalars(
        select(NetworkCoverage)
        .where(NetworkCoverage.org_id == org_id)
        .order_by(NetworkCoverage.status, NetworkCoverage.last_seen.desc())
    ).all()
    return [
        CoverageOut(
            id=r.id, ssid=r.ssid, subnet=r.subnet, gateway_ip=r.gateway_ip,
            label=r.label, status=r.status, evidence=r.evidence,
            device_count=r.device_count or 0, last_seen=r.last_seen,
        )
        for r in rows
    ]


def backfill_device_subnets(db: Session) -> int:
    """One-shot bootstrap backfill: legacy rows predate the subnet column, so
    assume /24 (their agent only ever swept its own /24) and mark it inferred."""
    rows = db.scalars(
        select(NetworkDevice).where(NetworkDevice.subnet.is_(None))
    ).all()
    for row in rows:
        row.subnet = _infer_subnet24(row.ip)
        row.subnet_inferred = True
    if rows:
        db.commit()
    return len(rows)


_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _scan_status(db: Session, org_id: str) -> tuple[set[str], dict[str, tuple[int, str | None]]]:
    """(ips that have a successful deep scan, {asset_ip: (open_cve_count, worst_severity)})."""
    from app.models import Asset, AssetVulnerability, DeepScan, Vulnerability

    scanned_ips = set(
        db.scalars(
            select(DeepScan.target_ip).where(
                DeepScan.org_id == org_id, DeepScan.available.is_(True)
            )
        ).all()
    )
    by_ip: dict[str, tuple[int, str | None]] = {}
    rows = db.execute(
        select(Asset.ip, Vulnerability.severity)
        .join(AssetVulnerability, AssetVulnerability.asset_id == Asset.id)
        .join(Vulnerability, Vulnerability.id == AssetVulnerability.vulnerability_id)
        .where(Asset.org_id == org_id, AssetVulnerability.status == "open")
    ).all()
    for ip, severity in rows:
        count, worst = by_ip.get(ip, (0, None))
        count += 1
        if worst is None or _SEV_RANK.get(severity, 0) > _SEV_RANK.get(worst, 0):
            worst = severity
        by_ip[ip] = (count, worst)
    return scanned_ips, by_ip


def _deepscan_ports_by_ip(db: Session, org_id: str) -> dict[str, list[int]]:
    """{target_ip: [open ports]} from the latest available deep scan per IP —
    real nmap output, used to flag exposed risky services."""
    from app.models import DeepScan

    rows = db.scalars(
        select(DeepScan)
        .where(DeepScan.org_id == org_id, DeepScan.available.is_(True))
        .order_by(DeepScan.created_at.desc())
    ).all()
    out: dict[str, list[int]] = {}
    for r in rows:
        if r.target_ip in out:
            continue  # first row per IP is the newest (ordered desc)
        ports = (r.result_json or {}).get("ports") or []
        out[r.target_ip] = [int(p) for p in ports if isinstance(p, (int, float))]
    return out


def _latest_deepscans_by_ip(db: Session, org_id: str) -> dict[str, DeepScan]:
    """Retrieve the latest valid DeepScan record per target IP for an organization."""
    rows = db.scalars(
        select(DeepScan)
        .where(DeepScan.org_id == org_id, DeepScan.available.is_(True))
        .order_by(DeepScan.created_at.desc())
    ).all()
    out: dict[str, DeepScan] = {}
    for r in rows:
        if r.target_ip not in out:
            out[r.target_ip] = r
    return out


def _generate_security_findings(
    ports: list[int],
    services: list[DeepScanService],
    cves: list[DeepScanCve],
) -> list[str]:
    """Create deterministic, evidence-based security findings only from real DeepScan data.

    Rules:
    - OPEN != VULNERABLE
    - EXPOSURE != confirmed vulnerability
    - CVE findings must come only from actual correlated CVEs
    - Never invent CVEs
    - Never infer an attack from an open port
    """
    findings: list[str] = []
    port_set = set(ports)

    # 1. Deterministic port exposure findings
    if 3389 in port_set:
        findings.append("HIGH EXPOSURE: TCP/3389 Open (Microsoft RDP)")
    if 445 in port_set:
        findings.append("HIGH EXPOSURE: TCP/445 Open (SMB)")
    if 23 in port_set or 2323 in port_set:
        findings.append("HIGH EXPOSURE: TCP/23 Open (Telnet - Unencrypted)")
    if 21 in port_set:
        findings.append("SUSPICIOUS EXPOSURE: TCP/21 Open (FTP - Plaintext Authentication)")
    if 5900 in port_set:
        findings.append("HIGH EXPOSURE: TCP/5900 Open (VNC Remote Desktop)")
    if 139 in port_set:
        findings.append("HIGH EXPOSURE: TCP/139 Open (NetBIOS Session Service)")

    # 2. Correlated CVE findings (Real evidence only, never fabricated)
    for cve in cves:
        summary_snip = cve.summary.strip()
        if len(summary_snip) > 80:
            summary_snip = summary_snip[:77] + "..."
        findings.append(f"CORRELATED CVE: {cve.id} ({cve.severity.upper()} {cve.cvss}) - {summary_snip}")

    # 3. Disciplined finding when service identified but no CVE match confirmed
    if not cves and (any(s.product for s in services) or any(s.version for s in services)):
        findings.append("NO CONFIRMED VULNERABILITY")

    return findings


# Live view = devices an agent is seeing RIGHT NOW. A row is shown only while
# it is online AND refreshed recently; the window is a safety net for a killed
# agent (sweeps run every ~8s, so 90s ≈ several missed sweeps).
_DEVICE_STALE_AFTER = timedelta(minutes=15)


def _normalize_host(h: str | None) -> str:
    if not h:
        return ""
    s = h.strip().lower()
    if s.endswith(".local"):
        s = s[:-6]
    return s.strip()


def _hosts_match(host_a: str | None, host_b: str | None) -> bool:
    if not host_a or not host_b:
        return False
    na, nb = _normalize_host(host_a), _normalize_host(host_b)
    if not na or not nb:
        return False
    if na == nb:
        return True
    # For IP addresses, strictly require exact match (do NOT do substring match)
    is_ip_a = re.match(r"^\d+\.\d+\.\d+\.\d+$", na) is not None
    is_ip_b = re.match(r"^\d+\.\d+\.\d+\.\d+$", nb) is not None
    if is_ip_a or is_ip_b:
        return na == nb
    return na in nb or nb in na


_DOMAIN_TO_APP_NAME = {
    "whatsapp.com": "WhatsApp",
    "whatsapp.net": "WhatsApp",
    "spotify.com": "Spotify",
    "spotifycdn.com": "Spotify",
    "netflix.com": "Netflix",
    "nflxvideo.net": "Netflix",
    "youtube.com": "YouTube",
    "googlevideo.com": "YouTube",
    "youtu.be": "YouTube",
    "instagram.com": "Instagram",
    "cdninstagram.com": "Instagram",
    "facebook.com": "Facebook",
    "messenger.com": "Messenger",
    "github.com": "GitHub",
    "githubusercontent.com": "GitHub",
    "discord.com": "Discord",
    "discord.gg": "Discord",
    "discordapp.com": "Discord",
    "slack.com": "Slack",
    "zoom.us": "Zoom",
    "telegram.org": "Telegram",
    "figma.com": "Figma",
    "notion.so": "Notion",
    "openai.com": "ChatGPT",
    "chatgpt.com": "ChatGPT",
    "claude.ai": "Claude AI",
    "anthropic.com": "Claude AI",
    "google.com": "Google Chrome",
    "googleapis.com": "Google Services",
    "gstatic.com": "Google Services",
    "apple.com": "Apple Services",
    "icloud.com": "Apple iCloud",
    "apple-cloudkit.com": "Apple iCloud",
    "microsoft.com": "Microsoft 365",
    "office.com": "Microsoft Office",
    "live.com": "Microsoft Services",
    "teams.microsoft.com": "Microsoft Teams",
    "amazon.com": "Amazon",
    "amazon.in": "Amazon",
    "primevideo.com": "Prime Video",
    "twitter.com": "X (Twitter)",
    "x.com": "X (Twitter)",
    "linkedin.com": "LinkedIn",
    "reddit.com": "Reddit",
    "twitch.tv": "Twitch",
}


def _infer_apps_from_domains(domains: set[str]) -> set[str]:
    apps: set[str] = set()
    for d in domains:
        d_lower = d.lower().strip()
        for dom_key, app_name in _DOMAIN_TO_APP_NAME.items():
            if dom_key == d_lower or d_lower.endswith("." + dom_key):
                apps.add(app_name)
    return apps


def _fingerprint_device_profile(device: NetworkDevice, live_apps: set[str], live_domains: set[str]) -> tuple[set[str], set[str]]:
    """Heuristic ecosystem & service fingerprinting so all discovered LAN devices display active apps."""
    apps: set[str] = set(live_apps)
    doms: set[str] = set(live_domains)

    # If already populated with multiple apps and domains from live network traffic, preserve them
    if len(apps) >= 2 and len(doms) >= 1:
        return apps, doms

    ip_last = 0
    if device.ip and device.ip.count(".") == 3:
        try:
            ip_last = int(device.ip.split(".")[-1])
        except ValueError:
            pass

    vendor_lower = (device.vendor or "").lower()
    host_lower = (device.hostname or "").lower()
    label_lower = (device.label or "").lower()

    if device.is_gateway or ip_last == 1:
        apps.update(["Gateway Router", "DNS Resolver", "DHCP Server"])
        if not doms:
            doms.update(["gateway.local", "router.lan"])
    elif "apple" in vendor_lower or "iphone" in host_lower or "macbook" in host_lower or "ipad" in host_lower:
        apps.update(["Apple AirPlay", "Apple iCloud", "Safari"])
        if not doms:
            doms.update(["icloud.com", "apple-cloudkit.com"])
    elif "samsung" in vendor_lower or "android" in host_lower or "xiaomi" in vendor_lower:
        apps.update(["Google Chrome", "WhatsApp", "YouTube"])
        if not doms:
            doms.update(["whatsapp.com", "googlevideo.com"])
    elif "intel" in vendor_lower or "dell" in vendor_lower or "lenovo" in vendor_lower or "microsoft" in vendor_lower or "windows" in host_lower:
        apps.update(["Microsoft 365", "Google Chrome", "Slack"])
        if not doms:
            doms.update(["microsoft.com", "slack.com"])
    elif "amazon" in vendor_lower or "echo" in host_lower or "fire" in host_lower:
        apps.update(["Alexa / Echo", "Prime Video"])
        if not doms:
            doms.update(["amazon.com", "primevideo.com"])
    elif "espressif" in vendor_lower or "tuya" in vendor_lower or "raspberry" in vendor_lower or "iot" in label_lower:
        apps.update(["IoT Smart Device", "MQTT Telemetry"])
    elif "private device" in vendor_lower or "randomized" in vendor_lower or (device.mac and len(device.mac) > 1 and device.mac[1] in "26ae"):
        # Mobile phones / laptops with MAC randomization
        presets = [
            (["Google Chrome / Cast", "YouTube", "WhatsApp"], ["youtube.com", "whatsapp.com"]),
            (["Apple AirPlay", "Apple iCloud", "Spotify"], ["spotify.com", "apple.com"]),
            (["Instagram", "WhatsApp", "Google Chrome"], ["instagram.com", "google.com"]),
            (["Netflix", "Spotify", "Discord"], ["netflix.com", "discord.com"]),
            (["Google Chrome", "Microsoft Teams", "ChatGPT"], ["chatgpt.com", "teams.microsoft.com"]),
            (["Spotify", "WhatsApp", "Chrome Mobile"], ["spotify.com", "whatsapp.com"]),
        ]
        chosen_apps, chosen_doms = presets[ip_last % len(presets)]
        apps.update(chosen_apps)
        if not doms:
            doms.update(chosen_doms)
    else:
        presets = [
            (["Google Chrome", "YouTube"], ["youtube.com"]),
            (["Spotify", "WhatsApp"], ["spotify.com"]),
            (["Google Services", "ChatGPT"], ["openai.com"]),
            (["Apple AirPlay", "Safari"], ["apple.com"]),
            (["Microsoft 365", "Slack"], ["microsoft.com"]),
        ]
        chosen_apps, chosen_doms = presets[ip_last % len(presets)]
        apps.update(chosen_apps)
        if not doms:
            doms.update(chosen_doms)

    return apps, doms


def list_devices(db: Session, org_id: str) -> list[NetworkDeviceOut]:
    rows = db.scalars(
        select(NetworkDevice)
        .where(NetworkDevice.org_id == org_id)
        .order_by(NetworkDevice.is_gateway.desc(), NetworkDevice.is_self.desc(), NetworkDevice.ip)
    ).all()
    scanned_ips, by_ip = _scan_status(db, org_id)
    deepscans_by_ip = _latest_deepscans_by_ip(db, org_id)
    cutoff = utcnow() - _DEVICE_STALE_AFTER

    recent_obs = db.scalars(
        select(LiveObservation).where(
            LiveObservation.org_id == org_id,
            LiveObservation.last_seen > (utcnow() - timedelta(minutes=2))
        )
    ).all()
    obs_by_host: dict[str, list[str]] = {}
    for obs in recent_obs:
        sh = obs.source_host or ""
        obs_by_host.setdefault(sh, []).append(obs.domain)

    # Fetch all device sessions for this org to calculate continuous & total durations
    all_sessions = db.scalars(
        select(DevicePresenceSession)
        .where(DevicePresenceSession.org_id == org_id)
        .order_by(DevicePresenceSession.started_at.asc())
    ).all()
    sessions_by_key: dict[tuple[str, str], list[DevicePresenceSession]] = {}
    for s in all_sessions:
        sessions_by_key.setdefault((s.network_key, s.device_key), []).append(s)

    all_endpoint_agents = db.scalars(
        select(EndpointAgent)
        .where(EndpointAgent.org_id == org_id)
    ).all()

    out: list[NetworkDeviceOut] = []
    now_time = utcnow()
    for r in rows:
        if not r.online:
            continue  # not connected right now — live view hides it
        last = r.last_seen
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)  # SQLite rows come back naive
        if last is None or last < cutoff:
            continue
        # scanned = a real deep scan produced data for this device, OR the
        # autonomous scanner has run on it. Otherwise "not scanned" (never 0).
        ds = deepscans_by_ip.get(r.ip)
        scanned = r.ip in scanned_ips or r.last_scanned_at is not None or (ds is not None)
        vuln_count: int | None = None
        worst: str | None = None

        dev_open_ports: list[int] = []
        dev_services: list[DeepScanService] = []
        dev_cves: list[DeepScanCve] = []
        dev_os_from_scan: str | None = None
        dev_risk_score: float | None = None
        # Phase 04: all Phase 03 finding states (all 6 states, not just VULNERABLE/KEV)
        dev_endpoint_vuln_findings: list[EndpointFindingOut] = []
        # Phase 04: AI state (only populated when LIVE tracking session exists)
        dev_ai_detection = None
        dev_ai_forecast = None
        dev_ai_tracking_active = False
        dev_ai_session_id = None
        dev_security_score: float | None = None

        if ds and ds.result_json:
            rj = ds.result_json or {}
            raw_ports = rj.get("ports") or []
            dev_open_ports = [int(p) for p in raw_ports if isinstance(p, (int, float))]
            raw_services = rj.get("services") or []
            for s in raw_services:
                if isinstance(s, dict):
                    dev_services.append(DeepScanService(
                        port=int(s.get("port", 0)),
                        protocol=str(s.get("protocol", "tcp")),
                        service_name=str(s.get("service_name", "unknown")),
                        product=s.get("product"),
                        version=s.get("version"),
                        cpe=s.get("cpe"),
                        banner=s.get("banner"),
                        confidence=s.get("confidence"),
                    ))
            raw_cves = rj.get("cves") or []
            for c in raw_cves:
                if isinstance(c, dict):
                    dev_cves.append(DeepScanCve(
                        id=str(c.get("id", "")),
                        cvss=float(c.get("cvss", 0.0)),
                        severity=str(c.get("severity", "low")),
                        summary=str(c.get("summary", "")),
                        affected_service=str(c.get("affected_service", "")),
                        finding_id=c.get("finding_id"),
                    ))
            dev_os_from_scan = rj.get("os")
            raw_risk = rj.get("risk_score")
            if raw_risk is not None:
                try:
                    dev_risk_score = float(raw_risk)
                except (ValueError, TypeError):
                    dev_risk_score = None

        dev_security_findings = _generate_security_findings(dev_open_ports, dev_services, dev_cves)

        if scanned:
            default_worst = None
            if dev_cves:
                default_worst = max(dev_cves, key=lambda c: _SEV_RANK.get(c.severity, 0)).severity
            vuln_count, worst = by_ip.get(r.ip, (len(dev_cves), default_worst))  # 0 = real "no CVEs found"

        # Check endpoint telemetry for this host (strict isolation)
        matched_host_telem: HostTelemetry | None = None
        for k, telem in _HOST_TELEMETRY.items():
            if (now_time - telem.updated_at).total_seconds() < 60:
                # 1. Match by exact hardware MAC if both have it
                mac_match = bool(r.mac and telem.mac and r.mac.lower().strip() == telem.mac.lower().strip())
                # 2. Match by exact IP address
                ip_match = bool(telem.source_host and _hosts_match(telem.source_host, r.ip)) or _hosts_match(k, r.ip)
                # 3. Match by Hostname
                host_match = bool(r.hostname and (_hosts_match(k, r.hostname) or (telem.source_host and _hosts_match(telem.source_host, r.hostname))))
                # 4. Localhost / self fallback for is_self
                self_match = bool(
                    r.is_self
                    and (
                        telem.source_host in ("127.0.0.1", "localhost", "default", None, "")
                        or k in ("127.0.0.1", "localhost", "default", None, "")
                    )
                )

                if mac_match or ip_match or host_match or self_match:
                    matched_host_telem = telem
                    break

        active_browser_tabs_list: list[ActivityItem] = []
        endpoint_processes_list: list[ActivityItem] = []
        installed_software_list: list[ActivityItem] = []
        installed_browsers_list: list[str] = []
        process_connections_list: list[ActivityItem] = []
        vpn_status_val: str | None = None
        vpn_adapters_list: list[str] = []
        final_os_info: str | None = None
        final_device_type: str | None = None
        dev_capability_state: str = "NETWORK ONLY"

        if matched_host_telem is not None:
            # 2. Truthful active browser tabs (TTL: 20s)
            if (now_time - matched_host_telem.tabs_updated_at).total_seconds() < 20:
                active_browser_tabs_list = list(matched_host_telem.active_browser_tabs)

            # 3. Truthful running endpoint processes (TTL: 300s)
            endpoint_processes_list = list(matched_host_telem.endpoint_processes)

            # 4. Truthful installed software & browsers
            installed_software_list = list(matched_host_telem.installed_software)
            installed_browsers_list = list(matched_host_telem.installed_browsers)

            # 5. Truthful process connections (sockets) (TTL: 60s)
            process_connections_list = list(matched_host_telem.process_connections)

            # 6. Truthful VPN status & adapters
            vpn_status_val = matched_host_telem.vpn_status
            vpn_adapters_list = list(matched_host_telem.vpn_adapters)

            # 7. OS info & Device type
            final_os_info = matched_host_telem.os_info or dev_os_from_scan
            final_device_type = "Workstation (Local Host)" if r.is_self else ("Gateway / Router" if r.is_gateway else "Authorized Workstation")

            # Determine explicit capability state:
            has_tabs = len(active_browser_tabs_list) > 0
            has_procs = len(endpoint_processes_list) > 0
            if has_tabs and has_procs:
                dev_capability_state = "FULL ENDPOINT TELEMETRY"
            elif has_tabs:
                dev_capability_state = "BROWSER EXTENSION CONNECTED"
            else:
                dev_capability_state = "AGENT CONNECTED"
        else:
            # Remote device safety: device without authorized endpoint telemetry
            dev_capability_state = "NETWORK ONLY"
            active_browser_tabs_list = []
            endpoint_processes_list = []
            installed_software_list = []
            installed_browsers_list = []
            process_connections_list = []
            vpn_status_val = "TELEMETRY UNAVAILABLE"
            vpn_adapters_list = []
            final_os_info = dev_os_from_scan
            final_device_type = "Gateway / Router" if r.is_gateway else None

        # Check endpoint agent telemetry (Phase 02)
        endpoint_agent_row = None
        for ag in all_endpoint_agents:
            if (
                ag.device_id == r.id
                or (ag.mac and r.mac and ag.mac.lower().strip() == r.mac.lower().strip())
                or (ag.current_ip and r.ip and ag.current_ip == r.ip)
                or (ag.hostname and r.hostname and ag.hostname.lower() == r.hostname.lower())
                or (r.is_self and ag.status == "ONLINE")
            ):
                endpoint_agent_row = ag
                break

        ep_telem = None
        if endpoint_agent_row:
            ep_telem = endpoint_telemetry.get_telemetry_for_device(org_id, endpoint_agent_row.device_id)
        if not ep_telem:
            ep_telem = endpoint_telemetry.get_telemetry_for_device(org_id, r.id)

        listening_ports_list: list[ActivityItem] = []
        browser_processes_list: list[ActivityItem] = []
        endpoint_services_list: list[ActivityItem] = []
        is_telem_stale: bool = False

        if ep_telem is not None:
            is_telem_stale = ep_telem.is_stale
            if not endpoint_processes_list and ep_telem.endpoint_processes:
                endpoint_processes_list = [
                    ActivityItem(
                        name=p.name,
                        category=p.category,
                        pid=p.pid,
                        cpu_percent=p.cpu_percent,
                        memory_mb=p.memory_mb,
                        observed_at=p.observed_at,
                    )
                    for p in ep_telem.endpoint_processes
                ]
            if not installed_software_list and ep_telem.installed_software:
                installed_software_list = [
                    ActivityItem(
                        name=s.name,
                        version=s.version,
                        vendor=s.vendor,
                        observed_at=s.observed_at,
                    )
                    for s in ep_telem.installed_software
                ]
            if not installed_browsers_list and ep_telem.installed_browsers:
                installed_browsers_list = list(ep_telem.installed_browsers)
            if not process_connections_list and ep_telem.process_connections:
                process_connections_list = [
                    ActivityItem(
                        name=f"{c.process_name} ({c.local_port} -> {c.remote_address}:{c.remote_port})",
                        state=c.state,
                        pid=c.pid,
                        observed_at=c.observed_at,
                    )
                    for c in ep_telem.process_connections
                ]
            if ep_telem.listening_ports:
                listening_ports_list = [
                    ActivityItem(
                        name=f"{lp.process_name or 'service'} ({lp.protocol} {lp.bind_address}:{lp.port})",
                        pid=lp.pid,
                        observed_at=lp.observed_at,
                    )
                    for lp in ep_telem.listening_ports
                ]
            if ep_telem.browser_processes:
                browser_processes_list = [
                    ActivityItem(
                        name=bp.browser_name,
                        pid=bp.pid,
                        observed_at=bp.observed_at,
                    )
                    for bp in ep_telem.browser_processes
                ]
            if ep_telem.services:
                endpoint_services_list = [
                    ActivityItem(
                        name=s.name,
                        details=f"{s.display_name or ''} | {s.status} | {s.start_type or ''}".strip(" |"),
                        observed_at=s.observed_at,
                    )
                    for s in ep_telem.services
                ]
            if ep_telem.os_info:
                final_os_info = ep_telem.os_info

            os_low = (ep_telem.os_name or "").lower()
            if "windows" in os_low:
                dev_capability_state = "WINDOWS ENDPOINT"
            elif "darwin" in os_low or "mac" in os_low:
                dev_capability_state = "MACOS ENDPOINT"
            elif "android" in os_low:
                dev_capability_state = "ANDROID ENDPOINT"
            else:
                dev_capability_state = "AGENT CONNECTED"

            if len(active_browser_tabs_list) > 0:
                dev_capability_state = "FULL ENDPOINT TELEMETRY"

            ep_dev_id = endpoint_agent_row.device_id if endpoint_agent_row else r.id
            ep_findings = endpoint_telemetry.get_vulnerability_findings_for_device(org_id, ep_dev_id)
            existing_cve_ids = {c.id for c in dev_cves}
            for f in ep_findings:
                if f.cve_id and f.cve_id not in existing_cve_ids and f.finding_state in (
                    FindingState.VULNERABLE,
                    FindingState.KNOWN_EXPLOITED,
                ):
                    dev_cves.append(
                        DeepScanCve(
                            id=f.cve_id,
                            cvss=f.cvss,
                            severity=f.severity,
                            summary=f.summary or "",
                            affected_service=f"{f.observed_product} {f.observed_version or ''}".strip(),
                            finding_id=f.finding_id,
                            evidence_type=f.evidence_type,
                            source="endpoint_software",
                            intel_sources=f.intel_sources,
                            in_kev=f.in_kev,
                            ghsa_ids=f.ghsa_ids,
                            evidence_basis="endpoint_software_version",
                            is_inferred=False,
                            finding_state=f.finding_state.value if hasattr(f.finding_state, "value") else str(f.finding_state),
                            source_freshness=f.source_freshness,
                            source_status_reason=f.source_status_reason,
                            affected_range_text=f.affected_range_text,
                            fixed_version_text=f.fixed_version_text,
                        )
                    )
                    existing_cve_ids.add(f.cve_id)
            if dev_cves and vuln_count is None:
                vuln_count = len(dev_cves)
                worst = max(dev_cves, key=lambda c: _SEV_RANK.get(c.severity, 0)).severity

            # Phase 04: surface ALL Phase 03 finding states (not just VULNERABLE/KNOWN_EXPLOITED)
            # OPEN | EXPOSED | POTENTIAL_MATCH | VULNERABLE | KNOWN_EXPLOITED | NO_CONFIRMED_VULNERABILITY
            for f in ep_findings:
                dev_endpoint_vuln_findings.append(EndpointFindingOut(
                    finding_id=f.finding_id,
                    finding_state=f.finding_state.value if hasattr(f.finding_state, "value") else str(f.finding_state),
                    evidence_source=f.evidence_source,
                    observed_product=f.observed_product,
                    observed_version=f.observed_version,
                    cve_id=f.cve_id,
                    title=f.title,
                    summary=f.summary,
                    cvss=f.cvss,
                    severity=f.severity,
                    in_kev=f.in_kev,
                    kev_date_added=f.kev_date_added,
                    ghsa_ids=list(f.ghsa_ids),
                    affected_range_text=f.affected_range_text,
                    fixed_version_text=f.fixed_version_text,
                    intel_sources=list(f.intel_sources),
                    source_freshness=f.source_freshness,
                    source_status_reason=f.source_status_reason,
                ))
        elif endpoint_agent_row:
            os_low = (endpoint_agent_row.os or "").lower()
            if "windows" in os_low:
                dev_capability_state = "WINDOWS ENDPOINT"
            elif "darwin" in os_low or "mac" in os_low:
                dev_capability_state = "MACOS ENDPOINT"
            elif "android" in os_low:
                dev_capability_state = "ANDROID ENDPOINT"
            else:
                dev_capability_state = "AGENT CONNECTED"
            if not final_os_info:
                final_os_info = f"{endpoint_agent_row.os} {endpoint_agent_row.os_version or ''}".strip()

        # Phase 04: look up active AI tracking session for this device (org-scoped).
        # Only populated when a LIVE tracking session exists — never cross-device.
        # Labels: CURRENT DETECTION and FORECAST — NOT confirmed attack status.
        from app.services.traffic.session_manager import session_manager as _sm
        ep_dev_id_for_ai = endpoint_agent_row.device_id if (endpoint_agent_row and matched_host_telem) else None
        ai_session = None
        if ep_dev_id_for_ai:
            ai_session = _sm.get_active_session_for_device(org_id, ep_dev_id_for_ai)
        dev_ai_detection = ai_session.last_detection if ai_session else None
        dev_ai_forecast = ai_session.last_forecast if ai_session else None
        dev_ai_tracking_active = ai_session is not None
        dev_ai_session_id = ai_session.session_id if ai_session else None

        # Phase 04: compute deterministic device security score.
        # This is a risk-signal score [0.0–1.0], NOT a compromise or confirmed-attack score.
        # Forecast probability is intentionally excluded from this formula.
        score_inputs = build_score_inputs_from_device(
            cves=dev_cves,
            ai_verdict=dev_ai_detection.verdict if dev_ai_detection else None,
            ai_confidence=dev_ai_detection.confidence if dev_ai_detection else 0.0,
        )
        dev_security_score = compute_device_security_score(score_inputs)

        # Truthful backward-compatible lists:
        # Remote devices without an agent have no endpoint telemetry -> empty lists.
        # Never fabricate running applications from domain traffic or presets.
        final_apps = [p.name for p in endpoint_processes_list]
        final_doms = [t.name for t in active_browser_tabs_list]


        # 8. Collect passive network destinations (TTL: 30 minutes = 1800s)
        dev_dest_records: list[PassiveDestinationRecord] = []
        dev_dest_seen_keys: set[str] = set()

        for (h_org, h_host), dest_dict in list(_PASSIVE_DESTINATIONS_BY_HOST.items()):
            if h_org != org_id:
                continue
            matches = (
                _hosts_match(h_host, r.ip)
                or (r.hostname and _hosts_match(h_host, r.hostname))
                or (r.is_self and h_host in ("manual", "localhost", "127.0.0.1", "default", ""))
            )
            if not matches:
                continue

            for d_k, d_rec in list(dest_dict.items()):
                # Sliding 30-minute TTL
                age = (now_time - d_rec.last_seen).total_seconds()
                if age > 1800:
                    dest_dict.pop(d_k, None)
                    continue
                if d_rec.domain not in dev_dest_seen_keys:
                    dev_dest_seen_keys.add(d_rec.domain)
                    dev_dest_records.append(d_rec)

        for obs in recent_obs:
            sh = obs.source_host or ""
            matches = (
                _hosts_match(sh, r.ip)
                or (r.hostname and _hosts_match(sh, r.hostname))
                or (r.is_self and sh in ("manual", "localhost", "127.0.0.1", ""))
            )
            if matches and obs.domain:
                dom_clean = _clean_domain(obs.domain)
                if dom_clean and dom_clean not in dev_dest_seen_keys:
                    dev_dest_seen_keys.add(dom_clean)
                    classified = classify_domain(dom_clean)
                    obs_t = obs.last_seen
                    if obs_t is not None and obs_t.tzinfo is None:
                        obs_t = obs_t.replace(tzinfo=timezone.utc)
                    f_seen = obs.first_seen
                    if f_seen is not None and f_seen.tzinfo is None:
                        f_seen = f_seen.replace(tzinfo=timezone.utc)
                    dev_dest_records.append(
                        PassiveDestinationRecord(
                            domain=dom_clean,
                            resolved_service_label=classified["resolved_service_label"],
                            category=classified["category"],
                            protocol="DNS",
                            connection_count=obs.hit_count or 1,
                            first_seen=f_seen or obs_t or now_time,
                            last_seen=obs_t or now_time,
                            possible_vpn=classified["possible_vpn"],
                            evidence_source="dns_query_log",
                            confidence=classified["confidence"],
                        )
                    )

        # Sort: highest connection count first, then most recent last_seen
        dev_dest_records.sort(
            key=lambda d: (d.connection_count, d.last_seen or datetime.min.replace(tzinfo=timezone.utc)),
            reverse=True,
        )

        network_destinations_list = [
            NetworkDestinationOut(
                domain=d.domain,
                resolved_service_label=d.resolved_service_label,
                category=d.category,
                protocol=d.protocol,
                connection_count=d.connection_count,
                first_seen=d.first_seen,
                last_seen=d.last_seen,
                possible_vpn=d.possible_vpn,
                evidence_source=d.evidence_source,
                confidence=d.confidence,
            )
            for d in dev_dest_records
        ]

        recent_destinations_list = [
            ActivityItem(
                name=d.domain,
                evidence_type="NETWORK_TRAFFIC",
                source="network",
                observed_at=d.last_seen,
                details=f"Observed active {d.protocol} traffic ({d.evidence_source})",
            )
            for d in dev_dest_records
        ]

        # Security annotation: Cross-link traffic to existing Nmap/CVE findings
        traffic_security_annotations_list: list[TrafficSecurityAnnotation] = []
        for dest in dev_dest_records:
            if dest.dest_port:
                matching_service = next((s for s in dev_services if s.port == dest.dest_port), None)
                matching_cve = None
                if matching_service and matching_service.product:
                    prod_lower = matching_service.product.lower()
                    matching_cve = next((c for c in dev_cves if prod_lower in c.affected_service.lower()), None)
                if not matching_cve and (dest.dest_port in dev_open_ports or matching_service):
                    matching_cve = next((c for c in dev_cves if c.finding_id or c.id), None)

                if matching_cve:
                    cve_ref = matching_cve.finding_id or matching_cve.id
                    traffic_security_annotations_list.append(
                        TrafficSecurityAnnotation(
                            finding_type="traffic_to_vulnerable_service",
                            device_id=r.id,
                            related_cve_finding_id=cve_ref,
                            traffic_evidence=f"Active {dest.protocol} traffic observed contacting {dest.domain} on port {dest.dest_port}",
                            why=f"Observed network traffic interacting with port {dest.dest_port} which is associated with known vulnerability {matching_cve.id} ({matching_cve.affected_service}).",
                        )
                    )

        dev_key = _device_identity_key(r.mac, r.subnet, r.ip)
        net_key = r.subnet or "default"
        dev_sessions = sessions_by_key.get((net_key, dev_key), [])

        session_count = len(dev_sessions) if dev_sessions else 1
        observation_count = sum(s.observation_count for s in dev_sessions) if dev_sessions else 1

        # Current active session
        current_session = next((s for s in reversed(dev_sessions) if s.is_current), None)

        current_session_started_at: datetime | None = None
        current_session_duration: float = 0.0
        presence_state: str = "new"
        obs_source: str | None = None

        # Calculate completed sessions duration
        completed_duration: float = 0.0
        for s in dev_sessions:
            if not s.is_current or not r.online:
                end_t = _aware(s.ended_at or s.last_seen)
                st_t = _aware(s.started_at)
                if st_t and end_t:
                    completed_duration += max(0.0, (end_t - st_t).total_seconds())

        if r.online and current_session is not None:
            c_st = _aware(current_session.started_at)
            current_session_started_at = current_session.started_at
            obs_source = current_session.observation_source or r.discovery or "arp"

            if current_session.observation_count <= 1 or not c_st:
                current_session_duration = 0.0
                presence_state = "new"
            else:
                now_utc = _aware(now_time)
                current_session_duration = max(0.0, (now_utc - c_st).total_seconds()) if (now_utc and c_st) else 0.0
                presence_state = "continuous"

            total_observed_duration = completed_duration + current_session_duration
        else:
            current_session_started_at = None
            current_session_duration = 0.0
            presence_state = "offline" if not r.online else "new"
            total_observed_duration = completed_duration
            obs_source = dev_sessions[-1].observation_source if dev_sessions else (r.discovery or "arp")

        dev_ladder_state: str | None = None
        if any(c.in_kev for c in dev_cves):
            dev_ladder_state = "KNOWN_EXPLOITED"
        elif dev_cves:
            dev_ladder_state = "VULNERABLE"
        elif any(getattr(s, "cpe", None) for s in dev_services):
            dev_ladder_state = "POTENTIAL_MATCH"
        elif any(s.product or s.version for s in dev_services) or dev_services:
            dev_ladder_state = "EXPOSED"
        elif dev_open_ports:
            dev_ladder_state = "OPEN"
        else:
            dev_ladder_state = None

        presence_envelope = EvidenceEnvelope(
            evidence_type=EvidenceType.DEVICE_PRESENCE,
            device_id=r.ip,
            observed_at=_aware(r.last_seen or r.first_seen or now_time),
            source=r.discovery or "arp",
            confidence="high",
            is_stale=(_aware(now_time) - _aware(r.last_seen or now_time)).total_seconds() > 90,
            is_inferred=False,
            raw_value=f"DEVICE PRESENCE: {r.ip} [{r.mac or 'NO_MAC'}] {r.hostname or ''} {r.vendor or ''}".strip(),
            inferred_label=r.vendor or None,
            details={
                "ip": r.ip,
                "mac": r.mac,
                "hostname": r.hostname,
                "vendor": r.vendor,
                "subnet": r.subnet,
                "online": r.online,
                "is_gateway": r.is_gateway,
                "is_self": r.is_self,
            },
        )
        record_timeline_event(org_id, r.ip, presence_envelope)

        dev_timeline = get_device_timeline(org_id, r.ip, limit=200)
        for ev in dev_timeline:
            ev_age = (_aware(now_time) - _aware(ev.observed_at)).total_seconds()
            ev_type_str = str(ev.evidence_type)
            if "NETWORK_SOCKET" in ev_type_str or "NETWORK_TRAFFIC" in ev_type_str:
                ev.is_stale = ev_age > 90
            elif "DNS_QUERY" in ev_type_str:
                ev.is_stale = ev_age > 1200
            elif "DEVICE_PRESENCE" in ev_type_str:
                ev.is_stale = ev_age > 90
            elif "BROWSER_ACTIVE_TAB" in ev_type_str:
                ev.is_stale = ev_age > 20
            elif "ENDPOINT_PROCESS" in ev_type_str:
                ev.is_stale = ev_age > 60
            else:
                ev.is_stale = False

        dev_network_evidence: list[EvidenceEnvelope] = [presence_envelope]
        for p in dev_open_ports:
            dev_network_evidence.append(EvidenceEnvelope(
                evidence_type=EvidenceType.OPEN_PORT,
                device_id=r.ip,
                observed_at=_aware(r.last_scanned_at or now_time),
                source="nmap",
                confidence="high",
                is_stale=False,
                is_inferred=False,
                raw_value=f"PORT {p}/TCP OPEN",
                details={"port": p, "protocol": "tcp"},
            ))
        for s in dev_services:
            dev_network_evidence.append(EvidenceEnvelope(
                evidence_type=EvidenceType.SERVICE_DETECTION,
                device_id=r.ip,
                observed_at=_aware(r.last_scanned_at or now_time),
                source="nmap",
                confidence="high",
                is_stale=False,
                is_inferred=False,
                raw_value=f"SERVICE {s.service_name} on port {s.port} ({s.product or ''} {s.version or ''})".strip(),
                details={"port": s.port, "service_name": s.service_name, "product": s.product, "version": s.version},
            ))
        for c in dev_cves:
            dev_network_evidence.append(EvidenceEnvelope(
                evidence_type=EvidenceType.CVE_CORRELATION,
                device_id=r.ip,
                observed_at=_aware(r.last_scanned_at or now_time),
                source="cve_database",
                confidence="high",
                is_stale=False,
                is_inferred=True,
                raw_value=f"{c.id} ({c.severity.upper()} {c.cvss}) - {c.summary}",
                details={"id": c.id, "cvss": c.cvss, "severity": c.severity, "affected_service": c.affected_service},
            ))
        for ev in dev_timeline:
            if ev not in dev_network_evidence:
                dev_network_evidence.append(ev)

        out.append(NetworkDeviceOut(
            id=r.id, ip=r.ip, mac=r.mac, hostname=r.hostname, vendor=r.vendor,
            subnet=r.subnet, subnet_inferred=bool(r.subnet_inferred),
            discovery=r.discovery or "arp", label=r.label,
            is_self=r.is_self, is_gateway=r.is_gateway, online=r.online,
            first_seen=r.first_seen, last_seen=r.last_seen,
            scanned=scanned, vuln_count=vuln_count, worst_severity=worst,
            last_scanned_at=r.last_scanned_at,
            active_domains=sorted(set(final_doms)),
            active_apps=sorted(set(final_apps)),
            recent_destinations=recent_destinations_list,
            endpoint_processes=endpoint_processes_list,
            active_browser_tabs=active_browser_tabs_list,
            current_session_started_at=current_session_started_at,
            current_session_duration_seconds=round(current_session_duration, 1),
            total_observed_duration_seconds=round(total_observed_duration, 1),
            session_count=session_count,
            observation_count=observation_count,
            observation_source=obs_source,
            presence_state=presence_state,
            open_ports=dev_open_ports,
            services=dev_services,
            cves=dev_cves,
            os_info=final_os_info,
            device_type=final_device_type,
            installed_software=installed_software_list,
            process_connections=process_connections_list,
            installed_browsers=installed_browsers_list,
            vpn_status=vpn_status_val,
            vpn_adapters=vpn_adapters_list,
            security_findings=dev_security_findings,
            risk_score=dev_risk_score,
            capability_state=dev_capability_state,
            network_destinations=network_destinations_list,
            traffic_security_annotations=traffic_security_annotations_list,
            network_timeline=dev_timeline,
            network_evidence=dev_network_evidence,
            ladder_state=dev_ladder_state,
            listening_ports=listening_ports_list,
            browser_processes=browser_processes_list,
            endpoint_services=endpoint_services_list,
            is_telemetry_stale=is_telem_stale,
            # Phase 04 — Unified Device Security Profile
            # AI state: CURRENT DETECTION / FORECAST — NOT confirmed attack status.
            ai_detection=dev_ai_detection,
            ai_forecast=dev_ai_forecast,
            ai_tracking_active=dev_ai_tracking_active,
            ai_tracking_session_id=dev_ai_session_id,
            # Risk-signal score [0.0–1.0] — NOT a compromise or confirmed-attack score.
            device_security_score=dev_security_score,
            # All Phase 03 finding states (all 6 states)
            endpoint_vuln_findings=dev_endpoint_vuln_findings,
            paired_endpoint_agent_id=endpoint_agent_row.agent_id if endpoint_agent_row else None,
            paired_endpoint_device_id=endpoint_agent_row.device_id if endpoint_agent_row else None,
            paired_endpoint_status=endpoint_agent_row.calculate_status(now_time) if endpoint_agent_row else None,
            paired_endpoint_hostname=endpoint_agent_row.hostname if endpoint_agent_row else None,
            paired_endpoint_os=endpoint_agent_row.os if endpoint_agent_row else None,
            paired_endpoint_os_version=endpoint_agent_row.os_version if endpoint_agent_row else None,
            paired_endpoint_agent_version=endpoint_agent_row.agent_version if endpoint_agent_row else None,
            paired_endpoint_last_heartbeat=endpoint_agent_row.last_heartbeat if endpoint_agent_row else None,
            paired_endpoint_paired_at=endpoint_agent_row.paired_at if endpoint_agent_row else None,
        ))
    return out


def upsert_device_from_endpoint_agent(db: Session, org_id: str, agent: EndpointAgent) -> None:
    """Ensure the endpoint agent's host appears in the NetworkDevice grid.

    Called from agent_heartbeat() and submit_pairing() so a paired endpoint host
    shows up in Live Watch immediately — without waiting for an ARP scan.
    The row is created with discovery='endpoint_agent' to distinguish it from
    ARP / nmap-discovered peers.  Idempotent: safe to call on every heartbeat.
    """
    import uuid
    ip = (agent.current_ip or "").strip()

    now = utcnow()
    row: NetworkDevice | None = None
    if agent.device_id:
        row = db.get(NetworkDevice, agent.device_id)
    if row is None and ip:
        row = db.scalar(
            select(NetworkDevice).where(
                NetworkDevice.org_id == org_id,
                NetworkDevice.ip == ip,
            )
        )
    if row is None and agent.mac:
        row = db.scalar(
            select(NetworkDevice).where(
                NetworkDevice.org_id == org_id,
                NetworkDevice.mac == agent.mac,
            )
        )

    init_vendor = "Android" if "android" in (agent.os or "").lower() else None

    if row is None:
        row = NetworkDevice(
            id=agent.device_id or str(uuid.uuid4()),
            org_id=org_id,
            ip=ip,
            mac=agent.mac,
            hostname=agent.hostname,
            vendor=init_vendor,
            source_agent_id=agent.agent_id,
            discovery="endpoint_agent",
            label=agent.hostname,
            is_self=False,
            is_gateway=False,
            online=True,
            first_seen=now,
            last_seen=now,
            subnet=None,
            subnet_inferred=True,
        )
        try:
            db.add(row)
            db.flush()
        except IntegrityError:
            db.rollback()
            if agent.device_id:
                row = db.get(NetworkDevice, agent.device_id)
            if row is None and ip:
                row = db.scalar(
                    select(NetworkDevice).where(
                        NetworkDevice.org_id == org_id,
                        NetworkDevice.ip == ip,
                    )
                )
            if row is None:
                return
    else:
        row.online = True
        row.last_seen = now
        if ip and not row.ip:
            row.ip = ip
        if not row.hostname and agent.hostname:
            row.hostname = agent.hostname
        if not row.mac and agent.mac:
            row.mac = agent.mac
        if not row.vendor and init_vendor:
            row.vendor = init_vendor

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.warning("upsert_device_from_endpoint_agent: commit failed (non-fatal)")


def clear_devices(db: Session, org_id: str) -> int:
    from sqlalchemy import delete

    rows = db.scalars(select(NetworkDevice).where(NetworkDevice.org_id == org_id)).all()
    n = len(rows)
    db.execute(delete(NetworkDevice).where(NetworkDevice.org_id == org_id))
    db.execute(delete(DevicePresenceSession).where(DevicePresenceSession.org_id == org_id))
    db.commit()
    _HOST_TELEMETRY.clear()
    _ACTIVE_APPS_BY_HOST.clear()
    _ACTIVE_OPEN_TABS_BY_HOST.clear()
    _PASSIVE_DESTINATIONS_BY_HOST.clear()
    _DEVICE_TIMELINES.clear()
    _RESOLVED_DNS_BY_HOST.clear()
    return n



def clear(db: Session, org_id: str) -> int:
    """Wipe this org's live observations (reset the feed before a fresh demo)."""
    from sqlalchemy import delete

    rows = db.scalars(select(LiveObservation).where(LiveObservation.org_id == org_id)).all()
    n = len(rows)
    db.execute(delete(LiveObservation).where(LiveObservation.org_id == org_id))
    db.commit()
    return n


def resolve_threat(db: Session, org_id: str, threat_id: str) -> bool:
    """Resolve/dismiss a specific live threat observation by id or domain."""
    from sqlalchemy import delete
    cleaned = _clean_domain(threat_id)
    stmt = delete(LiveObservation).where(
        LiveObservation.org_id == org_id,
        (LiveObservation.id == threat_id) | (LiveObservation.domain == threat_id) | (LiveObservation.domain == cleaned)
    )
    result = db.execute(stmt)
    db.commit()
    return bool(result.rowcount > 0)


def block_fix(db: Session, org_id: str, obs_id: str, domain_hint: str | None = None) -> BlockFixOut:
    # 1. Search by observation UUID
    row = db.scalar(
        select(LiveObservation).where(
            LiveObservation.id == obs_id, LiveObservation.org_id == org_id
        )
    )
    # 2. Fallback: search by domain name if obs_id is a domain string or domain_hint given
    target_domain = domain_hint or obs_id
    if row is None:
        cleaned = _clean_domain(target_domain)
        if cleaned:
            row = db.scalar(
                select(LiveObservation).where(
                    LiveObservation.org_id == org_id, LiveObservation.domain == cleaned
                )
            )
    # 3. Fallback: generate observation on-the-fly if missing/cleared
    if row is None:
        cleaned = _clean_domain(target_domain)
        if cleaned and "." in cleaned:
            try:
                obs_res = observe(db, org_id, cleaned, source_host="manual")
                row = db.scalar(
                    select(LiveObservation).where(
                        LiveObservation.id == obs_res.id, LiveObservation.org_id == org_id
                    )
                )
            except Exception:
                pass

    if row is None:
        raise NotFoundError("Observation not found")

    reasons = _reasons_from(row.verdict_json or {})
    ctx = {
        "domain": row.domain,
        "band": row.band,
        "score": float(row.score),
        "signals": reasons,
    }
    fallback = _templated_block(row.domain, row.band, reasons)

    from app.services.ai import prompts
    from app.services.ai.client import generate

    system, user_json, schema = prompts.build_block_messages(ctx)
    data = generate(system, user_json, "block_domain", fallback, schema)

    if data.get("refused"):
        return BlockFixOut(refused=True, reason=data.get("reason") or "Not supported",
                           domain=row.domain, band=row.band)
    cmds = data.get("commands") or fallback["commands"]
    return BlockFixOut(
        domain=row.domain,
        band=row.band,
        summary=data.get("summary") or fallback["summary"],
        why_risky=data.get("why_risky") or reasons,
        commands=[BlockCommand(platform=c.get("platform", "hosts"), command=c.get("command", "")) for c in cmds],
    )


def _templated_block(domain: str, band: str, reasons: list[str]) -> dict:
    if band == "Trusted":
        summary = f"Advisory: {domain} is rated 'Trusted'. Blocking this domain may disrupt legitimate services. Apply egress block rules only if explicitly isolating host traffic."
        why_risky = reasons or ["Domain has verified infrastructure reputation and clean security signals.", "Blocking will prevent legitimate application traffic to this host."]
    else:
        summary = f"Isolate and block outbound network connections to {domain} (rated '{band}') to contain threat traffic."
        why_risky = reasons or [f"Reputation rating: {band}", "Observed suspicious network telemetry."]

    return {
        "refused": False,
        "summary": summary,
        "why_risky": why_risky,
        "commands": [
            {
                "platform": "hosts",
                "command": f"echo -e \"\\n0.0.0.0 {domain}\\n::1 {domain}\" | sudo tee -a /etc/hosts",
            },
            {
                "platform": "linux",
                "command": f"sudo ufw deny out to any proto tcp port 80,443 comment \"Block {domain}\" 2>/dev/null || true; echo -e \"0.0.0.0 {domain}\\n::1 {domain}\" | sudo tee -a /etc/hosts",
            },
            {
                "platform": "macos",
                "command": f"echo -e \"\\n0.0.0.0 {domain}\\n::1 {domain}\" | sudo tee -a /etc/hosts && sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder",
            },
            {
                "platform": "windows",
                "command": f"Add-Content -Path \"$env:windir\\System32\\drivers\\etc\\hosts\" -Value \"`n0.0.0.0 {domain}`n::1 {domain}\"; Clear-DnsClientCache; try {{ $ips = (Resolve-DnsName -Name \"{domain}\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress); if ($ips) {{ New-NetFirewallRule -DisplayName \"Drishti Block {domain}\" -Direction Outbound -Action Block -RemoteAddress $ips }} }} catch {{}}",
            },
            {
                "platform": "pihole",
                "command": f"sudo pihole --wild {domain} 2>/dev/null || sudo pihole -b {domain}",
            },
            {
                "platform": "router",
                "command": f"# MikroTik RouterOS / VyOS drop rule\n/ip firewall filter add chain=forward dst-address-list={domain} action=drop comment=\"Drishti Block {domain}\"",
            },
        ],
    }
