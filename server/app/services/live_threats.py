# Drishti — live network threat detection. Turns the passive device inventory
# into ACTIVE, defensive threat signals: ARP-spoofing / MITM, rogue devices,
# exposed risky services, and hosts contacting malicious domains. Everything is
# computed from data we already collect — no traffic interception, no exploits.
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import LiveObservation, NetworkDevice
from app.models.base import utcnow
from app.schemas.live_threats import NetworkThreat

# a device first seen this recently, that isn't us or the gateway, is "new"
NEW_DEVICE_WINDOW = timedelta(minutes=10)
# rows seen within this window count as "currently on the wire" for spoof checks
RECENT_WINDOW = timedelta(minutes=5)

# services that should almost never be openly exposed on a LAN host — cleartext
# or remote-control ports an attacker loves to find
RISKY_PORTS: dict[int, str] = {
    21: "FTP (cleartext)",
    23: "Telnet (cleartext)",
    445: "SMB file sharing",
    3389: "RDP remote desktop",
    5900: "VNC remote desktop",
    139: "NetBIOS",
    1900: "UPnP",
    2323: "Telnet-alt (IoT)",
}

_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class DeviceView:
    ip: str
    mac: str | None
    hostname: str | None
    is_gateway: bool
    is_self: bool
    online: bool
    first_seen: datetime | None
    last_seen: datetime | None
    scanned: bool = False
    vuln_count: int | None = None
    worst_severity: str | None = None
    open_ports: list[int] = field(default_factory=list)


@dataclass
class DomainView:
    id: str
    domain: str
    band: str
    score: float
    source_host: str | None
    reasons: list[str]


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def detect_threats(
    devices: list[DeviceView], domains: list[DomainView], now: datetime
) -> list[NetworkThreat]:
    """Pure detector — same inputs, same threats out (unit-testable, no DB/IO)."""
    threats: list[NetworkThreat] = []
    cutoff = now - RECENT_WINDOW

    def recent(d: DeviceView) -> bool:
        ls = _aware(d.last_seen)
        return ls is not None and ls >= cutoff

    # ── 1. ARP spoofing / MITM: one IP claimed by two or more MACs at once ──────
    # NetworkDevice dedupes per (org, mac), so two MACs answering for the same IP
    # produce two rows — the classic ARP-poisoning signature we can see honestly.
    by_ip: dict[str, set[str]] = defaultdict(set)
    for d in devices:
        if d.mac and recent(d):
            by_ip[d.ip].add(d.mac.lower())
    spoofed_ips = {ip for ip, macs in by_ip.items() if len(macs) >= 2}
    for ip, macs in by_ip.items():
        if len(macs) >= 2:
            gw = any(d.is_gateway for d in devices if d.ip == ip)
            threats.append(
                NetworkThreat(
                    id=f"arp:{ip}",
                    kind="arp_spoof",
                    severity="critical" if gw else "high",
                    title=f"Possible ARP spoofing on {ip}",
                    detail=(
                        f"{len(macs)} different MAC addresses are claiming {ip}"
                        + (" — the gateway. This is the signature of a man-in-the-middle attack "
                           "redirecting your traffic." if gw
                           else ". A device may be impersonating another to intercept traffic.")
                    ),
                    device_ip=ip,
                    device_mac=None,
                    hostname=None,
                    evidence=[f"MAC {m}" for m in sorted(macs)],
                    recommendation=(
                        "Verify the gateway's real MAC from the router, pin it with a static ARP "
                        "entry, and isolate the impersonating device."
                    ),
                    mitre="T1557 · Adversary-in-the-Middle",
                    first_seen=None,
                )
            )

    # ── 2. Rogue / newly-joined device ─────────────────────────────────────────
    # An IP already flagged for spoofing is reported once (as the spoof); don't
    # also call each impostor MAC a "rogue device". Dedupe per IP.
    seen_rogue: set[str] = set()
    for d in devices:
        if not d.online or d.is_self or d.is_gateway:
            continue
        if d.ip in spoofed_ips or d.ip in seen_rogue:
            continue
        fs = _aware(d.first_seen)
        if fs is not None and (now - fs) <= NEW_DEVICE_WINDOW:
            seen_rogue.add(d.ip)
            name = d.hostname or d.ip
            threats.append(
                NetworkThreat(
                    id=f"rogue:{d.mac or d.ip}",
                    kind="rogue_device",
                    severity="medium",
                    title=f"New device joined: {name}",
                    detail=(
                        f"{name} ({d.ip}) appeared on your network within the last "
                        f"{int(NEW_DEVICE_WINDOW.total_seconds() // 60)} minutes. If you don't "
                        "recognise it, it may be unauthorised."
                    ),
                    device_ip=d.ip,
                    device_mac=d.mac,
                    hostname=d.hostname,
                    evidence=[f"first seen {fs.strftime('%H:%M:%S')} UTC", f"MAC {d.mac or 'unknown'}"],
                    recommendation="Confirm you own this device; if not, block its MAC at the router and investigate.",
                    mitre="T1200 · Hardware Additions",
                    first_seen=fs,
                )
            )

    # ── 3. Exposed risky service / known-vulnerable host (from real deep scans) ─
    seen_service: set[str] = set()
    for d in devices:
        if not d.scanned or d.ip in spoofed_ips or d.ip in seen_service:
            continue
        risky = [(p, RISKY_PORTS[p]) for p in d.open_ports if p in RISKY_PORTS]
        has_cves = (d.vuln_count or 0) > 0
        if not risky and not has_cves:
            continue
        seen_service.add(d.ip)
        name = d.hostname or d.ip
        ev: list[str] = [f"{name} ({d.ip})"]
        ev += [f"port {p} — {label}" for p, label in risky]
        if has_cves:
            ev.append(f"{d.vuln_count} known CVE(s), worst {d.worst_severity or 'unknown'}")
        sev = d.worst_severity if has_cves and d.worst_severity else ("high" if risky else "medium")
        threats.append(
            NetworkThreat(
                id=f"service:{d.mac or d.ip}",
                kind="risky_service",
                severity=sev,
                title=f"Exposed attack surface on {name}",
                detail=(
                    f"{name} exposes services an attacker can target directly for initial access "
                    "or lateral movement."
                ),
                device_ip=d.ip,
                device_mac=d.mac,
                hostname=d.hostname,
                evidence=ev,
                recommendation="Close the port if unused, or patch/segment the host. Run a deep scan for the full finding list.",
                mitre="T1210 · Exploitation of Remote Services",
                first_seen=None,
            )
        )

    # ── 4. Host contacting a malicious / suspicious domain ─────────────────────
    for dom in domains:
        if dom.band == "Trusted":
            continue
        sev = "high" if dom.band == "High Risk" else "medium"
        host = dom.source_host or "a host on your network"
        threats.append(
            NetworkThreat(
                id=f"domain:{dom.id}",
                kind="malicious_domain",
                severity=sev,
                title=f"{host} contacted {dom.domain}",
                detail=(
                    f"{dom.domain} scored {dom.score:.0f}/100 ({dom.band}). A device on your "
                    "network reached out to it — a sign of phishing, malware C2, or data exfiltration."
                ),
                device_ip=None,
                device_mac=None,
                hostname=dom.source_host,
                evidence=dom.reasons[:4] or [f"trust verdict: {dom.band}"],
                recommendation="Block this domain at the DNS/hosts level and inspect the host that reached it.",
                mitre="T1071 · Application Layer Protocol (C2)",
                first_seen=None,
            )
        )

    threats.sort(key=lambda t: _SEV_RANK.get(t.severity, 0), reverse=True)
    return threats


def network_threats(db: Session, org_id: str) -> list[NetworkThreat]:
    """DB adapter: gather what we already store and run the pure detector."""
    from app.services.live import _scan_status, _deepscan_ports_by_ip, list_threats

    since = utcnow() - RECENT_WINDOW
    rows = db.scalars(
        select(NetworkDevice).where(
            NetworkDevice.org_id == org_id, NetworkDevice.last_seen >= since
        )
    ).all()
    scanned_ips, by_ip = _scan_status(db, org_id)
    ports_by_ip = _deepscan_ports_by_ip(db, org_id)

    views: list[DeviceView] = []
    for r in rows:
        scanned = r.ip in scanned_ips or r.last_scanned_at is not None
        vuln_count, worst = (by_ip.get(r.ip, (0, None)) if scanned else (None, None))
        views.append(
            DeviceView(
                ip=r.ip, mac=r.mac, hostname=r.hostname,
                is_gateway=r.is_gateway, is_self=r.is_self, online=r.online,
                first_seen=r.first_seen, last_seen=r.last_seen,
                scanned=scanned, vuln_count=vuln_count, worst_severity=worst,
                open_ports=ports_by_ip.get(r.ip, []),
            )
        )

    threat_rows = list_threats(db, org_id)
    domains = [
        DomainView(id=t.id, domain=t.domain, band=t.band, score=t.score,
                   source_host=t.source_host, reasons=t.reasons)
        for t in threat_rows
    ]
    return detect_threats(views, domains, utcnow())


# ── Demo injector — for a live demo without a second physical device ──────────
_DEMO_LABEL = "DEMO-ATTACK"
_DEMO_HOST = "DEMO-workstation"
_DEMO_DOMAIN = "secure-paypal-login.drishti-demo.test"


def inject_demo(db: Session, org_id: str) -> None:
    """Insert clearly-labelled demo threats: an ARP-spoof pair on the gateway, a
    rogue host, and a High-Risk domain contact. Idempotent — clears prior demo
    rows first so re-running never collides on the (org, mac) unique key."""
    clear_demo(db, org_id)

    gw = db.scalar(
        select(NetworkDevice).where(
            NetworkDevice.org_id == org_id,
            NetworkDevice.is_gateway.is_(True),
            NetworkDevice.online.is_(True),
        ).order_by(NetworkDevice.last_seen.desc())  # most-recent gateway, not a stale one
    )
    any_dev = gw or db.scalar(
        select(NetworkDevice).where(
            NetworkDevice.org_id == org_id, NetworkDevice.online.is_(True)
        ).order_by(NetworkDevice.last_seen.desc())
    )
    gw_ip = gw.ip if gw else (any_dev.ip.rsplit(".", 1)[0] + ".1" if any_dev else "192.168.1.1")
    base = gw_ip.rsplit(".", 1)[0]
    subnet = f"{base}.0/24"
    now = utcnow()

    def dev(mac: str, ip: str, hostname: str) -> NetworkDevice:
        return NetworkDevice(
            org_id=org_id, mac=mac, ip=ip, hostname=hostname, subnet=subnet,
            subnet_inferred=False, discovery="arp", label=_DEMO_LABEL,
            vendor="Unknown (spoofed)", is_self=False, is_gateway=False,
            online=True, first_seen=now, last_seen=now,
        )

    # ARP-spoof: two extra MACs answering for the gateway IP → MITM signature
    db.add(dev("de:ad:be:ef:00:01", gw_ip, "attacker-mitm"))
    db.add(dev("de:ad:be:ef:00:02", gw_ip, "attacker-mitm"))
    # rogue newly-joined host
    db.add(dev("de:ad:be:ef:13:37", f"{base}.66", "unknown-intruder"))

    # High-Risk domain contact — real structural analysis via the URL analyzer;
    # falls back to a labelled row if analysis is unavailable offline
    try:
        from app.services.live import observe

        observe(db, org_id, _DEMO_DOMAIN, _DEMO_HOST)
    except Exception:
        db.add(
            LiveObservation(
                org_id=org_id, domain=_DEMO_DOMAIN, url=f"http://{_DEMO_DOMAIN}/",
                band="High Risk", score=22.0,
                verdict_json={"signals": [{"id": "demo", "label": "Lure keywords + lookalike brand + test TLD", "status": "fail"}]},
                source_host=_DEMO_HOST, hit_count=3,
            )
        )
    db.commit()


def clear_demo(db: Session, org_id: str) -> int:
    from sqlalchemy import delete

    n = 0
    n += db.execute(
        delete(NetworkDevice).where(
            NetworkDevice.org_id == org_id, NetworkDevice.label == _DEMO_LABEL
        )
    ).rowcount or 0
    n += db.execute(
        delete(LiveObservation).where(
            LiveObservation.org_id == org_id, LiveObservation.source_host == _DEMO_HOST
        )
    ).rowcount or 0
    db.commit()
    return n
