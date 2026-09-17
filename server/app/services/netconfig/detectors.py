# Drishti v0.1 — network-config vulnerability detectors | 12-Jul-2026
"""Detect real NAT / DMZ / DHCP misconfigurations from observed topology and/or
declared config. Every finding cites the concrete evidence it was inferred from.
When the evidence needed for a check isn't available, the check emits a
status='unknown' record — never a fabricated finding, and never a false 'passed'.

Severity is assigned by a transparent model (below), the same spirit as the risk
engine's coefficients — it is derived from the real finding, not invented data.
Only status='real' findings carry a severity that later maps into the engine;
'unknown'/'passed' contribute nothing to risk."""
from __future__ import annotations

from app.services.netconfig.facts import AssetFact, NetworkFacts
from app.services.risk_engine import INTERNET, Engine, blast_radius

# management / database ports that must never be exposed straight to the internet
_SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP",
    5432: "PostgreSQL", 3306: "MySQL", 1433: "MSSQL",
    6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 5900: "VNC",
}
# database ports — most sensitive when exposed
_DB_PORTS = {5432, 3306, 1433, 6379, 27017, 9200}
# ports risky even on the LAN (lateral-movement surface). SSH(22) is common/
# expected, so it's flagged only when internet-facing, not on every host.
_LAN_FLAG_PORTS = {23, 3389, 5900} | _DB_PORTS

# transparent severity → (cvss, exploitability) model for config findings
_SEVERITY_MODEL = {
    "critical": (9.0, 0.85),
    "high": (7.5, 0.65),
    "medium": (5.0, 0.45),
    "low": (3.0, 0.25),
}


def severity_to_engine(severity: str) -> tuple[float, float]:
    return _SEVERITY_MODEL.get(severity, (5.0, 0.45))


def _finding(
    category: str,
    slug: str,
    title: str,
    severity: str,
    status: str,
    source: str,
    evidence: str,
    affected: list[str],
    remediation_hint: str,
    affected_ids: list[str] | None = None,
) -> dict:
    return {
        "id": f"{category}-{slug}",
        "category": category,
        "title": title,
        "severity": severity,
        "status": status,  # real | unknown | passed
        "source": source,  # observed | declared
        "evidence": evidence,
        "affected": affected,
        "remediation_hint": remediation_hint,
        "affected_ids": affected_ids or [],  # asset ids to attach engine findings to
    }


def _crit_severity(asset: AssetFact) -> str:
    """Map an asset's business criticality to a finding severity."""
    return {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(
        asset.criticality, "medium"
    )


# ── DMZ segmentation ─────────────────────────────────────────────────────────
def detect_dmz(engine: Engine, facts: NetworkFacts) -> list[dict]:
    out: list[dict] = []
    by_id = {a.id: a for a in facts.assets}

    dmz_assets = [a for a in facts.assets if a.zone_kind == "dmz" or a.declared_dmz]
    has_dmz = ("dmz" in facts.zone_kinds_present) or bool(dmz_assets)
    # No DMZ segment at all. If the live sweep sees devices, a flat LAN with no
    # DMZ/VLAN separation is itself a real (observed) posture finding — the
    # risk-label zones (internal / crown-jewel) are not network segments. When
    # there is no live inventory and no zones either, we can only say 'unknown'.
    if not has_dmz:
        if facts.has_device_inventory:
            dev_n = len({a.ip for a in facts.assets}) or None
            out.append(_finding(
                "DMZ", "flat-network-live",
                "Flat network — no DMZ / VLAN segmentation",
                "medium", "real", "observed",
                "The live device sweep sees all hosts sharing one flat subnet with no DMZ or "
                "VLAN separation — a compromised device (phone, IoT, laptop) can reach every "
                "other host directly."
                + (f" {dev_n} host(s) share the segment." if dev_n else ""),
                [facts.gateway_ip] if facts.gateway_ip else [],
                "Put untrusted/IoT and internet-facing devices on their own VLAN behind the "
                "gateway firewall; keep sensitive hosts on a separate internal segment.",
            ))
            return out
        if not facts.zone_kinds_present:
            out.append(_finding(
                "DMZ", "zones-unknown",
                "Network zones / segmentation not defined",
                "none", "unknown", "observed",
                "No security zones (DMZ / internal / crown-jewel) are assigned to this network's "
                "assets, so segmentation between public-facing and internal systems can't be assessed.",
                [],
                "Assign zones to assets — load the sample topology or declare your DMZ hosts — to "
                "enable DMZ segmentation analysis.",
            ))
            return out
        # else: non-DMZ zones exist but no live inventory (an imported sample) —
        # fall through to the observed internet-facing / flat-network check below

    has_dmz_zone = "dmz" in facts.zone_kinds_present
    has_internal = bool(facts.zone_kinds_present & {"internal", "crown_jewel"})
    internet_facing = [a for a in facts.assets if a.internet_facing]

    # (a) flat network — internet-facing services with no DMZ zone at all
    if not has_dmz_zone and not any(a.declared_dmz for a in facts.assets):
        if internet_facing and has_internal:
            out.append(_finding(
                "DMZ", "flat-network",
                "Flat network — no DMZ segmentation for internet-facing services",
                "high", "real", "observed",  # derived from observed zones/internet_facing
                f"{len(internet_facing)} internet-facing asset(s) share zones with internal "
                f"assets; no zone of kind 'dmz' exists.",
                [a.hostname or a.ip for a in internet_facing],
                "Create a DMZ zone/VLAN for internet-facing hosts and place a firewall between "
                "it and the internal network.",
                affected_ids=[a.id for a in internet_facing],
            ))

    # (b) DMZ host that can reach internal / crown-jewel assets (broken segmentation)
    for dmz in dmz_assets:
        reachable = blast_radius(engine, dmz.id)
        sensitive = [
            by_id[r] for r in reachable
            if r in by_id and by_id[r].zone_kind in ("internal", "crown_jewel")
        ]
        if not sensitive:
            continue
        hits_crown = any(a.zone_kind == "crown_jewel" for a in sensitive)
        severity = "critical" if hits_crown else "high"
        src = "declared" if dmz.declared_dmz and dmz.zone_kind != "dmz" else "observed"
        names = ", ".join(sorted((a.hostname or a.ip) for a in sensitive)[:6])
        out.append(_finding(
            "DMZ", f"segmentation-{dmz.ip}",
            f"DMZ host {dmz.hostname or dmz.ip} can reach "
            f"{'crown-jewel' if hits_crown else 'internal'} asset(s)",
            severity, "real", src,
            f"Graph reachability from DMZ host {dmz.hostname or dmz.ip} traverses existing "
            f"connections to: {names}. Compromising the DMZ host yields an internal foothold.",
            [dmz.hostname or dmz.ip, *sorted((a.hostname or a.ip) for a in sensitive)[:6]],
            "Add a segmentation ACL/firewall rule denying DMZ→internal traffic except explicitly "
            "required flows; front sensitive services with a broker instead of direct DMZ access.",
            affected_ids=[dmz.id],  # the DMZ box is the exploitable foothold
        ))

    # (c) sensitive asset sitting IN the DMZ zone
    for a in facts.assets:
        if a.zone_kind == "dmz" and a.criticality in ("high", "critical"):
            out.append(_finding(
                "DMZ", f"sensitive-in-dmz-{a.ip}",
                f"{a.criticality.title()}-criticality asset {a.hostname or a.ip} is in the DMZ",
                "high" if a.criticality == "high" else "critical", "real", "observed",
                f"Asset {a.hostname or a.ip} (criticality={a.criticality}) is a member of a "
                f"DMZ (public-facing) zone.",
                [a.hostname or a.ip],
                "Relocate the sensitive asset to an internal/crown-jewel zone behind the DMZ; "
                "expose only a minimal proxy in the DMZ.",
                affected_ids=[a.id],
            ))

    return out


# ── NAT / exposure ───────────────────────────────────────────────────────────
def detect_nat(engine: Engine, facts: NetworkFacts) -> list[dict]:
    out: list[dict] = []
    # compute the INTERNET blast radius once — it's independent of the asset loop.
    internet_reachable = blast_radius(engine, INTERNET)

    # (a) internal / crown-jewel asset directly exposed to the internet
    for a in facts.assets:
        if a.zone_kind in ("internal", "crown_jewel") and a.internet_facing:
            reachable_from_net = a.id in internet_reachable
            out.append(_finding(
                "NAT", f"exposed-internal-{a.ip}",
                f"Internal asset {a.hostname or a.ip} is exposed to the internet",
                _crit_severity(a) if a.criticality != "low" else "medium", "real", "observed",
                f"Asset {a.hostname or a.ip} sits in a '{a.zone_kind}' zone but is marked "
                f"internet-facing"
                + (" and is reachable from the INTERNET node in the graph." if reachable_from_net
                   else "."),
                [a.hostname or a.ip],
                "Remove the public route / port-forward; place the asset behind NAT and a "
                "reverse proxy or VPN, exposing only what is required.",
                affected_ids=[a.id],
            ))

    # (b) sensitive management/DB ports found OPEN by the real scan/inventory —
    # evidence-based, works without any zone topology (this is what surfaces on a
    # freshly-scanned real network).
    for a in facts.assets:
        for p in sorted(set(a.ports)):
            svc = _SENSITIVE_PORTS.get(p)
            if not svc:
                continue
            internet = a.internet_facing
            if not internet and p not in _LAN_FLAG_PORTS:
                continue  # e.g. SSH on a LAN host — expected, don't flag as a vuln
            is_db = p in _DB_PORTS
            if internet:
                severity = "critical" if is_db else "high"
                scope = "directly to the internet"
                where = "to the internet"
            else:
                severity = "high" if is_db else "medium"
                scope = "on the local network"
                where = "broadly on the LAN"
            out.append(_finding(
                "NAT", f"exposed-port-{a.ip}-{p}",
                f"{svc} port {p} exposed {'to the internet' if internet else 'on the LAN'} "
                f"— {a.hostname or a.ip}",
                severity, "real", "observed",
                f"The scan/inventory shows port {p}/{svc} open on {a.hostname or a.ip} ({scope}).",
                [a.hostname or a.ip],
                f"Restrict {svc} (port {p}) to a management VLAN or VPN and close it if unused; "
                f"never expose it {where}.",
                affected_ids=[a.id],
            ))

    # (c) declared port-forwards to sensitive management/DB ports
    if facts.port_forwards:
        for pf in facts.port_forwards:
            iport = pf.get("internal_port")
            if iport is None:
                # malformed entry (no internal port) — can't judge which service it
                # exposes, so skip it explicitly rather than silently swallowing it.
                continue
            svc = _SENSITIVE_PORTS.get(iport)
            target = facts.by_ip(pf.get("internal_ip", ""))
            if svc:
                out.append(_finding(
                    "NAT", f"forward-{pf.get('external_port')}-{pf.get('internal_ip')}",
                    f"Port-forward exposes {svc} ({iport}) on {pf.get('internal_ip')}",
                    # match direct-exposure severity: all DB ports (incl. 9200/ES)
                    # are critical, other sensitive mgmt ports high.
                    "critical" if iport in _DB_PORTS else "high",
                    "real", "declared",
                    f"Declared port-forward {pf.get('external_port')}→"
                    f"{pf.get('internal_ip')}:{iport}/{pf.get('proto','tcp')} exposes a "
                    f"{svc} management/database port directly to the internet.",
                    [pf.get("internal_ip", "")],
                    f"Remove this port-forward; reach {svc} over a VPN/bastion instead of a "
                    "public NAT mapping.",
                    affected_ids=[target.id] if target else [],
                ))
    else:
        # no port-forward table supplied → we cannot judge NAT mappings
        out.append(_finding(
            "NAT", "port-forwards-unknown",
            "Port-forward / NAT mapping table not available",
            "none", "unknown", "observed",
            "No gateway port-forward table was observed or declared, so exposed management "
            "ports via NAT cannot be assessed.",
            [],
            "Declare your gateway's port-forward entries (or export them) to enable this check.",
        ))

    # (d) NAT boundary posture — a live gateway means the LAN sits behind NAT.
    # If nothing internal is directly internet-exposed, that's a real healthy check.
    exposed = any(f["id"].startswith("NAT-exposed-") for f in out)
    if facts.gateway_ip and facts.has_device_inventory and not exposed:
        out.append(_finding(
            "NAT", "boundary-ok",
            "LAN is behind the gateway NAT boundary",
            "none", "passed", "observed",
            f"The live gateway ({facts.gateway_ip}) fronts a private subnet and no scanned host "
            "is directly exposed to the internet in the observed topology.",
            [facts.gateway_ip],
            "No action — keep inbound exposure limited to explicit, reviewed port-forwards.",
        ))

    return out


# ── DHCP ─────────────────────────────────────────────────────────────────────
def detect_dhcp(facts: NetworkFacts) -> list[dict]:
    out: list[dict] = []

    if not facts.dhcp_servers:
        out.append(_finding(
            "DHCP", "servers-unknown",
            "DHCP configuration not collected",
            "none", "unknown", "observed",
            "No DHCP responder was observed or declared, and no live gateway is known. "
            "Rogue-DHCP and snooping posture cannot be assessed without it.",
            [],
            "Run the device sweep (so the gateway is known) or declare your DHCP server(s) to "
            "enable this check.",
        ))
        return out

    servers = facts.dhcp_servers
    gw = facts.gateway_ip
    # provenance: an inferred (gateway) responder is OBSERVED, a listed one DECLARED
    src = "observed" if facts.dhcp_inferred else "declared"
    how = "observed on the live network" if facts.dhcp_inferred else "declared"

    if len(servers) > 1:
        out.append(_finding(
            "DHCP", "multiple-responders",
            "Multiple DHCP responders — possible rogue DHCP server",
            "high", "real", src,
            f"{len(servers)} DHCP responders {how} on the subnet: "
            f"{', '.join(servers)}. A subnet should normally have exactly one.",
            servers,
            "Identify and remove the unexpected DHCP server; enable DHCP snooping to block "
            "rogue responders at the switch.",
        ))
    elif len(servers) == 1 and gw and servers[0] != gw:
        out.append(_finding(
            "DHCP", "not-gateway",
            "DHCP server is not the network gateway",
            "medium", "real", src,
            f"The sole DHCP responder ({servers[0]}) differs from the known gateway ({gw}). "
            "Confirm this responder is authorized.",
            servers,
            "Verify the DHCP server is sanctioned; if not, disable it and let the gateway serve "
            "DHCP, or add it to the snooping trust list.",
        ))
    elif len(servers) == 1:
        out.append(_finding(
            "DHCP", "single-ok",
            "Single DHCP responder on the subnet"
            + (" (gateway)" if gw and servers[0] == gw else ""),
            "none", "passed", src,
            f"Exactly one DHCP responder {how} ({servers[0]})"
            + (f", matching the gateway ({gw}) — the expected posture." if gw and servers[0] == gw
               else "."),
            servers,
            "No action — a single authorized DHCP server is the expected posture. Enable DHCP "
            "snooping on switches to block rogue responders.",
        ))

    # DHCP snooping posture (only when explicitly declared)
    if facts.dhcp_snooping is False:
        out.append(_finding(
            "DHCP", "snooping-off",
            "DHCP snooping is disabled",
            "medium", "real", "declared",
            "Declared config indicates DHCP snooping is disabled, so the switch will not block "
            "rogue DHCP offers.",
            [],
            "Enable DHCP snooping on access switches and mark only the gateway/DHCP uplink as "
            "trusted.",
        ))
    elif facts.dhcp_snooping is True:
        out.append(_finding(
            "DHCP", "snooping-on",
            "DHCP snooping is enabled",
            "none", "passed", "declared",
            "Declared config indicates DHCP snooping is enabled.",
            [],
            "No action — snooping mitigates rogue DHCP.",
        ))

    return out


def run_all(engine: Engine, facts: NetworkFacts) -> list[dict]:
    return [*detect_dmz(engine, facts), *detect_nat(engine, facts), *detect_dhcp(facts)]
