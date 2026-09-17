# Drishti v0.1 — nmap XML parser | 12-Jul-2026
"""Parse real `nmap -sV -oX -` XML into structured host results.

Pure functions over the scanner's output — no fabrication. Only OPEN ports with
a real <state state="open"> are returned; a port nmap couldn't classify is
simply omitted, never invented. Handles single-host (`parse_nmap_xml`) and
multi-host / subnet (`parse_hosts`) output. Unit-tested against real-shaped
nmap XML."""
from __future__ import annotations

import xml.etree.ElementTree as ET


def _root(xml_text: str) -> ET.Element:
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError as exc:  # ParseError is a SyntaxError, not a ValueError
        raise ValueError(str(exc)) from exc


def _ipv4(host: ET.Element) -> str | None:
    for addr in host.findall("address"):
        if addr.get("addrtype") == "ipv4":
            return addr.get("addr")
    # fall back to any address (e.g. ipv6) if no ipv4
    a = host.find("address")
    return a.get("addr") if a is not None else None


def _parse_host(host: ET.Element) -> dict:
    """One <host> element → {ip, up, os, services:[...]}."""
    status = host.find("status")
    up = status is not None and status.get("state") == "up"

    services: list[dict] = []
    ports_el = host.find("ports")
    if ports_el is not None:
        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue  # skip closed/filtered — never present them as findings
            try:
                port_num = int(port.get("portid", "0"))
            except (TypeError, ValueError):
                continue
            protocol = port.get("protocol", "tcp")
            svc = port.find("service")
            name = (svc.get("name") if svc is not None else None) or "unknown"
            product = svc.get("product") if svc is not None else None
            version = svc.get("version") if svc is not None else None
            cpe = _first_app_cpe(svc)  # accurate product identifier for CVE matching
            services.append(
                {
                    "port": port_num,
                    "protocol": protocol,
                    "service_name": name,
                    "product": product or None,
                    "version": version or None,
                    "cpe": cpe,
                }
            )

    return {"ip": _ipv4(host), "up": up, "os": _first_os(host), "services": services}


def parse_nmap_xml(xml_text: str) -> dict:
    """Single-host convenience: {up, os, services}. Raises ValueError on bad XML."""
    root = _root(xml_text)
    host = root.find("host")
    if host is None:
        return {"up": False, "os": None, "services": []}
    parsed = _parse_host(host)
    return {"up": parsed["up"], "os": parsed["os"], "services": parsed["services"]}


def parse_hosts(xml_text: str) -> list[dict]:
    """All <host> elements → [{ip, up, os, services}]. Raises ValueError on bad XML."""
    root = _root(xml_text)
    return [_parse_host(h) for h in root.findall("host")]


def parse_live_ips(xml_text: str) -> list[str]:
    """Host-discovery (`nmap -sn`) output → list of IPs that responded 'up'."""
    root = _root(xml_text)
    ips: list[str] = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") == "up":
            ip = _ipv4(h)
            if ip:
                ips.append(ip)
    return ips


def _first_app_cpe(svc: ET.Element | None) -> str | None:
    """The service's application CPE (cpe:/a:vendor:product), if nmap emitted one.
    This is the precise identifier we match CVEs against — far more accurate than
    the free-text product name."""
    if svc is None:
        return None
    for c in svc.findall("cpe"):
        text = (c.text or "").strip()
        if text.startswith("cpe:/a:") or text.startswith("cpe:2.3:a:"):
            return text
    return None


def _first_os(host: ET.Element) -> str | None:
    """Best-effort OS name from an <os> block (only present with `-O`/root)."""
    os_el = host.find("os")
    if os_el is None:
        return None
    match = os_el.find("osmatch")
    if match is not None and match.get("name"):
        return match.get("name")
    return None
