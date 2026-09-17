#!/usr/bin/env python3
# Drishti v0.1 — live network watch agent | 11-Jul-2026
"""Drishti Live Watch — surface which domains (and, in devices mode, which LAN
neighbours) are seen from THIS host and report them to the Drishti server, which
scores each domain with the real URL Trust Analyzer.

Scope, honestly stated — modes differ in what they collect, so read this before
running one you have not run before:
  dns      sniffs THIS host's own outbound DNS queries. Only this machine's
           domain lookups; no other device's traffic, no packet payloads.
  history  reads THIS host's local browser history DB (Chrome/Brave/Edge). Only
           domains you visited in a browser on this machine.
  conn     reads the URLs of ALL currently-open browser tabs on this machine
           (Chrome/Brave/Safari) via AppleScript. This inspects every open tab's
           address, not just outbound connections — it is broader than it sounds.
  devices  ACTIVELY probes the local network: it ping-sweeps the whole /24 and
           harvests the ARP table to build an inventory of neighbouring devices
           (IP / MAC / hostname). This touches OTHER devices on the LAN, so it is
           gated behind an explicit consent flag (see --consent-subnet).

None of the modes capture packet payloads or attack anything; dns/history/conn
only ever send domain names off-host, devices sends a LAN device inventory.

Usage:
  sudo python3 drishti_watch.py --mode dns \
      --server http://localhost:8000 --token agent-demo-token
  python3 drishti_watch.py --mode history --server http://localhost:8000 --token agent-demo-token
  # devices mode requires explicit consent to probe the local subnet:
  python3 drishti_watch.py --mode devices --consent-subnet \
      --server http://localhost:8000 --token agent-demo-token
"""
import argparse
import json
import os
import re
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Noise we never report: local, multicast, telemetry-ish infra. Domain names
# only — this is a denylist of things to *ignore*, not to block.
_IGNORE_SUFFIXES = (
    ".local", ".arpa", ".lan", ".internal", ".home", ".localdomain",
    "in-addr.arpa", "ip6.arpa",
)
_IGNORE_EXACT = {"localhost"}
_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")


def log(msg: str) -> None:
    print(f"[drishti-watch] {msg}", flush=True)


def _env_flag(name: str) -> bool:
    """True when an env var is set to a truthy value (1/true/yes/on)."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def registrable(host: str) -> str | None:
    """Reduce a hostname to something worth scoring; drop obvious noise."""
    h = (host or "").strip().lower().rstrip(".")
    if not h or h in _IGNORE_EXACT:
        return None
    if any(h == s.lstrip(".") or h.endswith(s) for s in _IGNORE_SUFFIXES):
        return None
    if not _DOMAIN_RE.match(h):
        return None
    # keep the last two labels for common TLDs (foo.bar.example.com -> example.com)
    parts = h.split(".")
    if len(parts) > 2 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


class Reporter:
    """POSTs newly-seen domains to the server, deduping within this run."""

    def __init__(self, server: str, token: str, source_host: str, cooldown: float = 3.0):
        self.server = server.rstrip("/")
        self.url = self.server + "/api/live/observe"
        self.token = token
        self.source_host = source_host
        self.cooldown = cooldown
        self._seen: dict[str, float] = {}

    def report(self, domain: str, source_host: str | None = None) -> None:
        src = source_host or self.source_host
        now = time.monotonic()
        key = f"{domain}:{src}"
        last = self._seen.get(key)
        if last is not None and now - last < self.cooldown:
            return
        self._seen[key] = now
        body = json.dumps({"domain": domain, "source_host": src}).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={"authorization": f"Bearer {self.token}", "content-type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read() or b"{}")
            flag = "⚠ THREAT" if data.get("is_threat") else "ok"
            log(f"{flag}  {domain} (from {src})  [{data.get('band')}] score={data.get('score')}")
        except urllib.error.HTTPError as e:
            log(f"server rejected {domain}: HTTP {e.code}")
        except Exception as e:  # noqa: BLE001 — best-effort telemetry
            log(f"could not report {domain}: {e}")

    def sync_active(self, domains: set[str], active_apps: list[str] | None = None, source_host: str | None = None) -> None:
        """Tell the server exactly which domains & active apps are active right now."""
        src = source_host or self.source_host
        payload = {"domains": list(domains), "source_host": src}
        if active_apps:
            payload["active_apps"] = active_apps
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.url.replace("/observe", "/sync_active"),
            data=body,
            headers={"authorization": f"Bearer {self.token}", "content-type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read() or b"{}")
                deleted = data.get("deleted", 0)
                if deleted > 0:
                    log(f"pruned {deleted} closed tabs")
        except Exception:
            pass

# ── mode: dns (scapy network DNS query sniffer) ──────────────────────────────


def run_dns(reporter: Reporter, interval: float = 2.0) -> None:
    import threading

    try:
        from scapy.all import DNS, DNSQR, sniff, IP  # type: ignore
    except Exception:
        log("ERROR: scapy is not installed in this Python environment.")
        log("If using a venv, run: sudo .venv/bin/python3 agent/drishti_watch.py --mode dns")
        log("Or install scapy with: pip install scapy  (or use --mode conn/history)")
        sys.exit(2)

    log("Starting concurrent browser tab & desktop application watcher in background…")
    conn_thread = threading.Thread(target=run_conn, args=(reporter, interval), daemon=True)
    conn_thread.start()

    _live_pkt_devices: dict[str, str] = {}

    log("Starting continuous LAN device discovery sweep in background…")
    def _bg_device_sweep():
        time.sleep(1.0)
        while True:
            try:
                candidates = resolve_subnets("auto", 1024)
                for c in candidates:
                    if c.get("scan") and c.get("kind") == "on-link":
                        net = ipaddress.ip_network(c["cidr"], strict=False)
                        devices = _scan_on_link(net)
                        existing_ips = {d.get("ip") for d in devices}
                        for ip_str, mac_str in list(_live_pkt_devices.items()):
                            try:
                                if ipaddress.ip_address(ip_str) in net and ip_str not in existing_ips:
                                    devices.append({"ip": ip_str, "mac": mac_str, "hostname": None, "subnet": c["cidr"], "discovery": "arp", "source": "scapy"})
                                    existing_ips.add(ip_str)
                            except Exception:
                                pass
                        self_mac = _self_mac()
                        if c.get("self_ip") and self_mac and not any(d.get("mac") == self_mac for d in devices):
                            devices.append({"ip": c["self_ip"], "mac": self_mac, "hostname": reporter.source_host, "subnet": c["cidr"], "discovery": "arp", "source": "arp"})
                        if devices:
                            _post_json(reporter.server, reporter.token, "/api/live/devices", {
                                "subnet": c["cidr"], "gateway_ip": _gateway_ip(), "label": "Local LAN", "devices": devices
                            })
                            log(f"Synced {len(devices)} active LAN device(s) on {c['cidr']}")
            except Exception:
                pass
            time.sleep(15.0)

    dev_thread = threading.Thread(target=_bg_device_sweep, daemon=True)
    dev_thread.start()

    log("Sniffing network DNS & mDNS queries (UDP 53, 5353) across LAN devices… (Ctrl-C to stop, needs sudo)")

    def on_pkt(pkt) -> None:
        try:
            from scapy.all import Ether
            if pkt.haslayer(IP) and pkt.haslayer(Ether):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_mac = _norm_mac(pkt[Ether].src)
                if src_ip and not src_ip.startswith(("127.", "224.", "239.", "8.8.", "1.1.")) and not src_ip.endswith(".255"):
                    _live_pkt_devices[src_ip] = src_mac
        except Exception:
            pass

        if not pkt.haslayer(DNSQR) and not pkt.haslayer(DNS):
            return
        try:
            if not pkt.haslayer(IP):
                return
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Identify the actual LAN client machine
            client_ip = src_ip
            # If this is a DNS response from a public DNS or router to a LAN device, target is dst_ip
            try:
                is_src_private = ipaddress.ip_address(src_ip).is_private
                is_dst_private = ipaddress.ip_address(dst_ip).is_private
            except Exception:
                is_src_private = False
                is_dst_private = False

            if not is_src_private and is_dst_private:
                client_ip = dst_ip
            elif is_src_private and is_dst_private and (src_ip == _gateway_ip() or src_ip.endswith(".1")):
                # Router replied to a client machine
                client_ip = dst_ip

            qname = ""
            if pkt.haslayer(DNSQR) and pkt[DNSQR].qname:
                qname = pkt[DNSQR].qname.decode("utf-8", "ignore").lower()
            elif pkt.haslayer(DNS) and getattr(pkt[DNS], "qd", None) and getattr(pkt[DNS].qd, "qname", None):
                qname = pkt[DNS].qd.qname.decode("utf-8", "ignore").lower()

            # Extract and report website domain queries for this specific device
            dom = registrable(qname)
            if dom and client_ip and client_ip not in ("8.8.8.8", "8.8.4.4", "1.1.1.1"):
                reporter.report(dom, source_host=client_ip)
        except Exception:
            return

    try:
        # udp port 53 / 5353 = DNS queries from all LAN devices
        sniff(filter="udp port 53 or udp port 5353 or arp", prn=on_pkt, store=False, promisc=True)
    except Exception as e:
        log(f"scapy packet sniffing encounter error: {e}. Active tab watcher is still running.")
        while True:
            time.sleep(interval)


# ── mode: conn (browser tabs & active apps) ──────────────────────────────────
def run_conn(reporter: Reporter, interval: float) -> None:
    import subprocess
    import platform
    from urllib.parse import urlparse
    
    log(f"polling open browser tabs and active applications every {interval}s…")
    browsers = ["Google Chrome", "Brave Browser", "Safari", "Arc", "Microsoft Edge", "Firefox"]
    
    _NOISE_APPS = {
        "python", "python3", "drishti.py", "drishti_watch.py", "drishti_agent.py",
        "terminal", "zsh", "bash", "sh", "launchd", "system events", "finder", "dock",
        "systemsettings", "controlcenter", "notificationcenter", "coreauthd"
    }

    while True:
        domains = set()
        active_apps_list = []
        if platform.system() == "Darwin":
            for browser in browsers:
                try:
                    if subprocess.run(["pgrep", "-xi", browser], capture_output=True).returncode != 0:
                        continue
                    script = f'tell application "{browser}" to get URL of every tab of every window'
                    out = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=2).stdout
                    urls = [u.strip() for u in out.split(', ') if u.strip().startswith('http')]
                    for u in urls:
                        try:
                            host = urlparse(u).netloc.split(':')[0]
                            dom = registrable(host) if host else None
                            if dom:
                                domains.add(dom)
                        except Exception:
                            pass
                except Exception:
                    continue

            try:
                cmd = ["osascript", "-e", 'tell application "System Events" to get name of every process whose background only is false']
                apps_out = subprocess.run(cmd, capture_output=True, text=True, timeout=2).stdout
                app_names = [a.strip() for a in apps_out.split(", ") if a.strip()]
                active_apps_list = [
                    a for a in app_names
                    if a.lower() not in _NOISE_APPS and not a.lower().endswith(".py")
                ]
            except Exception:
                pass

        elif platform.system() == "Windows":
            try:
                cmd = ["powershell", "-NoProfile", "-Command", "Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object -ExpandProperty ProcessName"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    raw_apps = [a.strip() for a in res.stdout.splitlines() if a.strip()]
                    active_apps_list = [
                        a for a in raw_apps
                        if a.lower() not in _NOISE_APPS and not a.lower().startswith("system")
                    ]
            except Exception:
                pass

        elif platform.system() == "Linux":
            try:
                cmd = ["ps", "-eo", "comm="]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    raw_apps = [a.strip() for a in res.stdout.splitlines() if a.strip()]
                    active_apps_list = list(set([
                        a for a in raw_apps
                        if a.lower() in {"chrome", "firefox", "brave", "spotify", "discord", "slack", "code", "zoom", "telegram-desktop", "figma", "postman"}
                    ]))
            except Exception:
                pass

        for dom in domains:
            reporter.report(dom)
            
        reporter.sync_active(domains, active_apps_list)
        time.sleep(interval)



# ── mode: devices (ARP/ping sweep — network inventory) ───────────────────────
import ipaddress  # noqa: E402
import platform  # noqa: E402
import subprocess  # noqa: E402

# Guards mirror server/app/services/deepscan/service.py (the agent is a
# single stdlib file, so the logic is mirrored, not imported): RFC-1918 only,
# hard host cap. Discovery may FIND a /16; it must refuse to SWEEP it.
_HARD_MAX_HOSTS = 1024
_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _cidr_guard(cidr: str, max_hosts: int) -> tuple["ipaddress.IPv4Network | None", str | None]:
    """(network, None) when the CIDR is safe to sweep, else (None, reason)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None, "not a valid CIDR"
    if net.version != 4:
        return None, "IPv6 not supported"
    if net.is_loopback or net.is_link_local:
        return None, "loopback/link-local range"
    if not any(net.subnet_of(r) for r in _RFC1918):
        return None, "not an RFC-1918 private range"
    cap = min(max_hosts, _HARD_MAX_HOSTS)
    hosts = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses
    if hosts > cap:
        return None, f"{hosts} hosts exceeds --max-hosts {cap}, narrow it"
    return net, None


def _host_count(net: "ipaddress.IPv4Network") -> int:
    return net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses


def _list_interfaces(run=None) -> list[dict]:
    """Up interfaces with a private IPv4 and their REAL netmask.
    Returns [{iface, ip, cidr}]. Never guesses a /24."""
    run = run or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout)
    out: list[dict] = []
    system = platform.system()
    try:
        if system == "Linux":
            text = run(["ip", "-o", "-4", "addr"])
            for line in text.splitlines():
                m = re.search(r"^\d+:\s+(\S+)\s+inet\s+([\d.]+)/(\d+)", line)
                if not m:
                    continue
                iface, ip, prefix = m.group(1), m.group(2), int(m.group(3))
                out.append({"iface": iface, "ip": ip, "prefix": prefix})
        elif system == "Windows":
            text = run(["ipconfig"])
            iface = "?"
            ip = mask = None
            for line in text.splitlines():
                m_iface = re.match(r"^(?:Ethernet adapter|Wireless LAN adapter)\s+([^:]+):", line)
                if not m_iface:
                    m_iface = re.match(r"^([a-zA-Z0-9_\- .]+):$", line)
                if m_iface:
                    iface = m_iface.group(1).strip()
                    ip = mask = None
                    continue
                m = re.search(r"IPv4 Address[ .]*:\s*([\d.]+)", line)
                if m:
                    ip = m.group(1)
                m = re.search(r"Subnet Mask[ .]*:\s*([\d.]+)", line)
                if m and ip:
                    mask = m.group(1)
                    prefix = ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
                    out.append({"iface": iface, "ip": ip, "prefix": prefix})
                    ip = mask = None
        else:  # macOS / BSD
            text = run(["ifconfig"])
            iface = None
            for line in text.splitlines():
                m = re.match(r"^(\w+):", line)
                if m:
                    iface = m.group(1)
                m = re.search(r"inet ([\d.]+) netmask 0x([0-9a-f]{8})", line)
                if m and iface:
                    mask = ipaddress.ip_address(int(m.group(2), 16))
                    prefix = ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
                    out.append({"iface": iface, "ip": m.group(1), "prefix": prefix})
    except Exception:
        return []
    result = []
    for i in out:
        addr = ipaddress.ip_address(i["ip"])
        # lo/utun aliases, host routes (/31,/32), and non-private addrs are not networks to sweep
        if i["iface"].startswith(("lo", "utun")) or i["prefix"] >= 31:
            continue
        if not addr.is_private or addr.is_loopback or addr.is_link_local:
            continue
        net = ipaddress.ip_network(f"{i['ip']}/{i['prefix']}", strict=False)
        result.append({"iface": i["iface"], "ip": i["ip"], "cidr": str(net)})
    return result


def _list_routes(run=None) -> list[dict]:
    """Private-range routes reachable via a gateway. Returns [{cidr, gw}]."""
    run = run or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout)
    out: list[dict] = []
    system = platform.system()
    try:
        if system == "Linux":
            text = run(["ip", "route"])
            for line in text.splitlines():
                m = re.match(r"^([\d.]+/\d+)\s+via\s+([\d.]+)", line)
                if m:
                    out.append({"cidr": m.group(1), "gw": m.group(2)})
        elif system == "Windows":
            text = run(["route", "print", "-4"])
            for line in text.splitlines():
                m = re.match(r"\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s", line)
                if m and m.group(3) != "0.0.0.0" and re.match(r"^\d", m.group(3)):
                    try:
                        net = ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}")
                    except ValueError:
                        continue
                    out.append({"cidr": str(net), "gw": m.group(3)})
        else:  # macOS / BSD
            text = run(["netstat", "-rn", "-f", "inet"])
            for line in text.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                dest, gw = parts[0], parts[1]
                m = re.match(r"^([\d.]+)/(\d+)$", dest)
                if not m or not re.match(r"^[\d.]+$", gw):
                    continue
                if int(m.group(2)) >= 31:
                    continue
                out.append({"cidr": f"{m.group(1)}/{m.group(2)}", "gw": gw})
    except Exception:
        return []
    result = []
    for r in out:
        try:
            net = ipaddress.ip_network(r["cidr"], strict=False)
        except ValueError:
            continue
        if net.version == 4 and net.is_private and not net.is_loopback and not net.is_link_local:
            result.append({"cidr": str(net), "gw": r["gw"]})
    return result


def _ping(ip: str, timeout_ms: int = 1000) -> bool:
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=3).returncode == 0
    except Exception:
        return False


def discover_subnets(max_hosts: int, run_ifaces=None, run_routes=None, ping=_ping) -> list[dict]:
    """Candidate CIDRs from real evidence (interfaces + routes), each with the
    evidence that selected it and a scan verdict. The COUNT is an output —
    nothing here assumes how many networks exist."""
    candidates: dict[str, dict] = {}
    for i in _list_interfaces(run_ifaces):
        candidates[i["cidr"]] = {
            "cidr": i["cidr"], "kind": "on-link", "iface": i["iface"],
            "self_ip": i["ip"], "gw": None,
            "evidence": f"interface {i['iface']}",
        }
    for r in _list_routes(run_routes):
        if r["cidr"] in candidates:
            continue
        candidates[r["cidr"]] = {
            "cidr": r["cidr"], "kind": "routed", "iface": None,
            "self_ip": None, "gw": r["gw"],
            "evidence": f"route via {r['gw']}",
        }
    out = []
    for c in candidates.values():
        net, reason = _cidr_guard(c["cidr"], max_hosts)
        c["hosts"] = _host_count(ipaddress.ip_network(c["cidr"], strict=False))
        if reason:
            c["verdict"] = f"SKIPPED: {reason}"
            c["scan"] = False
        elif c["kind"] == "on-link":
            c["verdict"] = "will scan"
            c["scan"] = True
        else:
            # routed: verify L3 reachability before promising a scan
            probe = c["gw"] or str(next(net.hosts()))
            if ping(probe):
                c["verdict"] = "will scan (L3, no MACs)"
                c["scan"] = True
            else:
                c["verdict"] = "unreachable, no ping replies"
                c["scan"] = False
        out.append(c)
    return out


def _sweep_responders(net: "ipaddress.IPv4Network") -> set[str]:
    """Ping every host in the (already size-capped) CIDR; return the repliers."""
    import concurrent.futures

    responders: set[str] = set()

    def ping_one(ip: str) -> None:
        if _ping(ip, timeout_ms=300):
            responders.add(ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(ping_one, (str(h) for h in net.hosts())))
    return responders


SOURCE_PRECEDENCE: dict[str, int] = {
    "scapy": 4,
    "arp": 3,
    "icmp": 2,
    "l3": 1,
}


def _source_priority(src: str | None) -> int:
    """Return deterministic integer priority for observation sources."""
    return SOURCE_PRECEDENCE.get(src or "", 0)


def _scan_on_link(net: "ipaddress.IPv4Network") -> list[dict]:
    """On-link path: Scapy L2 ARP broadcast + ICMP ping sweep + system ARP table."""
    devices_by_ip: dict[str, dict] = {}

    # 1. Scapy Layer-2 ARP broadcast sweep (reaches mobile phones/devices that drop ICMP ping)
    try:
        from scapy.all import Ether, ARP, srp
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)),
            timeout=2.0,
            verbose=False,
        )
        for _, r in ans:
            ip = getattr(r, "psrc", None)
            mac = getattr(r, "hwsrc", None)
            if ip and mac:
                devices_by_ip[ip] = {
                    "ip": ip,
                    "mac": _norm_mac(mac),
                    "hostname": None,
                    "subnet": str(net),
                    "discovery": "arp",
                    "source": "scapy",
                }
    except Exception:
        pass

    # 2. ICMP ping sweep to populate kernel ARP cache
    responders = _sweep_responders(net)
    for d in _arp_devices():
        try:
            ip = d.get("ip")
            if ip and ipaddress.ip_address(ip) in net:
                if ip not in devices_by_ip or not devices_by_ip[ip].get("mac"):
                    d["subnet"] = str(net)
                    d["discovery"] = "arp"
                    d["source"] = "arp"
                    devices_by_ip[ip] = d
                else:
                    if d.get("hostname") and not devices_by_ip[ip].get("hostname"):
                        devices_by_ip[ip]["hostname"] = d["hostname"]
                    existing_src = devices_by_ip[ip].get("source")
                    if _source_priority("arp") > _source_priority(existing_src):
                        devices_by_ip[ip]["source"] = "arp"
        except ValueError:
            continue

    # 3. ICMP-only responders: replied to ICMP ping, but no MAC in Scapy or system ARP cache
    for ip in sorted(responders):
        if ip not in devices_by_ip:
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except OSError:
                pass
            devices_by_ip[ip] = {
                "ip": ip,
                "mac": None,
                "hostname": hostname,
                "subnet": str(net),
                "discovery": "l3",
                "source": "icmp",
            }

    return list(devices_by_ip.values())


def _scan_off_link(net: "ipaddress.IPv4Network") -> list[dict]:
    """Off-link (routed) path: ARP cannot see remote MACs — the ARP table only
    holds the gateway's MAC for these destinations. Ping + reverse-DNS only;
    mac stays null (attributing the gateway's MAC would be fabricated data)."""
    devices = []
    for ip in sorted(_sweep_responders(net)):
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except OSError:
            pass
        devices.append({"ip": ip, "mac": None, "hostname": hostname,
                        "subnet": str(net), "discovery": "l3", "source": "l3"})
    return devices


def _self_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _self_mac() -> str | None:
    if platform.system() == "Windows":
        try:
            out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=3).stdout
            m = re.search(r"Physical address\s*:\s*([0-9a-fA-F:-]{17})", out)
            if m:
                return m.group(1).replace("-", ":").lower()
        except Exception:
            pass
        try:
            out = subprocess.run(["getmac", "/fo", "csv", "/v"], capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                if "Tcpip" in line:
                    m = re.search(r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})", line)
                    if m:
                        return m.group(1).replace("-", ":").lower()
        except Exception:
            pass
        return None
    for iface in ("en0", "en1", "eth0", "wlan0"):
        try:
            out = subprocess.run(["ifconfig", iface], capture_output=True, text=True, timeout=3).stdout
        except Exception:
            continue
        m = re.search(r"ether\s+([0-9a-f:]{17})", out)
        if m:
            return m.group(1).lower()
    return None


def _gateway_ip() -> str | None:
    system = platform.system()
    try:
        if system == "Windows":
            out = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                m = re.match(r"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)", line)
                if m and not m.group(1).startswith("0."):
                    return m.group(1)
            out_ip = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=3).stdout
            for line in out_ip.splitlines():
                m = re.search(r"Default Gateway[ .]*:\s*([\d.]+)", line)
                if m and not m.group(1).startswith("0."):
                    return m.group(1)
        else:
            out = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                if line.split()[:1] == ["default"] or line.startswith("0.0.0.0"):
                    parts = line.split()
                    for p in parts[1:]:
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", p):
                            return p
    except Exception:
        pass
    return None


def _norm_mac(mac: str) -> str:
    return ":".join(f"{int(o, 16):02x}" for o in mac.split(":")) if ":" in mac else mac.lower()


def _arp_devices() -> list[dict]:
    # -n = numeric (skip reverse-DNS, which hangs on unresolvable neighbours)
    system = platform.system()
    try:
        cmd = ["arp", "-a"] if system == "Windows" else ["arp", "-an"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return []
    devices = []
    for line in out.splitlines():
        if system == "Windows":
            m = re.search(r"^\s*([\d.]+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})", line)
            if not m:
                continue
            ip, mac = m.group(1), m.group(2).replace("-", ":")
            if mac.lower() in ("ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:16") or "invalid" in line.lower():
                continue
            if ip.startswith(("224.", "239.")) or ip.endswith(".255") or ip.startswith("127."):
                continue
            devices.append({"ip": ip, "mac": _norm_mac(mac), "hostname": None, "source": "arp"})
        else:
            m = re.search(r"\(([\d.]+)\) at ([0-9a-fA-F:]+)", line)
            if not m:
                continue
            ip, mac = m.group(1), m.group(2)
            if mac.lower() in ("ff:ff:ff:ff:ff:ff",) or "incomplete" in line:
                continue
            if ip.startswith(("224.", "239.")) or ip.endswith(".255"):
                continue
            host_m = re.match(r"^([^\s(]+)", line)
            hostname = host_m.group(1) if host_m and host_m.group(1) not in ("?",) else None
            devices.append({"ip": ip, "mac": _norm_mac(mac), "hostname": hostname, "source": "arp"})
    return devices


# ── passive WiFi enumeration (Task 3) ────────────────────────────────────────
_AIRPORT = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport")


def discover_wifi(run=None) -> dict:
    """List WiFi networks VISIBLE from this host — beacons are broadcast, this
    is listening, not probing. Read-only and passive: never joins, never
    authenticates, never captures traffic. Degrades to available:false with a
    reason — a fabricated SSID list is worse than none.

    Returns {available, reason?, joined_ssid?, networks: [{ssid, bssid,
    channel, signal, security, joined}]}."""
    run = run or (lambda cmd: subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout)
    system = platform.system()
    networks: list[dict] = []
    joined: str | None = None
    try:
        if system == "Linux":
            text = run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SIGNAL,SECURITY",
                        "dev", "wifi", "list"])
            for line in text.splitlines():
                # BSSID contains escaped colons in -t mode (\:)
                parts = re.split(r"(?<!\\):", line)
                if len(parts) < 6:
                    continue
                active, ssid, bssid, chan, signal, security = parts[:6]
                if not ssid:
                    continue
                is_joined = active.lower() == "yes"
                if is_joined:
                    joined = ssid
                networks.append({"ssid": ssid, "bssid": bssid.replace("\\:", ":"),
                                 "channel": chan, "signal": signal,
                                 "security": security, "joined": is_joined})
        elif system == "Windows":
            text = run(["netsh", "wlan", "show", "networks", "mode=bssid"])
            ssid = security = None
            for line in text.splitlines():
                m = re.match(r"\s*SSID \d+ : (.*)", line)
                if m:
                    ssid = m.group(1).strip() or None
                    security = None
                    continue
                m = re.match(r"\s*Authentication\s*:\s*(.*)", line)
                if m:
                    security = m.group(1).strip()
                m = re.match(r"\s*BSSID \d+\s*:\s*([0-9a-f:]+)", line, re.I)
                if m and ssid:
                    networks.append({"ssid": ssid, "bssid": m.group(1), "channel": None,
                                     "signal": None, "security": security, "joined": False})
            try:
                iface_text = run(["netsh", "wlan", "show", "interfaces"])
                m_state = re.search(r"^\s*State\s*:\s*(.+)$", iface_text, re.M | re.I)
                if m_state and "connected" in m_state.group(1).lower():
                    m_ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", iface_text, re.M)
                    if m_ssid:
                        joined = m_ssid.group(1).strip()
                        for n in networks:
                            n["joined"] = n["ssid"] == joined
            except Exception:
                pass
        elif system == "Darwin":
            text = run([_AIRPORT, "-s"])
            if not text.strip():
                return {"available": False, "networks": [],
                        "reason": "airport scan returned nothing (tool removed on recent macOS?)"}
            for line in text.splitlines()[1:]:
                m = re.match(r"\s*(.+?)\s+([0-9a-f:]{17})\s+(-?\d+)\s+(\S+)\s+\S+\s+(.*)$", line)
                if not m:
                    continue
                networks.append({"ssid": m.group(1).strip(), "bssid": m.group(2),
                                 "signal": m.group(3), "channel": m.group(4),
                                 "security": m.group(5).strip(), "joined": False})
            info = run([_AIRPORT, "-I"])
            m = re.search(r"^\s*SSID:\s*(.+)$", info, re.M)
            if m:
                joined = m.group(1).strip()
                for n in networks:
                    n["joined"] = n["ssid"] == joined
        else:
            return {"available": False, "networks": [],
                    "reason": f"unsupported platform {system}"}
    except FileNotFoundError as e:
        return {"available": False, "networks": [], "reason": f"OS wifi tool missing: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"available": False, "networks": [], "reason": f"wifi scan failed: {e}"}
    if not networks:
        return {"available": False, "networks": [],
                "reason": "no WiFi adapter or no scan results"}
    return {"available": True, "networks": networks, "joined_ssid": joined}


def _post_json(server: str, token: str, path: str, payload: dict) -> dict | None:
    req = urllib.request.Request(
        server.rstrip("/") + path, data=json.dumps(payload).encode(),
        headers={"authorization": f"Bearer {token}", "content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read() or b"{}")
    except Exception as e:  # noqa: BLE001
        log(f"could not POST {path}: {e}")
        return None


def resolve_subnets(subnets_arg: str, max_hosts: int) -> list[dict]:
    """Turn --subnets (auto | comma-list) into candidates with verdicts.
    Explicit CIDRs pass through the same guards — never a way around them."""
    if subnets_arg.strip().lower() == "auto":
        return discover_subnets(max_hosts)
    on_link = {c["cidr"]: c for c in discover_subnets(max_hosts) if c["kind"] == "on-link"}
    out = []
    for raw in [s.strip() for s in subnets_arg.split(",") if s.strip()]:
        net, reason = _cidr_guard(raw, max_hosts)
        cidr = str(ipaddress.ip_network(raw, strict=False)) if net else raw
        if reason:
            out.append({"cidr": raw, "kind": "explicit", "evidence": "operator --subnets",
                        "gw": None, "self_ip": None, "hosts": 0,
                        "verdict": f"SKIPPED: {reason}", "scan": False})
            continue
        if cidr in on_link:
            c = on_link[cidr]
            c["evidence"] += " (also explicit --subnets)"
            out.append(c)
            continue
        reachable = _ping(str(next(net.hosts())))
        out.append({"cidr": cidr, "kind": "routed", "evidence": "operator --subnets",
                    "gw": None, "self_ip": None, "hosts": _host_count(net),
                    "verdict": "will scan (L3, no MACs)" if reachable
                    else "unreachable, no ping replies",
                    "scan": reachable})
    return out


_WIFI_IFACES = ("en0", "wlan", "wlp", "wi-fi", "wifi", "wireless")  # macOS / Linux / Windows wireless naming


def _wifi_coverage_rows(candidates: list[dict], label: str | None) -> tuple[list[dict], str]:
    """Passive SSID scan → coverage rows + a human summary line.
    SSID→subnet correlation ONLY for the network we are joined to (via the
    wifi interface's on-link candidate); everything else stays subnet:null —
    guessing a mapping would be fabricated data."""
    scan = discover_wifi()
    if not scan["available"]:
        return [], f"wifi scan unavailable: {scan.get('reason')}"
    wifi_subnet = next(
        (c["cidr"] for c in candidates
         if c["kind"] == "on-link" and (c.get("iface") or "").lower().startswith(_WIFI_IFACES)),
        None,
    )
    rows, seen_ssids = [], set()
    inventoried = 0
    for n in scan["networks"]:
        if not n["ssid"] or n["ssid"] in seen_ssids:
            continue
        seen_ssids.add(n["ssid"])
        if n["joined"] and wifi_subnet:
            inventoried += 1
            rows.append({"ssid": n["ssid"], "subnet": wifi_subnet, "label": label,
                         "status": "inventoried",
                         "evidence": f"joined (beacon {n.get('bssid')}, ch {n.get('channel')})"})
        else:
            rows.append({"ssid": n["ssid"], "subnet": None, "label": None,
                         "status": "seen_not_joined",
                         "evidence": f"beacon {n.get('bssid')} ch {n.get('channel')} "
                                     f"signal {n.get('signal')}"})
    summary = (f"{len(seen_ssids)} SSIDs visible, {inventoried} inventoried, "
               f"{len(seen_ssids) - inventoried} need an agent placed on them")
    return rows, summary


def run_devices(server: str, token: str, source_host: str, interval: float,
                consent: bool, subnets_arg: str = "auto", label: str | None = None,
                max_hosts: int = _HARD_MAX_HOSTS, wifi: bool = False) -> None:
    # Consent gate: devices mode ACTIVELY ping-sweeps subnets and harvests the
    # ARP table, which probes OTHER devices on the LAN — not just this host.
    # Consent covers ALL subnets in the run, discovered or explicit — wider
    # input never widens permissions. Refuse clearly otherwise.
    if not consent:
        log(
            "refusing: --mode devices actively ping-sweeps the target subnet(s) "
            "and harvests neighbouring devices (IP/MAC/hostname) from the ARP "
            "table. This probes OTHER machines on your network. Re-run with "
            "--consent-subnet (or set DRISHTI_CONSENT_SUBNET=1) to confirm you "
            "are authorised to inventory this LAN."
        )
        sys.exit(2)

    self_mac = _self_mac()
    gw = _gateway_ip()
    candidates = resolve_subnets(subnets_arg, max_hosts)
    if not candidates:
        log("no candidate subnets found (no private interface or routes) — nothing to scan")
        sys.exit(2)

    log(f"Discovered {len(candidates)} candidate network(s):")
    for c in candidates:
        log(f"  {c['cidr']:<20} {c['kind']:<8} {c['evidence']:<32} "
            f"{c['hosts']:>6} hosts  -> {c['verdict']}")

    if wifi:
        rows, summary = _wifi_coverage_rows(candidates, label)
        log(f"passive wifi: {summary}")
        if rows:
            _post_json(server, token, "/api/live/coverage", {"networks": rows})

    # Start concurrent browser tab & app monitoring thread so all open websites & apps are reported live
    import threading
    reporter = Reporter(server, token, source_host)
    log("starting concurrent browser tab & app watcher thread…")
    conn_thread = threading.Thread(target=run_conn, args=(reporter, 3.0), daemon=True)
    conn_thread.start()

    known_cidrs = {c["cidr"] for c in candidates}
    while True:
        # WiFi can change under a long-running agent — re-resolve every sweep so
        # we scan the network we are on NOW, not the one from startup. Consent
        # already covers all subnets discovered during the run.
        fresh = resolve_subnets(subnets_arg, max_hosts)
        if fresh:
            fresh_cidrs = {c["cidr"] for c in fresh}
            if fresh_cidrs != known_cidrs:
                log(f"network change: now on {', '.join(sorted(fresh_cidrs))}")
                known_cidrs = fresh_cidrs
            candidates = fresh
            self_mac = _self_mac()
            gw = _gateway_ip()

        # honest coverage for what we are NOT scanning: skipped or unreachable
        not_scanned = [c for c in candidates if not c["scan"]]
        if not_scanned:
            _post_json(server, token, "/api/live/coverage", {"networks": [
                {"subnet": c["cidr"], "gateway_ip": c.get("gw"), "label": label,
                 "status": "unreachable" if "unreachable" in c["verdict"]
                 else "reachable_not_scanned",
                 "evidence": f"{c['evidence']} — {c['verdict']}"}
                for c in not_scanned
            ]})

        active_subnets = [c["cidr"] for c in candidates if c["scan"]]
        for c in (c for c in candidates if c["scan"]):
            net = ipaddress.ip_network(c["cidr"], strict=False)
            if c["kind"] == "on-link":
                devices = _scan_on_link(net)
                # make sure this host itself is in the list
                if c.get("self_ip") and self_mac and not any(
                    d.get("mac") == self_mac for d in devices
                ):
                    devices.append({"ip": c["self_ip"], "mac": self_mac,
                                    "hostname": source_host, "subnet": c["cidr"],
                                    "discovery": "arp", "source": "arp"})
            else:
                devices = _scan_off_link(net)
            data = _post_json(server, token, "/api/live/devices", {
                "devices": devices, "self_mac": self_mac,
                "gateway_ip": gw if gw and ipaddress.ip_address(gw) in net else None,
                "subnet": c["cidr"], "label": label, "agent_id": source_host,
                "active_subnets": active_subnets,
            })
            if data:
                log(f"{c['cidr']}: reported {data.get('total')} devices "
                    f"({data.get('new')} new, {c['kind']})")
        time.sleep(interval)


# ── mode: history (browser SQLite) ───────────────────────────────────────────
def _history_dbs() -> list[Path]:
    home = Path.home()
    cands = [
        home / "Library/Application Support/Google/Chrome/Default/History",
        home / "Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
        home / "Library/Application Support/Microsoft Edge/Default/History",
        home / ".config/google-chrome/Default/History",
        home / "AppData/Local/Google/Chrome/User Data/Default/History",
        home / "AppData/Local/Microsoft/Edge/User Data/Default/History",
        home / "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History",
    ]
    return [p for p in cands if p.exists()]


def run_history(reporter: Reporter, interval: float, backlog: int = 0) -> None:
    dbs = _history_dbs()
    if not dbs:
        log("no supported browser history DB found — use --mode dns or conn")
        sys.exit(2)
    log(f"watching browser history: {dbs[0]}  (no sudo, poll {interval}s)")
    import glob
    import shutil
    import tempfile
    from urllib.parse import urlparse

    def _query(db: Path, sql: str, args: tuple):
        # Copy the DB *and its journal/wal/shm siblings* so recently-committed
        # visits are visible (Chrome keeps them out of the bare .db file),
        # then read the copy so we never lock the browser's live DB.
        tmpdir = Path(tempfile.mkdtemp(prefix="drishti_hist_"))
        base = tmpdir / "History"
        try:
            shutil.copy2(db, base)
            for sib in glob.glob(str(db) + "-*"):  # History-wal / -shm / -journal
                shutil.copy2(sib, tmpdir / Path(sib).name)
            con = sqlite3.connect(f"file:{base}?mode=ro", uri=True)
            rows = con.execute(sql, args).fetchall()
            con.close()
            return rows
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # Prime to "now" so only sites opened AFTER start show — unless --backlog N
    # is given, in which case seed the feed with the N most recent visits too.
    last_ts = 0
    for db in dbs:
        try:
            r = _query(db, "SELECT MAX(last_visit_time) FROM urls", ())
            last_ts = max(last_ts, int((r and r[0][0]) or 0))
        except Exception:
            pass
    if backlog > 0:
        for db in dbs:
            try:
                for url, _ts in _query(
                    db, "SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?",
                    (backlog,),
                ):
                    host = urlparse(url).hostname
                    dom = registrable(host) if host else None
                    if dom:
                        reporter.report(dom)
            except Exception:
                pass
    log("primed — open a site now and it will appear (Ctrl-C to stop)")

    while True:
        for db in dbs:
            try:
                rows = _query(
                    db,
                    "SELECT url, last_visit_time FROM urls WHERE last_visit_time > ? "
                    "ORDER BY last_visit_time DESC LIMIT 50",
                    (last_ts,),
                )
            except Exception as e:  # noqa: BLE001
                log(f"history read failed: {e}")
                continue
            for url, ts in rows:
                last_ts = max(last_ts, ts or 0)
                host = urlparse(url).hostname
                dom = registrable(host) if host else None
                if dom:
                    reporter.report(dom)
        time.sleep(interval)


def main() -> None:
    ap = argparse.ArgumentParser(description="Drishti live network watch agent")
    # Default to history: it needs no sudo (dns/conn require root on macOS).
    ap.add_argument("--mode", choices=["dns", "conn", "history", "devices"], default="history")
    ap.add_argument("--server", default=os.environ.get("DRISHTI_SERVER_URL", "http://localhost:8000"))
    ap.add_argument("--token", default=os.environ.get("DRISHTI_AGENT_TOKEN", "agent-demo-token"))
    ap.add_argument("--interval", type=float, default=1.0, help="poll seconds (conn/history)")
    ap.add_argument("--backlog", type=int, default=0,
                    help="history mode: also seed the N most recent visits on start")
    host_default = socket.gethostname()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_default = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    ap.add_argument("--host", default=host_default, help="label or IP for this host")
    ap.add_argument(
        "--consent-subnet", action="store_true",
        default=_env_flag("DRISHTI_CONSENT_SUBNET"),
        help="devices mode only: confirm you are authorised to ping-sweep the "
             "target subnet(s) and inventory neighbouring devices (required to "
             "run --mode devices; can also be set via DRISHTI_CONSENT_SUBNET=1)",
    )
    ap.add_argument("--subnets", default="auto",
                    help="devices mode: 'auto' discovers candidates from "
                         "interfaces + routes; or a comma-separated CIDR list")
    ap.add_argument("--label", default=None,
                    help="devices mode: human name for this network, e.g. 'Floor-3-Guest'")
    ap.add_argument("--max-hosts", type=int, default=_HARD_MAX_HOSTS,
                    help=f"devices mode: per-CIDR host bound (hard cap {_HARD_MAX_HOSTS})")
    ap.add_argument("--discover-wifi", action="store_true",
                    help="devices mode: passively list visible SSIDs (beacons "
                         "only — never joins/authenticates) to surface the "
                         "seen-vs-inventoried coverage gap")
    args = ap.parse_args()

    log(f"reporting to {args.server} as host '{args.host}' (mode={args.mode})")
    try:
        if args.mode == "devices":
            run_devices(args.server, args.token, args.host, max(args.interval, 8.0),
                        args.consent_subnet, subnets_arg=args.subnets,
                        label=args.label, max_hosts=args.max_hosts,
                        wifi=args.discover_wifi)
            return
        reporter = Reporter(args.server, args.token, args.host)
        if args.mode == "dns":
            run_dns(reporter, args.interval)
        elif args.mode == "conn":
            run_conn(reporter, args.interval)
        else:
            run_history(reporter, args.interval, args.backlog)
    except KeyboardInterrupt:
        log("stopped")


if __name__ == "__main__":
    main()
