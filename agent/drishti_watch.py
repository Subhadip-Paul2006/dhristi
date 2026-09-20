#!/usr/bin/env python3
# Drishti — live network watch agent
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
from datetime import datetime, timezone
import http.server
import json
import os
import platform
import re
import socket
import sqlite3
import subprocess
import sys
import threading
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


def _get_local_mac() -> str | None:
    try:
        import uuid
        mac_int = uuid.getnode()
        if (mac_int >> 40) % 2 == 0:  # universal hardware MAC
            mac_hex = f"{mac_int:012x}"
            return ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))
    except Exception:
        pass
    return None


def _get_agent_id() -> str:
    env_id = os.environ.get("DRISHTI_AGENT_ID")
    if env_id and env_id.strip():
        return env_id.strip()
    try:
        hname = socket.gethostname().lower().strip()
        return f"agent-{hname}"
    except Exception:
        return "agent-windows-node"


class Reporter:
    """POSTs newly-seen domains to the server, deduping within this run."""

    def __init__(
        self,
        server: str,
        token: str,
        source_host: str,
        cooldown: float = 3.0,
        agent_id: str | None = None,
        mac: str | None = None,
    ):
        server_clean = server.rstrip("/").removesuffix("/api/live/observe").removesuffix("/api/live/sync_active")
        self.server = server_clean
        self.url = self.server + "/api/live/observe"
        self.token = token
        self.source_host = source_host
        self.agent_id = agent_id or _get_agent_id()
        self.mac = mac or _get_local_mac()
        self.cooldown = cooldown
        self._seen: dict[str, float] = {}

    def report(
        self,
        domain: str,
        source_host: str | None = None,
        protocol: str = "DNS",
        evidence_source: str = "dns_query_log",
        dest_port: int | None = None,
        connection_count: int = 1,
    ) -> None:
        src = source_host or self.source_host
        now = time.monotonic()
        key = f"{domain}:{src}:{protocol}:{dest_port}"
        last = self._seen.get(key)
        if last is not None and now - last < self.cooldown:
            return
        self._seen[key] = now
        payload = {
            "domain": domain,
            "source_host": src,
            "protocol": protocol,
            "evidence_source": evidence_source,
            "dest_port": dest_port,
            "connection_count": connection_count,
        }
        body = json.dumps(payload).encode()
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
            proto_str = f" via {protocol}" if protocol != "DNS" else ""
            log(f"{flag}  {domain} (from {src}{proto_str})  [{data.get('band')}] score={data.get('score')}")
        except urllib.error.HTTPError as e:
            log(f"server rejected {domain}: HTTP {e.code}")
        except Exception as e:  # noqa: BLE001 — best-effort telemetry
            log(f"could not report {domain}: {e}")

    def sync_active(
        self,
        domains: set[str] | list[str] | None = None,
        active_apps: list[str] | None = None,
        source_host: str | None = None,
        active_browser_tabs: list[dict] | None = None,
        endpoint_processes: list[dict] | None = None,
        installed_software: list[dict] | None = None,
        installed_browsers: list[str] | None = None,
        process_connections: list[dict] | None = None,
        vpn_status: str | None = None,
        vpn_adapters: list[str] | None = None,
        os_info: str | None = None,
    ) -> None:
        """Tell the server which domains, processes, software, and endpoint telemetry are active right now."""
        src = source_host or self.source_host
        payload: dict = {
            "domains": list(domains) if domains else [],
            "source_host": src,
            "agent_id": self.agent_id,
            "mac": self.mac,
        }
        if active_apps is not None:
            payload["active_apps"] = active_apps
        if active_browser_tabs is not None:
            payload["active_browser_tabs"] = active_browser_tabs
        if endpoint_processes is not None:
            payload["endpoint_processes"] = endpoint_processes
        if installed_software is not None:
            payload["installed_software"] = installed_software
        if installed_browsers is not None:
            payload["installed_browsers"] = installed_browsers
        if process_connections is not None:
            payload["process_connections"] = process_connections
        if vpn_status is not None:
            payload["vpn_status"] = vpn_status
        if vpn_adapters is not None:
            payload["vpn_adapters"] = vpn_adapters
        if os_info is not None:
            payload["os_info"] = os_info

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


def _extract_tls_sni(payload: bytes) -> str | None:
    """Parse TLS ClientHello and extract Server Name Indication (SNI) extension.

    Pure-Python, zero external dependencies. Works on unencrypted TLS handshakes (TCP 443).
    """
    if len(payload) < 44:
        return None
    # TLS Record Layer: ContentType 0x16 (Handshake), Version >= 0x0301
    if payload[0] != 0x16 or payload[1] != 0x03:
        return None
    record_len = int.from_bytes(payload[3:5], "big")
    if len(payload) < 5 + min(record_len, 500):
        return None
    pos = 5
    # Handshake Layer: Type 0x01 (ClientHello)
    if pos >= len(payload) or payload[pos] != 0x01:
        return None
    # Skip Handshake Type (1), Length (3), Version (2), Random (32)
    pos += 1 + 3 + 2 + 32
    if pos >= len(payload):
        return None
    # Skip Session ID
    session_id_len = payload[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(payload):
        return None
    # Skip Cipher Suites
    cipher_suites_len = int.from_bytes(payload[pos:pos+2], "big")
    pos += 2 + cipher_suites_len
    if pos + 1 > len(payload):
        return None
    # Skip Compression Methods
    comp_methods_len = payload[pos]
    pos += 1 + comp_methods_len
    if pos + 2 > len(payload):
        return None
    # Extensions length
    extensions_len = int.from_bytes(payload[pos:pos+2], "big")
    pos += 2
    end_extensions = min(pos + extensions_len, len(payload))

    while pos + 4 <= end_extensions:
        ext_type = int.from_bytes(payload[pos:pos+2], "big")
        ext_len = int.from_bytes(payload[pos+2:pos+4], "big")
        pos += 4
        if ext_type == 0x0000:  # server_name extension
            if pos + 2 <= end_extensions:
                list_len = int.from_bytes(payload[pos:pos+2], "big")
                curr = pos + 2
                while curr + 3 <= pos + 2 + list_len and curr + 3 <= end_extensions:
                    name_type = payload[curr]
                    name_len = int.from_bytes(payload[curr+1:curr+3], "big")
                    curr += 3
                    if name_type == 0x00 and curr + name_len <= end_extensions:
                        try:
                            sni = payload[curr:curr+name_len].decode("utf-8")
                            return sni.lower().strip()
                        except UnicodeDecodeError:
                            return None
                    curr += name_len
        pos += ext_len
    return None


def run_dns(reporter: Reporter, interval: float = 2.0, consent_subnet: bool = False) -> None:
    import threading

    try:
        from scapy.all import DNS, DNSQR, sniff, IP, TCP, UDP, Raw  # type: ignore
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
                                    devices.append({"ip": ip_str, "mac": mac_str, "hostname": None, "subnet": c["cidr"], "discovery": "arp"})
                                    existing_ips.add(ip_str)
                            except Exception:
                                pass
                        self_mac = _self_mac()
                        if c.get("self_ip") and self_mac and not any(d.get("mac") == self_mac for d in devices):
                            devices.append({"ip": c["self_ip"], "mac": self_mac, "hostname": reporter.source_host, "subnet": c["cidr"], "discovery": "arp"})
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

    if consent_subnet:
        sniff_filter = "udp port 53 or udp port 5353 or arp or (tcp and (dst port 443 or src port 443)) or udp port 51820 or udp port 1194"
        log("Consent confirmed: Sniffing DNS (53), mDNS (5353), TLS SNI (443), and VPN tunnel flows across LAN…")
    else:
        sniff_filter = "udp port 53 or udp port 5353 or arp"
        log("Standard mode: Sniffing DNS (53), mDNS (5353), and ARP across LAN… (pass --consent-subnet for SNI/tunnel flows)")

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

        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        try:
            is_src_private = ipaddress.ip_address(src_ip).is_private
            is_dst_private = ipaddress.ip_address(dst_ip).is_private
        except Exception:
            is_src_private = False
            is_dst_private = False

        # Identify client device
        client_ip = src_ip
        if not is_src_private and is_dst_private:
            client_ip = dst_ip
        elif is_src_private and is_dst_private and (src_ip == _gateway_ip() or src_ip.endswith(".1")):
            client_ip = dst_ip

        # 1. TLS ClientHello SNI Extraction (TCP 443)
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
            try:
                if pkt.haslayer(Raw):
                    load = bytes(pkt[Raw].load)
                    sni = _extract_tls_sni(load)
                    if sni:
                        dom = registrable(sni) or sni
                        t_client = src_ip if is_src_private else dst_ip
                        if t_client and t_client not in ("8.8.8.8", "8.8.4.4", "1.1.1.1"):
                            reporter.report(
                                dom,
                                source_host=t_client,
                                protocol="TLS/443",
                                evidence_source="sni_sniffing",
                                dest_port=443,
                            )
            except Exception:
                pass
            return

        # 2. Known VPN tunnel ports (WireGuard 51820, OpenVPN 1194)
        if pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            target_tunnel_port = dport if dport in (51820, 1194) else (sport if sport in (51820, 1194) else None)
            if target_tunnel_port:
                try:
                    t_client = src_ip if is_src_private else dst_ip
                    if t_client and t_client not in ("8.8.8.8", "8.8.4.4", "1.1.1.1"):
                        reporter.report(
                            f"tunnel-port-{target_tunnel_port}",
                            source_host=t_client,
                            protocol=f"UDP/{target_tunnel_port}",
                            evidence_source="flow_metadata",
                            dest_port=target_tunnel_port,
                        )
                except Exception:
                    pass
                return

        # 3. DNS / mDNS Queries (UDP 53, 5353)
        if pkt.haslayer(DNSQR) or pkt.haslayer(DNS):
            try:
                qname = ""
                if pkt.haslayer(DNSQR) and pkt[DNSQR].qname:
                    qname = pkt[DNSQR].qname.decode("utf-8", "ignore").lower()
                elif pkt.haslayer(DNS) and getattr(pkt[DNS], "qd", None) and getattr(pkt[DNS].qd, "qname", None):
                    qname = pkt[DNS].qd.qname.decode("utf-8", "ignore").lower()

                dom = registrable(qname)
                if dom and client_ip and client_ip not in ("8.8.8.8", "8.8.4.4", "1.1.1.1"):
                    reporter.report(
                        dom,
                        source_host=client_ip,
                        protocol="DNS",
                        evidence_source="dns_query_log",
                        dest_port=53,
                    )
            except Exception:
                pass

    try:
        sniff(filter=sniff_filter, prn=on_pkt, store=False, promisc=True)
    except Exception as e:
        log(f"scapy packet sniffing encountered error: {e}. Active tab watcher is still running.")
        while True:
            time.sleep(interval)


# ── Cross-Platform Endpoint Telemetry Collectors (macOS, Windows, Linux) ──────
_PURE_KERNEL_NAMES = {
    "system idle process", "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "svchost.exe",
    "kernel_task", "launchd", "sysmond", "distnoted", "cfprefsd", "trustd", "opendirectoryd", "powerd", "logd", "fseventsd"
}

_SYSTEM_SERVICE_NAMES = {
    "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
    "winlogon.exe", "dwm.exe", "sihost.exe", "taskhostw.exe",
    "runtimebroker.exe", "ctfmon.exe", "wlanext.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "smartscreen.exe", "sedsvc.exe", "compattelrunner.exe",
    "aggregatorhost.exe", "dashost.exe", "spoolsv.exe", "audiodg.exe",
    "mpdefendercoreservice.exe",
}

_KNOWN_USER_APPS = {
    "chrome", "chrome.exe", "google chrome", "msedge", "msedge.exe", "microsoft edge",
    "brave", "brave.exe", "brave browser", "firefox", "firefox.exe", "mozilla firefox",
    "opera", "opera.exe", "arc", "arc.exe", "safari",
    "code", "code.exe", "visual studio code", "cursor", "devenv.exe", "pycharm", "pycharm64.exe",
    "notepad", "notepad.exe", "notepad++", "notepad++.exe", "textedit", "sublime_text", "sublime_text.exe",
    "explorer.exe", "cmd.exe", "powershell.exe", "windowsterminal.exe", "terminal", "iterm2", "alacritty", "warp",
    "slack", "slack.exe", "discord", "discord.exe", "teams", "teams.exe", "telegram", "telegram.exe", "telegram-desktop",
    "whatsapp", "whatsapp.exe", "zoom", "zoom.exe", "spotify", "spotify.exe", "vlc", "vlc.exe",
    "postman", "postman.exe", "figma", "figma.exe", "notion", "docker", "calc.exe", "taskmgr.exe",
    "activity monitor", "notes", "mail", "calendar", "messages", "finder"
}

_VPN_DRIVER_KEYWORDS = (
    "wireguard", "wintun", "openvpn", "tap-windows", "tailscale", "zerotier",
    "cisco anyconnect", "nordlynx", "proton", "expressvpn", "surfshark",
    "windscribe", "mullvad", "warp", "forticlient", "globalprotect",
    "ipsec", "pptp", "l2tp", "softether", "puresvpn", "checkpoint",
    "utun", "tun", "tap", "ppp",
)

_VIRTUAL_ADAPTER_KEYWORDS = (
    "virtualbox", "vmware", "hyper-v", "vethernet", "wsl", "virtual",
    "host-only", "internal network", "nat", "npcap loopback", "bridge", "vboxnet",
)


def _collect_endpoint_processes(max_processes: int = 150) -> list[dict]:
    """Collect real currently-running processes using psutil across macOS, Windows, and Linux.

    Categorizes processes into:
    - USER_APPLICATION: Interactive desktop software, browsers, editors, user tools
    - BACKGROUND_PROCESS: Legitimate background services, daemons, workers, utilities
    - SYSTEM_PROCESS: Low-level OS services

    Enforces strict privacy: captures safe metadata only (name, PID, start time, category).
    NEVER captures command-line secrets, passwords, cookies, tokens, keystrokes, clipboard,
    or file contents.
    Zero fabrication: never maps process names to domains.
    """
    import psutil
    from datetime import datetime, timezone

    now_iso = datetime.now(timezone.utc).isoformat()
    collected: list[dict] = []
    seen_pids: set[int] = set()

    system_name = platform.system()
    source_tag = "macos_endpoint" if system_name == "Darwin" else "windows_endpoint" if system_name == "Windows" else "linux_endpoint"

    try:
        proc_iter = iter(psutil.process_iter(['pid', 'name', 'create_time', 'exe']))
        while True:
            try:
                proc = next(proc_iter)
            except StopIteration:
                break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue

            try:
                pid = proc.info.get('pid')
                if pid is None or pid in seen_pids:
                    continue
                seen_pids.add(pid)

                pname = proc.info.get('name')
                if not pname:
                    continue
                pname_clean = str(pname).strip()
                pname_lower = pname_clean.lower()

                # Filter pure kernel internal noise (PID 0, 1, 4, Idle, System, Registry, Smss)
                if pid in (0, 1, 4) or pname_lower in _PURE_KERNEL_NAMES:
                    continue

                exe_path = (proc.info.get('exe') or '').lower()
                create_time = proc.info.get('create_time')
                started_str = ""
                if create_time:
                    try:
                        started_dt = datetime.fromtimestamp(create_time, timezone.utc)
                        started_str = started_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                    except Exception:
                        pass

                # Classification per OS
                pname_base = pname_lower.replace(".exe", "").replace(".app", "")
                is_helper = any(h in pname_lower for h in ("helper", "crashpad", "renderer", "xprotect", "plugin", "daemon", "service"))

                if system_name == "Darwin":
                    is_sys = (
                        exe_path.startswith(("/system/", "/usr/libexec/", "/usr/sbin/"))
                        or pname_lower.startswith("com.apple.")
                        or pname_lower in _PURE_KERNEL_NAMES
                    )
                    is_user = (
                        pname_base in _KNOWN_USER_APPS
                        or exe_path.startswith("/applications/")
                        or ("/contents/macos/" in exe_path and not is_sys)
                        or "/users/" in exe_path
                    )
                    if is_helper:
                        category = "BACKGROUND_PROCESS"
                    elif is_user:
                        category = "USER_APPLICATION"
                    elif is_sys:
                        category = "SYSTEM_PROCESS"
                    else:
                        category = "BACKGROUND_PROCESS"
                elif system_name == "Windows":
                    if pname_lower in _KNOWN_USER_APPS or "\\users\\" in exe_path or "\\appdata\\" in exe_path:
                        category = "USER_APPLICATION"
                    elif pname_lower in _SYSTEM_SERVICE_NAMES or "windows\\system32" in exe_path:
                        category = "SYSTEM_PROCESS"
                    else:
                        category = "BACKGROUND_PROCESS"
                else:  # Linux / Unix
                    if pname_base in _KNOWN_USER_APPS or "/home/" in exe_path:
                        category = "USER_APPLICATION"
                    elif exe_path.startswith(("/sbin/", "/usr/sbin/", "/lib/systemd/")):
                        category = "SYSTEM_PROCESS"
                    else:
                        category = "BACKGROUND_PROCESS"

                details = f"PID: {pid} | [{category}]"
                if started_str:
                    details += f" | Started: {started_str}"

                collected.append({
                    "name": pname_clean,
                    "evidence_type": "ENDPOINT_PROCESS",
                    "source": source_tag,
                    "category": category,
                    "observed_at": now_iso,
                    "details": details,
                })

                if len(collected) >= max_processes:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue
    except Exception as e:
        log(f"process telemetry collection notice: {e}")

    return collected


def _collect_windows_processes(max_processes: int = 150) -> list[dict]:
    """Compatibility wrapper for _collect_endpoint_processes."""
    return _collect_endpoint_processes(max_processes)


def _collect_installed_software(max_items: int = 150) -> list[dict]:
    """Collect installed software across macOS, Windows, and Linux.

    - macOS: Scans /Applications, /System/Applications, ~/Applications and Info.plist, plus Homebrew
    - Windows: Scans HKLM and HKCU Uninstall registry keys
    - Linux: Queries system packages (dpkg/rpm/pacman)

    Captures safe metadata only (DisplayName, Version, Publisher).
    Installed != Running. Zero fabrication.
    """
    from datetime import datetime, timezone

    now_iso = datetime.now(timezone.utc).isoformat()
    software_map: dict[str, dict] = {}
    system_name = platform.system()

    if system_name == "Darwin":
        import plistlib
        app_dirs = [
            "/Applications",
            "/System/Applications",
            os.path.expanduser("~/Applications"),
        ]
        for app_dir in app_dirs:
            if not os.path.isdir(app_dir):
                continue
            try:
                for item in os.listdir(app_dir):
                    if item.endswith(".app"):
                        app_path = os.path.join(app_dir, item)
                        plist_path = os.path.join(app_path, "Contents", "Info.plist")
                        name = item[:-4]
                        version = ""
                        publisher = "Apple" if app_dir.startswith("/System") else ""
                        if os.path.exists(plist_path):
                            try:
                                with open(plist_path, "rb") as f:
                                    pl = plistlib.load(f)
                                    name = pl.get("CFBundleDisplayName") or pl.get("CFBundleName") or name
                                    version = pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion") or ""
                                    publisher = pl.get("CFBundleIdentifier") or publisher
                            except Exception:
                                pass
                        name_clean = str(name).strip()
                        if not name_clean:
                            continue
                        norm_key = name_clean.lower()
                        if norm_key not in software_map:
                            details_parts = []
                            if version:
                                details_parts.append(f"Version: {version}")
                            if publisher:
                                details_parts.append(f"Publisher: {publisher}")
                            details_str = " | ".join(details_parts) if details_parts else "macOS Application"
                            software_map[norm_key] = {
                                "name": name_clean,
                                "evidence_type": "INSTALLED_SOFTWARE",
                                "source": "macos_applications",
                                "observed_at": now_iso,
                                "details": details_str,
                            }
            except Exception:
                continue

        # Optional: check Homebrew packages
        try:
            brew_res = subprocess.run(["brew", "list", "--versions"], capture_output=True, text=True, timeout=3)
            if brew_res.returncode == 0:
                for line in brew_res.stdout.splitlines():
                    parts = line.strip().split()
                    if parts:
                        bname = parts[0]
                        bver = parts[1] if len(parts) > 1 else ""
                        norm_k = f"brew:{bname.lower()}"
                        if norm_k not in software_map:
                            software_map[norm_k] = {
                                "name": f"{bname} (Homebrew)",
                                "evidence_type": "INSTALLED_SOFTWARE",
                                "source": "homebrew",
                                "observed_at": now_iso,
                                "details": f"Version: {bver} | Package: Homebrew Formula" if bver else "Homebrew Formula",
                            }
        except Exception:
            pass

    elif system_name == "Windows":
        try:
            import winreg
        except ImportError:
            return []

        locations = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", 0),
        ]

        for root, subkey, flags in locations:
            try:
                with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | flags) as key:
                    num_subkeys = winreg.QueryInfoKey(key)[0]
                    for i in range(num_subkeys):
                        try:
                            subname = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subname) as item_key:
                                try:
                                    try:
                                        sys_comp, _ = winreg.QueryValueEx(item_key, "SystemComponent")
                                        if sys_comp == 1:
                                            continue
                                    except OSError:
                                        pass

                                    try:
                                        parent_key, _ = winreg.QueryValueEx(item_key, "ParentKeyName")
                                        if parent_key:
                                            continue
                                    except OSError:
                                        pass

                                    display_name, _ = winreg.QueryValueEx(item_key, "DisplayName")
                                    if not display_name or not str(display_name).strip():
                                        continue
                                    name_clean = str(display_name).strip()

                                    if name_clean.startswith("KB") and len(name_clean) > 5 and name_clean[2:6].isdigit():
                                        continue

                                    version = ""
                                    try:
                                        ver_val, _ = winreg.QueryValueEx(item_key, "DisplayVersion")
                                        if ver_val:
                                            version = str(ver_val).strip()
                                    except OSError:
                                        pass

                                    publisher = ""
                                    try:
                                        pub_val, _ = winreg.QueryValueEx(item_key, "Publisher")
                                        if pub_val:
                                            publisher = str(pub_val).strip()
                                    except OSError:
                                        pass

                                    details_parts = []
                                    if version:
                                        details_parts.append(f"Version: {version}")
                                    if publisher:
                                        details_parts.append(f"Publisher: {publisher}")
                                    details_str = " | ".join(details_parts) if details_parts else "Installed application"

                                    norm_key = name_clean.lower()
                                    if norm_key not in software_map:
                                        software_map[norm_key] = {
                                            "name": name_clean,
                                            "evidence_type": "INSTALLED_SOFTWARE",
                                            "source": "windows_registry",
                                            "observed_at": now_iso,
                                            "details": details_str,
                                        }
                                except OSError:
                                    continue
                        except OSError:
                            continue
            except OSError:
                continue

    sorted_items = sorted(software_map.values(), key=lambda x: x["name"].lower())
    return sorted_items[:max_items]


def _collect_installed_browsers() -> list[str]:
    """Detect genuine installed browsers across macOS, Windows, and Linux.

    At minimum detects: Google Chrome, Microsoft Edge, Brave, Mozilla Firefox, Safari, Arc, Opera.
    Returns only browsers actually found. Zero fabrication.
    """
    system_name = platform.system()
    browsers: set[str] = set()

    if system_name == "Darwin":
        mac_browser_paths = {
            "Google Chrome": ["/Applications/Google Chrome.app", os.path.expanduser("~/Applications/Google Chrome.app")],
            "Brave": ["/Applications/Brave Browser.app", os.path.expanduser("~/Applications/Brave Browser.app")],
            "Microsoft Edge": ["/Applications/Microsoft Edge.app", os.path.expanduser("~/Applications/Microsoft Edge.app")],
            "Mozilla Firefox": ["/Applications/Firefox.app", os.path.expanduser("~/Applications/Firefox.app")],
            "Safari": ["/Applications/Safari.app", "/System/Applications/Safari.app", "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app"],
            "Arc": ["/Applications/Arc.app", os.path.expanduser("~/Applications/Arc.app")],
            "Opera": ["/Applications/Opera.app", os.path.expanduser("~/Applications/Opera.app")],
        }
        for bname, paths in mac_browser_paths.items():
            if any(os.path.exists(p) for p in paths):
                browsers.add(bname)

    elif system_name == "Windows":
        try:
            import winreg
        except ImportError:
            return []

        browser_checks = {
            "Google Chrome": [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
                os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
            ],
            "Microsoft Edge": [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
                os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
                os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            ],
            "Brave": [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\brave.exe",
                os.path.expandvars(r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe"),
                os.path.expandvars(r"%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe"),
            ],
            "Mozilla Firefox": [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe",
                os.path.expandvars(r"%ProgramFiles%\Mozilla Firefox\firefox.exe"),
                os.path.expandvars(r"%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe"),
            ],
        }

        for bname, paths in browser_checks.items():
            found = False
            reg_subpath = paths[0]
            for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(root, reg_subpath) as key:
                        val, _ = winreg.QueryValueEx(key, "")
                        if val and os.path.exists(str(val)):
                            browsers.add(bname)
                            found = True
                            break
                except OSError:
                    pass
            if found:
                continue

            for fpath in paths[1:]:
                if fpath and os.path.exists(fpath):
                    browsers.add(bname)
                    break
    else:  # Linux
        linux_bins = {
            "Google Chrome": ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"],
            "Mozilla Firefox": ["firefox"],
            "Brave": ["brave-browser", "brave"],
            "Microsoft Edge": ["microsoft-edge", "microsoft-edge-stable"],
            "Opera": ["opera"],
        }
        import shutil
        for bname, bins in linux_bins.items():
            if any(shutil.which(b) for b in bins):
                browsers.add(bname)

    return sorted(browsers)


def _collect_process_connections(max_connections: int = 50) -> list[dict]:
    """Capture observed active socket connections using psutil and lsof across macOS, Windows, and Linux.

    Safe metadata only: PID, local/remote endpoints, protocol, status, process name.
    Does NOT infer website/application names from remote IPs.
    """
    import psutil
    from datetime import datetime, timezone

    now_iso = datetime.now(timezone.utc).isoformat()
    conns: list[dict] = []
    proc_name_cache: dict[int, str] = {}

    system_name = platform.system()
    source_tag = "macos_endpoint" if system_name == "Darwin" else "windows_endpoint" if system_name == "Windows" else "linux_endpoint"

    # Try psutil.net_connections
    try:
        net_conns = psutil.net_connections(kind="inet")
        for c in net_conns:
            try:
                if c.status not in ("ESTABLISHED", "LISTEN", "SYN_SENT"):
                    continue

                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "unknown"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""

                pname = "unknown"
                if c.pid:
                    if c.pid in proc_name_cache:
                        pname = proc_name_cache[c.pid]
                    else:
                        try:
                            pname = psutil.Process(c.pid).name()
                            proc_name_cache[c.pid] = pname
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                            pname = "unknown"

                proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                endpoint_str = f"{pname}:{c.laddr.port}" if c.laddr else pname
                details_str = f"PID: {c.pid or 'N/A'} | {proto.upper()} | Local: {laddr}"
                if raddr:
                    details_str += f" | Remote: {raddr}"
                details_str += f" | Status: {c.status}"

                conns.append({
                    "name": endpoint_str,
                    "evidence_type": "PROCESS_NETWORK_CONNECTION",
                    "source": source_tag,
                    "observed_at": now_iso,
                    "details": details_str,
                })

                if len(conns) >= max_connections:
                    break
            except Exception:
                continue
    except (psutil.AccessDenied, PermissionError, OSError):
        pass

    # If non-root on macOS/Linux and conns is empty, fallback to lsof
    if not conns and system_name in ("Darwin", "Linux"):
        try:
            out = subprocess.run(["lsof", "-iTCP", "-iUDP", "-P", "-n"], capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 8:
                    pname = parts[0]
                    pid_str = parts[1]
                    proto = parts[7].lower() if len(parts) > 7 else "tcp"
                    name_field = parts[8] if len(parts) > 8 else ""
                    state = parts[9].replace("(", "").replace(")", "") if len(parts) > 9 else "ESTABLISHED"
                    
                    if not name_field:
                        continue
                    
                    laddr = name_field
                    raddr = ""
                    if "->" in name_field:
                        laddr, raddr = name_field.split("->", 1)
                    
                    port = laddr.rsplit(":", 1)[-1] if ":" in laddr else ""
                    endpoint_str = f"{pname}:{port}" if port else pname
                    details_str = f"PID: {pid_str} | {proto.upper()} | Local: {laddr}"
                    if raddr:
                        details_str += f" | Remote: {raddr}"
                    details_str += f" | Status: {state}"

                    conns.append({
                        "name": endpoint_str,
                        "evidence_type": "PROCESS_NETWORK_CONNECTION",
                        "source": source_tag,
                        "observed_at": now_iso,
                        "details": details_str,
                    })

                    if len(conns) >= max_connections:
                        break
        except Exception:
            pass

    return conns


def _collect_vpn_status() -> tuple[str, list[str]]:
    """Determine VPN / Virtual Adapter status truthfully from network interfaces on macOS, Windows, and Linux.

    Returns:
      (status, adapter_evidence_list)
      status in: "VPN DETECTED", "VIRTUAL ADAPTER PRESENT", "NO VPN DETECTED"
    """
    import subprocess
    import psutil

    vpn_adapters: list[str] = []
    virtual_adapters: list[str] = []
    system_name = platform.system()

    if system_name == "Darwin":
        try:
            scutil_res = subprocess.run(["scutil", "--nc", "list"], capture_output=True, text=True, timeout=3)
            if scutil_res.returncode == 0:
                for line in scutil_res.stdout.splitlines():
                    if "(Connected)" in line:
                        vpn_adapters.append(line.strip())
        except Exception:
            pass

        try:
            for iface_name in psutil.net_if_stats().keys():
                iface_lower = iface_name.lower()
                if any(iface_lower.startswith(p) for p in ("utun", "tun", "tap", "ppp", "wg", "tailscale", "ipsec")):
                    if any(kw in iface_lower for kw in ("tailscale", "wireguard", "cisco", "openvpn", "warp", "proton", "nord")):
                        vpn_adapters.append(f"Interface: {iface_name}")
                    else:
                        virtual_adapters.append(f"Interface: {iface_name}")
                elif any(kw in iface_lower for kw in _VIRTUAL_ADAPTER_KEYWORDS):
                    virtual_adapters.append(f"Interface: {iface_name}")
        except Exception:
            pass

    elif system_name == "Windows":
        try:
            cmd = [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, Virtual | ConvertTo-Json -Compress"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
            if res.returncode == 0 and res.stdout.strip():
                raw = res.stdout.strip()
                data = json.loads(raw)
                adapters = data if isinstance(data, list) else [data]

                for a in adapters:
                    name = str(a.get("Name") or "").strip()
                    desc = str(a.get("InterfaceDescription") or "").strip()
                    is_virt = bool(a.get("Virtual", False))

                    label = f"{name}: {desc}" if desc else name
                    combined = f"{name} {desc}".lower()

                    if any(kw in combined for kw in _VPN_DRIVER_KEYWORDS):
                        vpn_adapters.append(label)
                    elif is_virt or any(kw in combined for kw in _VIRTUAL_ADAPTER_KEYWORDS):
                        virtual_adapters.append(label)
        except Exception:
            pass

    if not vpn_adapters and not virtual_adapters:
        try:
            for iface_name, stats in psutil.net_if_stats().items():
                iface_lower = iface_name.lower()
                if any(kw in iface_lower for kw in _VPN_DRIVER_KEYWORDS):
                    vpn_adapters.append(iface_name)
                elif any(kw in iface_lower for kw in _VIRTUAL_ADAPTER_KEYWORDS):
                    virtual_adapters.append(iface_name)
        except Exception:
            pass

    if vpn_adapters:
        return "VPN DETECTED", vpn_adapters
    if virtual_adapters:
        return "VIRTUAL ADAPTER PRESENT", virtual_adapters
    return "NO VPN DETECTED", []


def _collect_os_info() -> str:
    """Collect real OS platform information across macOS, Windows, and Linux."""
    try:
        sys_name = platform.system()
        if sys_name == "Darwin":
            mac_ver = platform.mac_ver()[0]
            machine = platform.machine()
            return f"macOS {mac_ver} ({machine}) - {platform.platform()}"
        elif sys_name == "Windows":
            release = platform.release()
            ver = platform.version()
            plat = platform.platform()
            return f"Windows {release} (Build {ver}) - {plat}"
        else:
            return f"{sys_name} - {platform.platform()}"
    except Exception:
        return platform.platform() or "Windows"


# ── Browser Extension Loopback Receiver (Phase MVP / B2.4) ────────────────────
_ACTIVE_TABS_LOCK = threading.Lock()
_ACTIVE_TABS_BY_BROWSER: dict[str, dict] = {}
_LOOPBACK_SERVER_STARTED = False


class _TabReceiverHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress standard logging to keep terminal clean
        return

    def _set_cors(self, status: int = 200, content_type: str = "application/json"):
        origin = self.headers.get("Origin", "")
        # Restrict CORS to browser extensions and local loopback origins
        allowed_origin = "*"
        if origin:
            if (
                origin.startswith("chrome-extension://")
                or origin.startswith("moz-extension://")
                or origin.startswith("http://127.0.0.1")
                or origin.startswith("http://localhost")
            ):
                allowed_origin = origin
            else:
                allowed_origin = "null"

        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin", allowed_origin)
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Type", content_type)
        self.end_headers()

    def do_OPTIONS(self):
        self._set_cors(204, "text/plain")

    def do_GET(self):
        if self.path in ("/status", "/health"):
            self._set_cors(200)
            self.wfile.write(b'{"status":"ok","agent":"drishti_watch"}')
        else:
            self._set_cors(404)
            self.wfile.write(b'{"error":"not_found"}')

    def do_POST(self):
        if self.path in ("/tab", "/browser_tab"):
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(length)
                data = json.loads(raw_body.decode("utf-8"))

                browser = str(data.get("browser") or "Browser").strip()
                url = str(data.get("url") or "").strip()
                domain = str(data.get("domain") or "").strip()
                title = str(data.get("title") or domain or "Active Tab").strip()

                if url and domain and (url.startswith("http://") or url.startswith("https://")):
                    now_iso = datetime.now(timezone.utc).isoformat()
                    item = {
                        "name": f"{browser}: {domain}",
                        "evidence_type": "BROWSER_ACTIVE_TAB",
                        "source": "browser_extension",
                        "observed_at": now_iso,
                        "details": f"{title} | {url}",
                        "browser": browser,
                        "url": url,
                        "domain": domain,
                        "title": title,
                    }
                    with _ACTIVE_TABS_LOCK:
                        _ACTIVE_TABS_BY_BROWSER[browser] = {
                            "item": item,
                            "received_at": time.monotonic(),
                            "domain": domain,
                        }
                    self._set_cors(200)
                    self.wfile.write(b'{"status":"ok","received":true}')
                    return
            except Exception:
                pass
            self._set_cors(400)
            self.wfile.write(b'{"error":"invalid_payload"}')
        else:
            self._set_cors(404)
            self.wfile.write(b'{"error":"not_found"}')


def start_loopback_tab_server(port: int = 48124) -> None:
    """Start local loopback HTTP server to receive active tabs from browser extension."""
    global _LOOPBACK_SERVER_STARTED
    if _LOOPBACK_SERVER_STARTED:
        return

    def _run():
        try:
            server = http.server.HTTPServer(("127.0.0.1", port), _TabReceiverHandler)
            log(f"Browser extension receiver listening on http://127.0.0.1:{port}/tab")
            server.serve_forever()
        except OSError as e:
            log(f"Could not bind extension receiver on 127.0.0.1:{port}: {e}")

    t = threading.Thread(target=_run, daemon=True, name="drishti_tab_receiver")
    t.start()
    _LOOPBACK_SERVER_STARTED = True


def _collect_browser_history_tabs(max_tabs: int = 35) -> list[dict]:
    """Extract recent browser visits from Arc, Chrome, Edge, and Brave history DBs."""
    import shutil
    import tempfile
    from urllib.parse import urlparse
    from datetime import datetime, timezone, timedelta

    dbs = _history_dbs()
    tabs = []
    seen_domains = set()
    epoch_start = datetime(1601, 1, 1, tzinfo=timezone.utc)

    for db_path in dbs:
        p_str = str(db_path)
        bname = (
            "Arc" if "Arc" in p_str
            else ("Google Chrome" if "Chrome" in p_str
            else ("Microsoft Edge" if "Edge" in p_str
            else ("Brave" if "Brave" in p_str else "Browser")))
        )
        tmpdir = Path(tempfile.mkdtemp(prefix="drishti_tabs_"))
        tmp_db = tmpdir / "History"
        try:
            shutil.copy2(db_path, tmp_db)
            # copy journal/wal/shm if present
            for ext in ("-journal", "-wal", "-shm"):
                sib = db_path.parent / (db_path.name + ext)
                if sib.exists():
                    try:
                        shutil.copy2(sib, tmpdir / (tmp_db.name + ext))
                    except Exception:
                        pass
            conn = sqlite3.connect(str(tmp_db), timeout=1.0)
            cur = conn.cursor()
            cur.execute("SELECT url, title, last_visit_time FROM urls WHERE last_visit_time > 0 ORDER BY last_visit_time DESC LIMIT 100")
            rows = cur.fetchall()
            conn.close()

            for u, t, lvt in rows:
                if not u or not u.startswith("http"):
                    continue
                dom = urlparse(u).netloc.split(":")[0].lower()
                if dom.startswith("www."):
                    dom = dom[4:]
                if not dom or dom in ("localhost", "127.0.0.1"):
                    continue
                reg = registrable(dom) or dom
                if reg not in seen_domains:
                    seen_domains.add(reg)
                    visit_dt = epoch_start + timedelta(microseconds=lvt)
                    observed_iso = visit_dt.isoformat()
                    tabs.append({
                        "name": f"{bname}: {reg}",
                        "evidence_type": "BROWSER_ACTIVE_TAB",
                        "source": "browser_history",
                        "observed_at": observed_iso,
                        "details": f"{t or reg} | {u}",
                        "browser": bname,
                        "url": u,
                        "domain": reg,
                        "title": t or reg,
                    })
                    if len(tabs) >= max_tabs:
                        break
        except Exception:
            pass
        finally:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass
        if len(tabs) >= max_tabs:
            break

    return tabs


def _get_active_browser_tabs(ttl_seconds: float = 300.0) -> list[dict]:
    """Retrieve non-stale active browser tabs received from extension and recent browser history."""
    now = time.monotonic()
    active_tabs = []
    with _ACTIVE_TABS_LOCK:
        expired = [b for b, data in _ACTIVE_TABS_BY_BROWSER.items() if now - data["received_at"] > ttl_seconds]
        for b in expired:
            del _ACTIVE_TABS_BY_BROWSER[b]
        for b, data in sorted(_ACTIVE_TABS_BY_BROWSER.items()):
            active_tabs.append(data["item"])

    # Merge recent browser history tabs (Arc, Chrome, Edge, Brave) so Arc visits are displayed
    seen_domains = {t.get("domain") for t in active_tabs if t.get("domain")}
    for ht in _collect_browser_history_tabs(max_tabs=20):
        dom = ht.get("domain")
        if dom and dom not in seen_domains:
            seen_domains.add(dom)
            active_tabs.append(ht)

    return active_tabs


def collect_windows_endpoint_telemetry() -> dict:
    """Convenience helper to gather all Windows endpoint telemetry in one call."""
    procs = _collect_windows_processes()
    tabs = _get_active_browser_tabs(ttl_seconds=20.0)
    soft = _collect_installed_software()
    browsers = _collect_installed_browsers()
    conns = _collect_process_connections()
    vpn_st, vpn_ad = _collect_vpn_status()
    os_inf = _collect_os_info()

    return {
        "endpoint_processes": procs,
        "active_browser_tabs": tabs,
        "installed_software": soft,
        "installed_browsers": browsers,
        "process_connections": conns,
        "vpn_status": vpn_st,
        "vpn_adapters": vpn_ad,
        "os_info": os_inf,
        "active_apps": [p["name"] for p in procs],
    }


# ── mode: conn (browser tabs & active apps) ──────────────────────────────────
def run_conn(reporter: Reporter, interval: float) -> None:
    from urllib.parse import urlparse
    
    # Start loopback HTTP receiver for browser extension (Chrome, Edge, Brave)
    start_loopback_tab_server()

    log(f"polling open browser tabs and active applications every {interval}s…")
    browsers = ["Google Chrome", "Brave Browser", "Safari", "Arc", "Microsoft Edge", "Firefox"]
    
    _NOISE_APPS = {
        "python", "python3", "drishti.py", "drishti_watch.py", "drishti_agent.py",
        "terminal", "zsh", "bash", "sh", "launchd", "system events", "finder", "dock",
        "systemsettings", "controlcenter", "notificationcenter", "coreauthd"
    }

    _last_inventory_time: float = 0.0
    _cached_software: list[dict] = []
    _cached_browsers: list[str] = []
    _cached_vpn_status: str = "NO VPN DETECTED"
    _cached_vpn_adapters: list[str] = []
    _cached_os_info: str = ""

    while True:
        domains = set()
        active_apps_list = []
        active_browser_tabs = None
        endpoint_processes = None
        installed_software = None
        installed_browsers = None
        process_connections = None
        vpn_status = None
        vpn_adapters = None
        os_info = None

        # Cross-platform Endpoint Telemetry Collection
        endpoint_processes = _collect_endpoint_processes()
        user_apps = [p["name"] for p in endpoint_processes if p.get("category") == "USER_APPLICATION"]
        active_apps_list = user_apps if user_apps else [p["name"] for p in endpoint_processes]
        process_connections = _collect_process_connections()
        active_browser_tabs = _get_active_browser_tabs(ttl_seconds=20.0)

        # On macOS, if extension tab receiver isn't providing tabs, attempt AppleScript tab extraction
        if platform.system() == "Darwin" and not active_browser_tabs:
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

        # Observe active browser tab domains for live reputation scoring
        for tab_item in (active_browser_tabs or []):
            t_dom = tab_item.get("domain")
            if t_dom:
                reg = registrable(t_dom) or t_dom
                if reg:
                    domains.add(reg)

        # Refresh software, browser, VPN, and OS inventories every 60s
        now_mono = time.monotonic()
        if now_mono - _last_inventory_time > 60:
            _cached_software = _collect_installed_software()
            _cached_browsers = _collect_installed_browsers()
            _cached_vpn_status, _cached_vpn_adapters = _collect_vpn_status()
            _cached_os_info = _collect_os_info()
            _last_inventory_time = now_mono

        installed_software = _cached_software
        installed_browsers = _cached_browsers
        vpn_status = _cached_vpn_status
        vpn_adapters = _cached_vpn_adapters
        os_info = _cached_os_info

        for dom in domains:
            reporter.report(dom)
            
        reporter.sync_active(
            domains=domains,
            active_apps=active_apps_list,
            active_browser_tabs=active_browser_tabs,
            endpoint_processes=endpoint_processes,
            installed_software=installed_software,
            installed_browsers=installed_browsers,
            process_connections=process_connections,
            vpn_status=vpn_status,
            vpn_adapters=vpn_adapters,
            os_info=os_info,
        )
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
            ip = mask = None
            for line in text.splitlines():
                m = re.search(r"IPv4 Address[ .]*:\s*([\d.]+)", line)
                if m:
                    ip = m.group(1)
                m = re.search(r"Subnet Mask[ .]*:\s*([\d.]+)", line)
                if m and ip:
                    mask = m.group(1)
                    prefix = ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
                    out.append({"iface": "?", "ip": ip, "prefix": prefix})
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
                }
    except Exception:
        pass

    # 2. ICMP ping sweep to discover live responders
    responders = _sweep_responders(net)
    for ip in responders:
        if ip not in devices_by_ip:
            devices_by_ip[ip] = {
                "ip": ip,
                "mac": None,
                "hostname": None,
                "subnet": str(net),
                "discovery": "icmp",
            }

    # 3. System ARP table to enrich MACs and hostnames
    for d in _arp_devices():
        try:
            ip = d.get("ip")
            if ip and ipaddress.ip_address(ip) in net:
                if ip not in devices_by_ip or not devices_by_ip[ip].get("mac"):
                    d["subnet"] = str(net)
                    d["discovery"] = "arp"
                    devices_by_ip[ip] = d
                elif d.get("hostname") and not devices_by_ip[ip].get("hostname"):
                    devices_by_ip[ip]["hostname"] = d["hostname"]
                if d.get("mac") and ip in devices_by_ip:
                    devices_by_ip[ip]["mac"] = d["mac"]
                    devices_by_ip[ip]["discovery"] = "arp"
        except ValueError:
            continue

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
                        "subnet": str(net), "discovery": "l3"})
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
            import uuid
            node = uuid.getnode()
            if (node >> 40) % 2 == 0:
                mac_hex = f"{node:012x}"
                return ":".join(mac_hex[i:i+2] for i in range(0, 12, 2)).lower()
        except Exception:
            pass
        try:
            out = subprocess.run(["getmac", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                line = line.strip().replace('"', '')
                if line:
                    parts = line.split(',')
                    candidate = parts[0].strip().replace('-', ':').lower()
                    if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", candidate):
                        return candidate
        except Exception:
            pass
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
    if platform.system() == "Windows":
        try:
            out = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        gw = parts[1].strip()
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
                            return gw
        except Exception:
            pass
    try:
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
    system = platform.system()
    try:
        cmd = ["arp", "-a"] if system in ("Windows", "Darwin") else ["arp", "-an"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return []
    devices = []
    for line in out.splitlines():
        if system == "Windows":
            m = re.search(r"^\s*([\d.]+)\s+([0-9a-fA-F[:-]{11,17})\s+(\w+)", line)
            if not m:
                continue
            ip, raw_mac, entry_type = m.group(1), m.group(2), m.group(3)
            mac = raw_mac.replace("-", ":").lower()
            if entry_type.lower() != "dynamic" and not mac.startswith("00:"):
                if mac == "ff:ff:ff:ff:ff:ff" or ip.startswith(("224.", "239.")) or ip.endswith(".255"):
                    continue
            if mac == "ff:ff:ff:ff:ff:ff" or ip.startswith(("224.", "239.")) or ip.endswith(".255"):
                continue
            devices.append({"ip": ip, "mac": _norm_mac(mac), "hostname": None})
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
            devices.append({"ip": ip, "mac": _norm_mac(mac), "hostname": hostname})
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
        elif system == "Darwin":
            if os.path.exists(_AIRPORT):
                try:
                    text = run([_AIRPORT, "-s"])
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
                except Exception:
                    pass

            if not joined:
                try:
                    hw = run(["networksetup", "-listallhardwareports"])
                    wifi_dev = "en0"
                    m = re.search(r"Hardware Port:\s*Wi-Fi\s+Device:\s*(\w+)", hw)
                    if m:
                        wifi_dev = m.group(1)
                    res = run(["networksetup", "-getairportnetwork", wifi_dev])
                    if "Current Wi-Fi Network:" in res:
                        joined = res.split(":", 1)[1].strip()
                        if not any(n.get("ssid") == joined for n in networks):
                            networks.append({
                                "ssid": joined,
                                "bssid": "N/A",
                                "channel": "N/A",
                                "signal": "N/A",
                                "security": "Wi-Fi (Active)",
                                "joined": True,
                            })
                        else:
                            for n in networks:
                                if n.get("ssid") == joined:
                                    n["joined"] = True
                except Exception:
                    pass
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


_WIFI_IFACES = ("en0", "wlan", "wlp")  # macOS builtin / Linux wireless naming


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
         if c["kind"] == "on-link" and (c.get("iface") or "").startswith(_WIFI_IFACES)),
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
                effective_self_mac = self_mac or "02:00:00:00:00:01"
                if c.get("self_ip") and not any(d.get("ip") == c["self_ip"] for d in devices):
                    devices.append({"ip": c["self_ip"], "mac": effective_self_mac,
                                    "hostname": source_host, "subnet": c["cidr"],
                                    "discovery": "arp"})
            else:
                devices = _scan_off_link(net)
            data = _post_json(server, token, "/api/live/devices", {
                "devices": devices, "self_mac": self_mac or effective_self_mac,
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
        # macOS
        home / "Library/Application Support/Google/Chrome/Default/History",
        home / "Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
        home / "Library/Application Support/Microsoft Edge/Default/History",
        home / "Library/Application Support/Arc/User Data/Default/History",
        # Linux
        home / ".config/google-chrome/Default/History",
        home / ".config/BraveSoftware/Brave-Browser/Default/History",
        home / ".config/microsoft-edge/Default/History",
        # Windows
        home / "AppData/Local/Google/Chrome/User Data/Default/History",
        home / "AppData/Local/Microsoft/Edge/User Data/Default/History",
        home / "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History",
    ]
    if platform.system() == "Windows":
        try:
            import glob
            arc_paths = glob.glob(str(home / "AppData/Local/Packages/TheBrowserCompany.Arc_*/LocalCache/Local/Arc/User Data/*/History"))
            for p in reversed(arc_paths):
                cands.insert(0, Path(p))
            chrome_profiles = glob.glob(str(home / "AppData/Local/Google/Chrome/User Data/Profile */History"))
            for p in chrome_profiles:
                cands.append(Path(p))
        except Exception:
            pass
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


def install_autostart() -> bool:
    """Install Drishti endpoint agent into macOS LaunchAgents or Windows Current User Run key."""
    system_name = platform.system()
    if system_name == "Darwin":
        plist_dir = Path.home() / "Library/LaunchAgents"
        plist_dir.mkdir(parents=True, exist_ok=True)
        plist_path = plist_dir / "dev.drishti.agent.plist"
        exe = sys.executable
        script = os.path.abspath(__file__)
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.drishti.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>{script}</string>
        <string>--mode</string>
        <string>conn</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
        try:
            with open(plist_path, "w") as f:
                f.write(plist_content)
            subprocess.run(["launchctl", "load", "-w", str(plist_path)], capture_output=True)
            log(f"SUCCESS: Drishti Endpoint Agent registered in macOS LaunchAgents: {plist_path}")
            return True
        except Exception as e:
            log(f"Failed to install macOS LaunchAgent: {e}")
            return False

    elif system_name == "Windows":
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            exe = sys.executable
            script = os.path.abspath(__file__)
            cmd = f'"{exe}" "{script}" --mode conn'
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "DrishtiEndpointAgent", 0, winreg.REG_SZ, cmd)
            log(f"SUCCESS: Drishti Endpoint Agent registered in Windows Run key: {cmd}")
            return True
        except Exception as e:
            log(f"Failed to install autostart: {e}")
            return False
    else:
        log("Autostart is supported on macOS and Windows")
        return False


def uninstall_autostart() -> bool:
    """Remove Drishti endpoint agent from macOS LaunchAgents or Windows Current User Run key."""
    system_name = platform.system()
    if system_name == "Darwin":
        plist_path = Path.home() / "Library/LaunchAgents/dev.drishti.agent.plist"
        if plist_path.exists():
            try:
                subprocess.run(["launchctl", "unload", "-w", str(plist_path)], capture_output=True)
            except Exception:
                pass
            try:
                plist_path.unlink()
                log(f"SUCCESS: Drishti Endpoint Agent LaunchAgent removed from {plist_path}")
                return True
            except Exception as e:
                log(f"Failed to remove plist file: {e}")
                return False
        log("Notice: Drishti Endpoint Agent LaunchAgent was not present.")
        return True

    elif system_name == "Windows":
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, "DrishtiEndpointAgent")
            log("SUCCESS: Drishti Endpoint Agent removed from Windows Run key.")
            return True
        except FileNotFoundError:
            log("Notice: Drishti Endpoint Agent was not present in Windows Run key.")
            return True
        except Exception as e:
            log(f"Failed to uninstall autostart: {e}")
            return False
    else:
        log("Autostart is supported on macOS and Windows")
        return False


def main() -> None:
    ap = argparse.ArgumentParser(description="Drishti live network watch agent")
    # Default to history: it needs no sudo (dns/conn require root on macOS).
    ap.add_argument("--mode", choices=["dns", "conn", "history", "devices"], default="history")
    ap.add_argument("--server", default=os.environ.get("DRISHTI_SERVER_URL", "http://localhost:8000"))
    ap.add_argument("--url", dest="server", help="Alias for --server (e.g. http://192.168.1.2:8000)")
    ap.add_argument("--token", default=os.environ.get("DRISHTI_AGENT_TOKEN", "agent-demo-token"))
    ap.add_argument("--interval", type=float, default=1.0, help="poll seconds (conn/history)")
    ap.add_argument("--backlog", type=int, default=0,
                    help="history mode: also seed the N most recent visits on start")
    ap.add_argument("--agent-id", default=None, help="Explicit unique identity for this endpoint agent")
    ap.add_argument("--install-autostart", action="store_true", help="Install Drishti endpoint agent to autostart with Windows")
    ap.add_argument("--uninstall-autostart", action="store_true", help="Remove Drishti endpoint agent from Windows autostart")
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

    if args.install_autostart:
        install_autostart()
        return
    if args.uninstall_autostart:
        uninstall_autostart()
        return

    log(f"reporting to {args.server} as host '{args.host}' (mode={args.mode})")
    try:
        if args.mode == "devices":
            run_devices(args.server, args.token, args.host, max(args.interval, 8.0),
                        args.consent_subnet, subnets_arg=args.subnets,
                        label=args.label, max_hosts=args.max_hosts,
                        wifi=args.discover_wifi)
            return
        reporter = Reporter(args.server, args.token, args.host, agent_id=args.agent_id)
        if args.mode == "dns":
            run_dns(reporter, args.interval, consent_subnet=args.consent_subnet)
        elif args.mode == "conn":
            run_conn(reporter, args.interval)
        else:
            run_history(reporter, args.interval, args.backlog)
    except KeyboardInterrupt:
        log("stopped")


if __name__ == "__main__":
    main()
