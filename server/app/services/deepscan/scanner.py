# Drishti v0.1 — nmap service/version scanner | 12-Jul-2026
"""Run a REAL nmap service/version scan against a consented target IP.

Defensive only: this scans a device the user explicitly selected and consented
to, to help secure it. It is a service/version detection scan (`-sV`), not an
exploit. Everything is wrapped so that a missing binary, a timeout, or any
failure returns a structured available:false result — it NEVER fabricates
ports or services on failure.

Device scan is isolated from live network traffic capture: this module only
invokes nmap against consented LAN hosts. It does not read sockets, flows,
SNI, or packet captures.

`run_nmap` is the single subprocess seam; tests monkeypatch it to run offline."""
from __future__ import annotations

import logging
import shutil
import subprocess

from app.config import get_settings
from app.services.deepscan import parser

logger = logging.getLogger("drishti")

# Full TCP coverage (`-p-` = 1–65535), not nmap's default top-1000. Services
# bound to non-standard ports (8080, 8443, 9000, 32400, …) must not be silently
# skipped. `-sV` + a moderate `--version-intensity` collects product/version
# evidence for correlation. `-Pn` skips host discovery — the device is already
# known-up from the ARP/ping sweep. `--open` keeps XML to listening ports.
# `--min-rate` keeps a full-port LAN sweep bounded. No `-O` (needs root).
#
# nmap gets its OWN `--host-timeout` just under the subprocess timeout so it
# flushes partial XML instead of being hard-killed with empty output.
def _nmap_args(host_timeout_s: int) -> list[str]:
    return [
        "-sV", "--version-intensity", "5", "-T4", "-Pn",
        "-p-", "--open",
        "--max-retries", "1",
        "--min-rate", "1500",
        f"--host-timeout={host_timeout_s}s", "-oX", "-",
    ]


def run_nmap(ip: str, timeout: float) -> tuple[str | None, str | None]:
    """Invoke the nmap binary. Returns (xml, error).

    (xml, None)  → success, xml is nmap's -oX output (possibly partial).
    (None, msg)  → nmap missing / produced nothing / failed; msg is a short reason.
    This is the ONLY place a subprocess runs; the whole thing is caught."""
    if shutil.which("nmap") is None:
        return None, "nmap is not installed on the server"
    # let nmap self-terminate ~15s before we would, so it flushes its XML
    host_timeout_s = max(30, int(timeout) - 15)
    try:
        proc = subprocess.run(
            ["nmap", *_nmap_args(host_timeout_s), ip],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, f"nmap scan timed out after {int(timeout)}s"
    except Exception as exc:  # pragma: no cover - defensive
        return None, f"nmap failed to run: {exc}"

    if proc.returncode != 0 and not proc.stdout.strip():
        err = (proc.stderr or "").strip().splitlines()
        detail = err[-1] if err else f"nmap exited {proc.returncode}"
        return None, detail[:200]
    if not proc.stdout.strip():
        return None, "nmap returned no output"
    return proc.stdout, None


def _host_result(ip: str, parsed: dict) -> dict:
    services = parsed.get("services") or []
    return {
        "available": True,
        "target": ip,
        "up": parsed.get("up", False),
        "os": parsed.get("os"),
        "services": services,
        "http_endpoints": parser.http_endpoints(ip, services),
    }


def scan(ip: str, timeout: float | None = None) -> dict:
    """Scan `ip` and return a structured result.

    Success shape: {available: True, target, up, os, services, http_endpoints}.
    Failure shape: {available: False, target, reason} — no fabricated data."""
    settings = get_settings()
    to = timeout if timeout is not None else settings.deepscan_timeout_seconds

    xml, err = run_nmap(ip, to)
    if err is not None:
        return {"available": False, "target": ip, "reason": err}

    try:
        parsed = parser.parse_nmap_xml(xml or "")
    except ValueError as exc:
        return {"available": False, "target": ip, "reason": f"could not parse nmap output: {exc}"}

    return _host_result(ip, parsed)


# ── subnet / range scanning ──────────────────────────────────────────────────
# Range scanning is pure Nmap on the LOCAL subnet: it reaches each device
# directly by its IP on the same link. There is NO NAT, routing, port-forwarding
# or traffic interception — just service/version probes to hosts the user
# consents to and is authorized to test.


def run_nmap_discovery(cidr: str, timeout: float) -> tuple[str | None, str | None]:
    """Host discovery only (`nmap -sn`, no port scan). Returns (xml, error).

    This is the ping/ARP sweep that finds which hosts on the subnet are up so we
    only version-scan the responsive ones. Subprocess seam — mocked in tests."""
    if shutil.which("nmap") is None:
        return None, "nmap is not installed on the server"
    try:
        proc = subprocess.run(
            ["nmap", "-sn", "-T4", "-oX", "-", cidr],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, f"host discovery timed out after {int(timeout)}s"
    except Exception as exc:  # pragma: no cover - defensive
        return None, f"nmap failed to run: {exc}"
    if not proc.stdout.strip():
        err = (proc.stderr or "").strip().splitlines()
        return None, (err[-1] if err else "nmap returned no output")[:200]
    return proc.stdout, None


def run_nmap_multi(ips: list[str], timeout: float, host_timeout_s: int) -> tuple[str | None, str | None]:
    """Version-scan several explicit IPs in one nmap run. Returns (xml, error).

    Same full-TCP `-p-` coverage as a single-host scan so non-standard listeners
    are not dropped in a subnet sweep. `-Pn` (hosts already known-up) + a
    per-host `--host-timeout` so one slow host can't sink the batch.
    Subprocess seam — mocked in tests."""
    if shutil.which("nmap") is None:
        return None, "nmap is not installed on the server"
    args = ["nmap", *_nmap_args(host_timeout_s), *ips]
    # give the subprocess a margin above nmap's own per-host budget so nmap
    # self-terminates and flushes partial XML instead of being hard-killed
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 20, check=False)
    except subprocess.TimeoutExpired:
        return None, f"subnet scan timed out after {int(timeout)}s"
    except Exception as exc:  # pragma: no cover - defensive
        return None, f"nmap failed to run: {exc}"
    if not proc.stdout.strip():
        err = (proc.stderr or "").strip().splitlines()
        return None, (err[-1] if err else "nmap returned no output")[:200]
    return proc.stdout, None


def discover_hosts(cidr: str, timeout: float | None = None) -> dict:
    """Find responsive hosts on the subnet. {available, hosts:[ip], reason?}."""
    settings = get_settings()
    to = timeout if timeout is not None else settings.deepscan_discovery_timeout_seconds
    xml, err = run_nmap_discovery(cidr, to)
    if err is not None:
        return {"available": False, "hosts": [], "reason": err}
    try:
        ips = parser.parse_live_ips(xml or "")
    except ValueError as exc:
        return {"available": False, "hosts": [], "reason": f"could not parse discovery output: {exc}"}
    return {"available": True, "hosts": ips, "reason": None}


def scan_range(cidr: str, max_hosts: int | None = None, timeout: float | None = None) -> dict:
    """Discover live hosts on `cidr`, then version-scan ALL of them in batches.

    Every live host is scanned (not just the first N): the batch size only bounds
    how many go into one nmap run so no single subprocess starves or times out;
    we iterate batch-by-batch until every discovered host is covered, up to a hard
    total ceiling. Returns {available, reason?, discovered, scanned, capped,
    hosts:[per-host scan dict {available, target, up, os, services}]}. No
    fabrication: a failed discovery/scan degrades to available:false with a
    truthful reason."""
    settings = get_settings()
    batch_size = max_hosts if max_hosts is not None else settings.deepscan_max_hosts
    total_cap = settings.deepscan_max_total_hosts
    batch_to = timeout if timeout is not None else settings.deepscan_range_timeout_seconds

    disc = discover_hosts(cidr)
    if not disc["available"]:
        return {"available": False, "reason": disc["reason"], "discovered": 0, "scanned": 0, "capped": False, "hosts": []}

    live = disc["hosts"]
    if not live:
        # discovery ran fine but nothing answered — truthful empty, not a failure
        return {"available": True, "reason": None, "discovered": 0, "scanned": 0, "capped": False, "hosts": []}

    capped = len(live) > total_cap
    targets = live[:total_cap]
    target_set = set(targets)

    hosts: list[dict] = []
    seen: set[str] = set()
    last_err: str | None = None
    # iterate every discovered host in fixed-size batches so all get scanned
    for start in range(0, len(targets), max(1, batch_size)):
        chunk = targets[start:start + max(1, batch_size)]
        # split each batch's own budget across its hosts, floored for a real shot
        per_host = max(45, int(batch_to / max(1, len(chunk))))
        xml, err = run_nmap_multi(chunk, batch_to, per_host)
        if err is not None:
            last_err = err  # a bad batch must not sink the others
            continue
        try:
            parsed_hosts = parser.parse_hosts(xml or "")
        except ValueError as exc:
            last_err = f"could not parse scan output: {exc}"
            continue
        for h in parsed_hosts:
            ip = h.get("ip")
            # keep only in-scope, first-seen hosts (guards duplicate/stray output)
            if not ip or ip in seen or ip not in target_set:
                continue
            seen.add(ip)
            hosts.append(_host_result(ip, h))

    if not hosts and last_err is not None:
        # every batch failed — surface the truth, don't pretend it scanned
        return {"available": False, "reason": last_err,
                "discovered": len(live), "scanned": 0, "capped": capped, "hosts": []}

    return {
        "available": True,
        "reason": None,
        "discovered": len(live),
        "scanned": len(hosts),
        "capped": capped,
        "hosts": hosts,
    }
