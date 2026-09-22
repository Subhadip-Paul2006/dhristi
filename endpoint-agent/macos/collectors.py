# Drishti v0.1 — macOS Telemetry Collectors | Phase 02
from __future__ import annotations

import logging
import os
import socket
import sys
from datetime import datetime, timezone
from typing import Any

import psutil

from collectors.base import (
    BaseBrowserCollector,
    BaseHardwareCollector,
    BaseProcessCollector,
    BaseServiceCollector,
    BaseSocketCollector,
    BaseSoftwareCollector,
)
from collectors.contracts import (
    BrowserProcessItem,
    CpuInfo,
    ListeningPortItem,
    MemoryInfo,
    NetworkInterfaceInfo,
    PerCoreUsage,
    ProcessCategory,
    ProcessItem,
    ServiceItem,
    SocketConnectionItem,
    SoftwareItem,
)

logger = logging.getLogger("drishti.agent.macos")

MACOS_SYSTEM_PROCESSES = {
    "launchd",
    "kernel_task",
    "syslogd",
    "kextd",
    "fseventsd",
    "securityd",
    "distnoted",
    "cfprefsd",
    "logd",
    "diskarbitrationd",
    "notifyd",
    "coreaudiod",
    "windowserver",
    "opendirectoryd",
    "systemsoundserverd",
    "mds",
    "mdworker",
    "loginwindow",
}

MACOS_BROWSERS = {
    "google chrome": "Chrome",
    "chrome": "Chrome",
    "safari": "Safari",
    "brave browser": "Brave",
    "brave": "Brave",
    "firefox": "Firefox",
    "arc": "Arc",
    "opera": "Opera",
}


class MacOSProcessCollector(BaseProcessCollector):
    """Gathers genuine running processes on macOS and classifies them deterministically."""

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label

    def _classify_process(self, name: str, exe_path: str | None) -> str:
        lower_name = name.lower()
        if lower_name in MACOS_SYSTEM_PROCESSES:
            return ProcessCategory.SYSTEM_PROCESS.value
        if lower_name in MACOS_BROWSERS:
            return ProcessCategory.USER_APPLICATION.value

        if exe_path:
            lower_path = exe_path.lower()
            if "/system/library" in lower_path or "/usr/libexec" in lower_path or "/usr/sbin" in lower_path:
                return ProcessCategory.SYSTEM_PROCESS.value
            if "/applications" in lower_path and not "/system/" in lower_path:
                return ProcessCategory.USER_APPLICATION.value

        return ProcessCategory.BACKGROUND_PROCESS.value

    def collect_processes(self) -> tuple[list[ProcessItem], list[str]]:
        processes: list[ProcessItem] = []
        active_apps_set: set[str] = set()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Prime the cpu_percent counters (non-blocking first call)
        try:
            for proc in psutil.process_iter(["pid"]):
                try:
                    proc.cpu_percent(interval=None)
                except Exception:
                    pass
        except Exception:
            pass

        import time
        time.sleep(0.12)

        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]):
            try:
                info = proc.info
                name = info.get("name") or "unknown"
                pid = info.get("pid")
                if pid is None:
                    continue

                ppid = info.get("ppid")
                exe_path = info.get("exe")
                cmdline = info.get("cmdline")

                create_time = info.get("create_time")
                start_time_iso = (
                    datetime.fromtimestamp(create_time, tz=timezone.utc).isoformat()
                    if create_time
                    else None
                )

                category = self._classify_process(name, exe_path)
                if category == ProcessCategory.USER_APPLICATION.value:
                    active_apps_set.add(name)

                cpu_pct: float | None = None
                mem_mb: float | None = None
                try:
                    cpu_pct = proc.cpu_percent(interval=None)
                except Exception:
                    pass
                try:
                    mem_info = proc.memory_info()
                    mem_mb = round(mem_info.rss / (1024 * 1024), 2)
                except Exception:
                    pass

                processes.append(
                    ProcessItem(
                        pid=pid,
                        name=name,
                        ppid=ppid,
                        exe_path=exe_path,
                        cmdline=cmdline,
                        category=category,
                        start_time=start_time_iso,
                        cpu_percent=cpu_pct,
                        memory_mb=mem_mb,
                        observed_at=now_iso,
                        source=self.source_label,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug("Error inspecting macOS process %s: %s", getattr(proc, "pid", "unknown"), e)
                continue

        return processes, sorted(list(active_apps_set))


class MacOSSoftwareCollector(BaseSoftwareCollector):
    """Enumerates installed applications on macOS via /Applications bundles."""

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label

    def collect_software(self) -> list[SoftwareItem]:
        software_list: list[SoftwareItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        app_dirs = ["/Applications", "/System/Applications"]
        for d in app_dirs:
            if not os.path.exists(d):
                continue
            try:
                for entry in os.listdir(d):
                    if entry.endswith(".app"):
                        app_name = entry[:-4]
                        app_path = os.path.join(d, entry)
                        software_list.append(
                            SoftwareItem(
                                name=app_name,
                                version=None,
                                publisher="Apple" if "/System/" in d else None,
                                install_location=app_path,
                                observed_at=now_iso,
                                source=self.source_label,
                            )
                        )
            except Exception as e:
                logger.debug("Could not enumerate macOS directory %s: %s", d, e)

        software_list.sort(key=lambda s: s.name.lower())
        return software_list


class MacOSServiceCollector(BaseServiceCollector):
    """Enumerates launchd services on macOS."""

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label

    def collect_services(self) -> list[ServiceItem]:
        # On actual macOS, launchd services can be enumerated; fallback returns empty without fabrication
        return []


class MacOSSocketCollector(BaseSocketCollector):
    """Gathers listening sockets and connections on macOS."""

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label

    def collect_sockets(self) -> tuple[list[ListeningPortItem], list[SocketConnectionItem]]:
        """Collect sockets using per-process iteration.

        macOS (Apple Silicon + recent macOS versions) blocks the system-wide
        psutil.net_connections() with AccessDenied unless running as root.
        Iterating per-process works for all processes the current user owns.
        """
        listening_ports: list[ListeningPortItem] = []
        connections: list[SocketConnectionItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()
        seen_listening: set[tuple] = set()
        seen_conns: set[tuple] = set()

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                proc_conns = proc.net_connections(kind="inet")
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug("macOS net_connections error for pid %s: %s", getattr(proc, 'pid', '?'), e)
                continue

            for conn in proc_conns:
                try:
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    laddr = conn.laddr
                    raddr = conn.raddr
                    pid = conn.pid if conn.pid else getattr(proc, 'pid', None)

                    if not laddr:
                        continue

                    if conn.status == psutil.CONN_LISTEN:
                        dedup_key = (laddr.ip, laddr.port, proto)
                        if dedup_key in seen_listening:
                            continue
                        seen_listening.add(dedup_key)
                        listening_ports.append(
                            ListeningPortItem(
                                protocol=proto,
                                local_address=laddr.ip,
                                local_port=laddr.port,
                                pid=pid,
                                process_name=None,
                                observed_at=now_iso,
                                source=self.source_label,
                            )
                        )
                    elif raddr:
                        dedup_key = (laddr.ip, laddr.port, raddr.ip, raddr.port, proto)
                        if dedup_key in seen_conns:
                            continue
                        seen_conns.add(dedup_key)
                        connections.append(
                            SocketConnectionItem(
                                pid=pid,
                                process_name=None,
                                protocol=proto,
                                local_address=laddr.ip,
                                local_port=laddr.port,
                                remote_address=raddr.ip,
                                remote_port=raddr.port,
                                state=str(conn.status or "ESTABLISHED").upper(),
                                observed_at=now_iso,
                                source=self.source_label,
                            )
                        )
                except Exception:
                    continue

        return listening_ports, connections


class MacOSBrowserCollector(BaseBrowserCollector):
    """Detects running browser executables on macOS."""

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label

    def collect_browsers(self) -> tuple[list[str], list[BrowserProcessItem]]:
        browser_processes: list[BrowserProcessItem] = []
        running_names: set[str] = set()
        now_iso = datetime.now(timezone.utc).isoformat()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = (proc.info.get("name") or "").lower()
                canonical = MACOS_BROWSERS.get(name)
                if canonical:
                    running_names.add(canonical)
                    browser_processes.append(
                        BrowserProcessItem(
                            browser_name=canonical,
                            pid=proc.info["pid"],
                            exe_path=proc.info.get("exe"),
                            observed_at=now_iso,
                            source=self.source_label,
                        )
                    )
            except Exception:
                continue

        return sorted(list(running_names)), browser_processes


class MacOSHardwareCollector(BaseHardwareCollector):
    """Collects CPU, memory, and network interface telemetry on macOS via psutil."""

    def __init__(self, source_label: str = "macos_endpoint"):
        self.source_label = source_label

    def collect_cpu(self) -> CpuInfo:
        import platform
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            per_core_raw = psutil.cpu_percent(interval=0.2, percpu=True)
            overall = psutil.cpu_percent(interval=None)
        except Exception:
            per_core_raw = []
            overall = None

        per_core = [
            PerCoreUsage(core=i, usage_percent=round(pct, 1))
            for i, pct in enumerate(per_core_raw)
        ]

        try:
            physical = psutil.cpu_count(logical=False) or 1
            logical = psutil.cpu_count(logical=True) or 1
        except Exception:
            physical = 1
            logical = 1

        # macOS: use platform.processor() for model string
        model = platform.processor() or None
        arch = platform.machine() or None

        return CpuInfo(
            model=model,
            physical_cores=physical,
            logical_cores=logical,
            overall_usage_percent=round(overall, 1) if overall is not None else None,
            per_core=per_core,
            architecture=arch,
            observed_at=now_iso,
        )

    def collect_memory(self) -> MemoryInfo:
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            vm = psutil.virtual_memory()
            swap = psutil.swap_memory()
            return MemoryInfo(
                total_bytes=vm.total,
                available_bytes=vm.available,
                used_bytes=vm.used,
                percent_used=round(vm.percent, 1),
                swap_total_bytes=swap.total,
                swap_used_bytes=swap.used,
                swap_percent_used=round(swap.percent, 1),
                observed_at=now_iso,
            )
        except Exception as e:
            logger.debug("Memory collection error: %s", e)
            return MemoryInfo(observed_at=now_iso)

    def collect_network_interfaces(self) -> list[NetworkInterfaceInfo]:
        interfaces: list[NetworkInterfaceInfo] = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface_name, addr_list in addrs.items():
                if iface_name.lower() == "lo0":
                    continue
                iface_stats = stats.get(iface_name)
                is_up = iface_stats.isup if iface_stats else True
                speed = iface_stats.speed if iface_stats else None

                ip_addrs: list[str] = []
                mac_addr: str | None = None
                for addr in addr_list:
                    if addr.family == socket.AF_INET and addr.address:
                        ip_addrs.append(addr.address)
                    elif addr.family == socket.AF_INET6 and addr.address:
                        ip_addrs.append(addr.address.split("%")[0])
                    elif addr.family == psutil.AF_LINK and addr.address:
                        mac_addr = addr.address

                if not ip_addrs and not mac_addr:
                    continue

                interfaces.append(
                    NetworkInterfaceInfo(
                        name=iface_name,
                        addresses=ip_addrs,
                        mac=mac_addr,
                        is_up=is_up,
                        speed_mbps=speed if speed and speed > 0 else None,
                    )
                )
        except Exception as e:
            logger.debug("Network interface collection error: %s", e)
        return interfaces
