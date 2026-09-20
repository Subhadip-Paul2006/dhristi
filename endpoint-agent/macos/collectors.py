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
    BaseProcessCollector,
    BaseServiceCollector,
    BaseSocketCollector,
    BaseSoftwareCollector,
)
from collectors.contracts import (
    BrowserProcessItem,
    ListeningPortItem,
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

                processes.append(
                    ProcessItem(
                        pid=pid,
                        name=name,
                        ppid=ppid,
                        exe_path=exe_path,
                        cmdline=cmdline,
                        category=category,
                        start_time=start_time_iso,
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
        listening_ports: list[ListeningPortItem] = []
        connections: list[SocketConnectionItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            net_conns = psutil.net_connections(kind="inet")
        except Exception as e:
            logger.debug("Failed to query macOS net_connections: %s", e)
            return listening_ports, connections

        for conn in net_conns:
            try:
                proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                laddr = conn.laddr
                raddr = conn.raddr
                pid = conn.pid

                if not laddr:
                    continue

                if conn.status == psutil.CONN_LISTEN:
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
