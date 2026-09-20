# Drishti v0.1 — Windows Telemetry Collectors | Phase 02
from __future__ import annotations

import logging
import os
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

logger = logging.getLogger("drishti.agent.windows")

# Standard Windows system binaries & core services
SYSTEM_PROCESS_NAMES = {
    "system",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "spoolsv.exe",
    "dasHost.exe",
    "sihost.exe",
    "taskhostw.exe",
    "explorer.exe",
    "ctfmon.exe",
    "securityhealthservice.exe",
    "smartscreen.exe",
    "searchindexer.exe",
    "runtimebroker.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "applicationframehost.exe",
}

# Known browser binaries mapping to canonical names
KNOWN_BROWSERS = {
    "chrome.exe": "Chrome",
    "msedge.exe": "Edge",
    "brave.exe": "Brave",
    "firefox.exe": "Firefox",
    "arc.exe": "Arc",
    "opera.exe": "Opera",
}

# Standard user-interactive software indicators
KNOWN_USER_APPS = {
    "code.exe": "Visual Studio Code",
    "devenv.exe": "Visual Studio",
    "notepad.exe": "Notepad",
    "notepad++.exe": "Notepad++",
    "calc.exe": "Calculator",
    "calculatorapp.exe": "Calculator",
    "slack.exe": "Slack",
    "discord.exe": "Discord",
    "teams.exe": "Microsoft Teams",
    "spotify.exe": "Spotify",
    "steam.exe": "Steam",
    "windowsterminal.exe": "Windows Terminal",
    "cmd.exe": "Command Prompt",
    "powershell.exe": "PowerShell",
    "pwsh.exe": "PowerShell Core",
    "python.exe": "Python",
    "node.exe": "Node.js",
    "git.exe": "Git",
    "docker.exe": "Docker",
}


class WindowsProcessCollector(BaseProcessCollector):
    """Gathers genuine Windows running processes and classifies them deterministically."""

    def __init__(self, source_label: str = "windows_endpoint"):
        self.source_label = source_label

    def _classify_process(self, name: str, exe_path: str | None, username: str | None) -> str:
        lower_name = name.lower()
        if lower_name in SYSTEM_PROCESS_NAMES:
            return ProcessCategory.SYSTEM_PROCESS.value
        if lower_name in KNOWN_BROWSERS or lower_name in KNOWN_USER_APPS:
            return ProcessCategory.USER_APPLICATION.value

        # Path heuristics: system32 / syswow64 / Windows folder usually system/background
        if exe_path:
            lower_path = exe_path.lower()
            if "\\windows\\system32" in lower_path or "\\windows\\syswow64" in lower_path:
                return ProcessCategory.SYSTEM_PROCESS.value
            if "\\program files" in lower_path or "\\appdata\\local\\programs" in lower_path:
                return ProcessCategory.USER_APPLICATION.value

        return ProcessCategory.BACKGROUND_PROCESS.value

    def collect_processes(self) -> tuple[list[ProcessItem], list[str]]:
        processes: list[ProcessItem] = []
        active_apps_set: set[str] = set()
        now_iso = datetime.now(timezone.utc).isoformat()

        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time", "username"]):
            try:
                info = proc.info
                name = info.get("name") or "unknown"
                pid = info.get("pid")
                if pid is None:
                    continue

                ppid = info.get("ppid")
                exe_path = info.get("exe")
                cmdline = info.get("cmdline")
                username = info.get("username")

                create_time = info.get("create_time")
                start_time_iso = (
                    datetime.fromtimestamp(create_time, tz=timezone.utc).isoformat()
                    if create_time
                    else None
                )

                category = self._classify_process(name, exe_path, username)

                if category == ProcessCategory.USER_APPLICATION.value:
                    friendly_name = KNOWN_BROWSERS.get(name.lower()) or KNOWN_USER_APPS.get(name.lower()) or name
                    active_apps_set.add(friendly_name)

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
                logger.debug("Error inspecting process PID %s: %s", getattr(proc, "pid", "unknown"), e)
                continue

        return processes, sorted(list(active_apps_set))


class WindowsSoftwareCollector(BaseSoftwareCollector):
    """Gathers genuine installed software inventory from Windows Registry uninstall keys."""

    def __init__(self, source_label: str = "windows_endpoint"):
        self.source_label = source_label

    def collect_software(self) -> list[SoftwareItem]:
        software_list: list[SoftwareItem] = []
        seen_keys: set[tuple[str, str | None]] = set()
        now_iso = datetime.now(timezone.utc).isoformat()

        if not sys.platform.startswith("win"):
            return software_list

        import winreg

        registry_targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0),
        ]

        for root_hive, subkey_path, flags in registry_targets:
            try:
                with winreg.OpenKey(root_hive, subkey_path, 0, winreg.KEY_READ | flags) as root_key:
                    num_subkeys = winreg.QueryInfoKey(root_key)[0]
                    for idx in range(num_subkeys):
                        try:
                            subkey_name = winreg.EnumKey(root_key, idx)
                            with winreg.OpenKey(root_key, subkey_name, 0, winreg.KEY_READ | flags) as app_key:
                                try:
                                    display_name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                                except FileNotFoundError:
                                    continue  # Skip entries with no display name

                                if not display_name or not isinstance(display_name, str) or not display_name.strip():
                                    continue

                                display_name = display_name.strip()

                                # Skip Windows updates / Hotfixes without proper application titles
                                if display_name.startswith("KB") and display_name[2:].isdigit():
                                    continue

                                try:
                                    display_version, _ = winreg.QueryValueEx(app_key, "DisplayVersion")
                                    display_version = str(display_version).strip() if display_version else None
                                except FileNotFoundError:
                                    display_version = None

                                try:
                                    publisher, _ = winreg.QueryValueEx(app_key, "Publisher")
                                    publisher = str(publisher).strip() if publisher else None
                                except FileNotFoundError:
                                    publisher = None

                                try:
                                    install_loc, _ = winreg.QueryValueEx(app_key, "InstallLocation")
                                    install_loc = str(install_loc).strip() if install_loc else None
                                except FileNotFoundError:
                                    install_loc = None

                                dedupe_key = (display_name.lower(), display_version)
                                if dedupe_key in seen_keys:
                                    continue
                                seen_keys.add(dedupe_key)

                                software_list.append(
                                    SoftwareItem(
                                        name=display_name,
                                        version=display_version,
                                        publisher=publisher,
                                        install_location=install_loc,
                                        observed_at=now_iso,
                                        source=self.source_label,
                                    )
                                )
                        except Exception:
                            continue
            except Exception as e:
                logger.debug("Could not inspect registry hive %s\\%s: %s", root_hive, subkey_path, e)
                continue

        software_list.sort(key=lambda s: s.name.lower())
        return software_list


class WindowsServiceCollector(BaseServiceCollector):
    """Enumerates local Windows services via psutil."""

    def __init__(self, source_label: str = "windows_endpoint"):
        self.source_label = source_label

    def collect_services(self) -> list[ServiceItem]:
        services: list[ServiceItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        if not hasattr(psutil, "win_service_iter"):
            return services

        try:
            for s in psutil.win_service_iter():
                try:
                    info = s.as_dict()
                    name = info.get("name") or "unknown"
                    display_name = info.get("display_name") or name
                    status = str(info.get("status") or "UNKNOWN").upper()
                    start_type = str(info.get("start_type") or "UNKNOWN").upper()

                    services.append(
                        ServiceItem(
                            name=name,
                            display_name=display_name,
                            status=status,
                            start_type=start_type,
                            observed_at=now_iso,
                            source=self.source_label,
                        )
                    )
                except Exception:
                    continue
        except Exception as e:
            logger.debug("Error enumerating Windows services: %s", e)

        services.sort(key=lambda x: x.name.lower())
        return services


class WindowsSocketCollector(BaseSocketCollector):
    """Gathers local listening sockets and process network connections."""

    def __init__(self, source_label: str = "windows_endpoint"):
        self.source_label = source_label

    def collect_sockets(self) -> tuple[list[ListeningPortItem], list[SocketConnectionItem]]:
        listening_ports: list[ListeningPortItem] = []
        connections: list[SocketConnectionItem] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # Build quick PID -> Process Name cache
        pid_names: dict[int, str] = {}
        for p in psutil.process_iter(["pid", "name"]):
            try:
                pid_names[p.info["pid"]] = p.info["name"]
            except Exception:
                continue

        try:
            net_conns = psutil.net_connections(kind="inet")
        except Exception as e:
            logger.debug("Failed to query net_connections: %s", e)
            return listening_ports, connections

        for conn in net_conns:
            try:
                proto = "TCP" if conn.type == psutil.SOCK_STREAM else "UDP"
                laddr = conn.laddr
                raddr = conn.raddr
                pid = conn.pid
                proc_name = pid_names.get(pid) if pid else None

                if not laddr:
                    continue

                local_ip = laddr.ip
                local_port = laddr.port

                if conn.status == psutil.CONN_LISTEN:
                    listening_ports.append(
                        ListeningPortItem(
                            protocol=proto,
                            local_address=local_ip,
                            local_port=local_port,
                            pid=pid,
                            process_name=proc_name,
                            observed_at=now_iso,
                            source=self.source_label,
                        )
                    )
                elif raddr:
                    remote_ip = raddr.ip
                    remote_port = raddr.port
                    state = str(conn.status or "ESTABLISHED").upper()

                    connections.append(
                        SocketConnectionItem(
                            pid=pid,
                            process_name=proc_name,
                            protocol=proto,
                            local_address=local_ip,
                            local_port=local_port,
                            remote_address=remote_ip,
                            remote_port=remote_port,
                            state=state,
                            observed_at=now_iso,
                            source=self.source_label,
                        )
                    )
            except Exception:
                continue

        # Sort for deterministic reporting
        listening_ports.sort(key=lambda x: (x.local_port, x.protocol))
        connections.sort(key=lambda x: (x.remote_address, x.remote_port))
        return listening_ports, connections


class WindowsBrowserCollector(BaseBrowserCollector):
    """Detects running browser executables without fabricating tabs or active URLs."""

    def __init__(self, source_label: str = "windows_endpoint"):
        self.source_label = source_label

    def collect_browsers(self) -> tuple[list[str], list[BrowserProcessItem]]:
        browser_processes: list[BrowserProcessItem] = []
        running_browser_names: set[str] = set()
        now_iso = datetime.now(timezone.utc).isoformat()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = (proc.info.get("name") or "").lower()
                canonical = KNOWN_BROWSERS.get(name)
                if canonical:
                    running_browser_names.add(canonical)
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

        return sorted(list(running_browser_names)), browser_processes
