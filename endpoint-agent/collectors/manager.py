# Drishti v0.1 — Collector Manager | Phase 02 (rev 2 — hardware telemetry)
from __future__ import annotations

import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any

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
    ProcessItem,
    ServiceItem,
    SocketConnectionItem,
    SoftwareItem,
    TelemetryBatch,
)
from common.identity import DeviceIdentity

logger = logging.getLogger("drishti.agent.collectors")


class CollectorManager:
    """Coordinates OS-specific telemetry collectors with failure isolation and independent schedules."""

    def __init__(
        self,
        identity: DeviceIdentity,
        process_collector: BaseProcessCollector | None = None,
        software_collector: BaseSoftwareCollector | None = None,
        service_collector: BaseServiceCollector | None = None,
        socket_collector: BaseSocketCollector | None = None,
        browser_collector: BaseBrowserCollector | None = None,
        hardware_collector: BaseHardwareCollector | None = None,
        software_interval_seconds: float = 300.0,
    ):
        self.identity = identity
        self.software_interval_seconds = software_interval_seconds

        # Resolve collectors based on OS if not explicitly injected
        os_name = identity.os.lower()
        if os_name == "windows":
            from windows.collectors import (
                WindowsBrowserCollector,
                WindowsHardwareCollector,
                WindowsProcessCollector,
                WindowsServiceCollector,
                WindowsSocketCollector,
                WindowsSoftwareCollector,
            )
            self.process_collector = process_collector or WindowsProcessCollector()
            self.software_collector = software_collector or WindowsSoftwareCollector()
            self.service_collector = service_collector or WindowsServiceCollector()
            self.socket_collector = socket_collector or WindowsSocketCollector()
            self.browser_collector = browser_collector or WindowsBrowserCollector()
            self.hardware_collector = hardware_collector or WindowsHardwareCollector()
        else:
            from macos.collectors import (
                MacOSBrowserCollector,
                MacOSHardwareCollector,
                MacOSProcessCollector,
                MacOSServiceCollector,
                MacOSSocketCollector,
                MacOSSoftwareCollector,
            )
            self.process_collector = process_collector or MacOSProcessCollector()
            self.software_collector = software_collector or MacOSSoftwareCollector()
            self.service_collector = service_collector or MacOSServiceCollector()
            self.socket_collector = socket_collector or MacOSSocketCollector()
            self.browser_collector = browser_collector or MacOSBrowserCollector()
            self.hardware_collector = hardware_collector or MacOSHardwareCollector()

        # Cache for slow-cycle software inventory
        self._cached_software: list[SoftwareItem] = []
        self._last_software_collect: float = 0.0

    def collect_all(self, force_slow_collect: bool = False) -> TelemetryBatch:
        """Run all collectors with per-collector error isolation."""
        processes: list[ProcessItem] = []
        active_apps: list[str] = []
        services: list[ServiceItem] = []
        listening_ports: list[ListeningPortItem] = []
        connections: list[SocketConnectionItem] = []
        running_browsers: list[str] = []
        browser_procs: list[BrowserProcessItem] = []
        cpu_info: CpuInfo | None = None
        memory_info: MemoryInfo | None = None
        network_interfaces: list[NetworkInterfaceInfo] = []

        now_mono = time.monotonic()

        # 1. Hardware Collection (CPU, Memory, Network Interfaces) — always fast-cycle
        try:
            cpu_info = self.hardware_collector.collect_cpu()
        except Exception as e:
            logger.warning("[Drishti Collector] CPU collection failed: %s", e)

        try:
            memory_info = self.hardware_collector.collect_memory()
        except Exception as e:
            logger.warning("[Drishti Collector] Memory collection failed: %s", e)

        try:
            network_interfaces = self.hardware_collector.collect_network_interfaces()
        except Exception as e:
            logger.warning("[Drishti Collector] Network interface collection failed: %s", e)

        # 2. Process Collection
        try:
            processes, active_apps = self.process_collector.collect_processes()
        except Exception as e:
            logger.warning("[Drishti Collector] Process collection failed: %s", e)

        # 3. Service Collection
        try:
            services = self.service_collector.collect_services()
        except Exception as e:
            logger.warning("[Drishti Collector] Service collection failed: %s", e)

        # 4. Socket Collection
        try:
            listening_ports, connections = self.socket_collector.collect_sockets()
        except Exception as e:
            logger.warning("[Drishti Collector] Socket collection failed: %s", e)

        # 5. Browser Process Collection
        try:
            running_browsers, browser_procs = self.browser_collector.collect_browsers()
        except Exception as e:
            logger.warning("[Drishti Collector] Browser collection failed: %s", e)

        # 6. Software Inventory (Slow Cycle)
        if force_slow_collect or (now_mono - self._last_software_collect >= self.software_interval_seconds):
            try:
                self._cached_software = self.software_collector.collect_software()
                self._last_software_collect = now_mono
                logger.info(
                    "[Drishti Collector] Gathered %d installed software items",
                    len(self._cached_software),
                )
            except Exception as e:
                logger.warning("[Drishti Collector] Software inventory collection failed: %s", e)

        now_iso = datetime.now(timezone.utc).isoformat()
        os_info_str = f"{self.identity.os} {self.identity.os_version}"

        return TelemetryBatch(
            agent_id=self.identity.agent_id,
            device_id=self.identity.device_id,
            hostname=self.identity.hostname,
            os_name=self.identity.os,
            os_version=self.identity.os_version,
            timestamp=now_iso,
            endpoint_processes=processes,
            active_apps=active_apps,
            installed_software=self._cached_software,
            services=services,
            listening_ports=listening_ports,
            process_connections=connections,
            installed_browsers=running_browsers,
            browser_processes=browser_procs,
            os_info=os_info_str,
            cpu_info=cpu_info,
            memory_info=memory_info,
            network_interfaces=network_interfaces,
        )
