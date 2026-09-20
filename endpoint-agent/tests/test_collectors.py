# Drishti v0.1 — Endpoint Telemetry Unit Tests | Phase 02
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from collectors.contracts import (
    BrowserProcessItem,
    ListeningPortItem,
    ProcessCategory,
    ProcessItem,
    ServiceItem,
    SocketConnectionItem,
    SoftwareItem,
    TelemetryBatch,
)
from collectors.manager import CollectorManager
from common.identity import create_new_identity
from windows.collectors import (
    WindowsBrowserCollector,
    WindowsProcessCollector,
    WindowsServiceCollector,
    WindowsSocketCollector,
    WindowsSoftwareCollector,
)
from macos.collectors import (
    MacOSBrowserCollector,
    MacOSProcessCollector,
    MacOSServiceCollector,
    MacOSSocketCollector,
    MacOSSoftwareCollector,
)


@pytest.fixture
def mock_identity():
    return create_new_identity(
        hostname="lab-workstation",
        os_name="windows",
        os_version="11.0",
        mac="00:11:22:33:44:55",
        current_ip="192.168.1.50",
        agent_version="0.1.0",
    )


def test_process_categorization_windows():
    collector = WindowsProcessCollector()
    
    # User application in AppData
    cat_user = collector._classify_process("code.exe", r"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code\Code.exe", "tester")
    assert cat_user == ProcessCategory.USER_APPLICATION.value

    # System process in System32
    cat_sys = collector._classify_process("svchost.exe", r"C:\Windows\System32\svchost.exe", "SYSTEM")
    assert cat_sys == ProcessCategory.SYSTEM_PROCESS.value

    # Background service without user path
    cat_bg = collector._classify_process("custom_worker.exe", r"C:\Services\worker.exe", "SYSTEM")
    assert cat_bg == ProcessCategory.BACKGROUND_PROCESS.value


def test_browser_detection_windows():
    collector = WindowsBrowserCollector()

    class MockProc:
        def __init__(self, pid: int, name: str, exe: str):
            self.info = {"pid": pid, "name": name, "exe": exe}

    mock_procs = [
        MockProc(1001, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        MockProc(1002, "msedge.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        MockProc(1003, "notepad.exe", r"C:\Windows\notepad.exe"),
    ]

    with patch("psutil.process_iter", return_value=mock_procs):
        browsers, procs = collector.collect_browsers()
        assert "Chrome" in browsers
        assert "Edge" in browsers
        assert len(procs) == 2
        assert any(bp.browser_name == "Chrome" and bp.pid == 1001 for bp in procs)
        assert any(bp.browser_name == "Edge" and bp.pid == 1002 for bp in procs)


def test_process_categorization_macos():
    collector = MacOSProcessCollector()

    # User Application in /Applications
    cat_user = collector._classify_process("Safari", "/Applications/Safari.app/Contents/MacOS/Safari")
    assert cat_user == ProcessCategory.USER_APPLICATION.value

    # System process
    cat_sys = collector._classify_process("launchd", "/sbin/launchd")
    assert cat_sys == ProcessCategory.SYSTEM_PROCESS.value

    # Background daemon
    cat_bg = collector._classify_process("agent_daemon", "/Library/Drishti/agent_daemon")
    assert cat_bg == ProcessCategory.BACKGROUND_PROCESS.value


def test_browser_detection_macos():
    collector = MacOSBrowserCollector()

    class MockProc:
        def __init__(self, pid: int, name: str, exe: str):
            self.info = {"pid": pid, "name": name, "exe": exe}

    mock_procs = [
        MockProc(2001, "Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        MockProc(2002, "Slack", "/Applications/Slack.app/Contents/MacOS/Slack"),
    ]

    with patch("psutil.process_iter", return_value=mock_procs):
        browsers, procs = collector.collect_browsers()
        assert "Chrome" in browsers
        assert len(procs) == 1
        assert procs[0].pid == 2001


def test_collector_manager_isolation_on_collector_failure(mock_identity):
    """If a collector raises an unexpected exception, CollectorManager isolates it and completes the rest."""
    failing_proc_collector = MagicMock()
    failing_proc_collector.collect_processes.side_effect = RuntimeError("Process collection failed")

    mock_software_collector = MagicMock()
    mock_software_collector.collect_software.return_value = [
        SoftwareItem(name="Git", version="2.40.0", publisher="Git SCM", source="registry_test")
    ]

    mock_service_collector = MagicMock()
    mock_service_collector.collect_services.return_value = [
        ServiceItem(name="Spooler", display_name="Print Spooler", status="RUNNING")
    ]

    mock_socket_collector = MagicMock()
    mock_socket_collector.collect_sockets.return_value = (
        [ListeningPortItem(protocol="TCP", local_address="127.0.0.1", local_port=8000, pid=5000, process_name="uvicorn.exe")],
        [SocketConnectionItem(pid=5000, process_name="uvicorn.exe", protocol="TCP", local_address="127.0.0.1", local_port=8000, remote_address="127.0.0.1", remote_port=52341, state="ESTABLISHED")]
    )

    mock_browser_collector = MagicMock()
    mock_browser_collector.collect_browsers.return_value = (["Google Chrome"], [BrowserProcessItem(browser_name="Google Chrome", pid=1001)])

    mgr = CollectorManager(
        identity=mock_identity,
        process_collector=failing_proc_collector,
        software_collector=mock_software_collector,
        service_collector=mock_service_collector,
        socket_collector=mock_socket_collector,
        browser_collector=mock_browser_collector,
        software_interval_seconds=300.0,
    )

    # Collect all with force_slow_collect=True to trigger software collect
    batch = mgr.collect_all(force_slow_collect=True)

    # Even though process collection threw, other collectors succeeded
    assert batch.endpoint_processes == []
    assert len(batch.installed_software) == 1
    assert batch.installed_software[0].name == "Git"
    assert len(batch.services) == 1
    assert batch.services[0].name == "Spooler"
    assert len(batch.listening_ports) == 1
    assert batch.listening_ports[0].local_port == 8000
    assert len(batch.process_connections) == 1
    assert "Google Chrome" in batch.installed_browsers


def test_software_collection_slow_interval_caching(mock_identity):
    """Software collector runs on slow interval and caches result for fast cycles."""
    mock_software_collector = MagicMock()
    mock_software_collector.collect_software.return_value = [
        SoftwareItem(name="Python", version="3.11.0", publisher="Python Software Foundation")
    ]

    mgr = CollectorManager(
        identity=mock_identity,
        software_collector=mock_software_collector,
        software_interval_seconds=100.0,
    )

    # First run without force: slow cycle runs because last_software_collect is 0
    batch1 = mgr.collect_all(force_slow_collect=False)
    assert mock_software_collector.collect_software.call_count == 1
    assert len(batch1.installed_software) == 1

    # Second run immediately: within interval, cached results returned without re-invoking slow collector
    batch2 = mgr.collect_all(force_slow_collect=False)
    assert mock_software_collector.collect_software.call_count == 1
    assert len(batch2.installed_software) == 1


def test_telemetry_batch_serialization(mock_identity):
    batch = TelemetryBatch(
        agent_id=mock_identity.agent_id,
        device_id=mock_identity.device_id,
        hostname=mock_identity.hostname,
        os_name=mock_identity.os,
        os_version=mock_identity.os_version,
        endpoint_processes=[
            ProcessItem(name="code.exe", pid=1010, category="USER_APPLICATION")
        ],
        active_apps=["code.exe"],
        installed_software=[
            SoftwareItem(name="Node.js", version="20.10.0")
        ],
        services=[
            ServiceItem(name="wuauserv", display_name="Windows Update", status="RUNNING")
        ],
        listening_ports=[
            ListeningPortItem(protocol="TCP", local_address="0.0.0.0", local_port=443, pid=4, process_name="System")
        ],
        process_connections=[
            SocketConnectionItem(pid=1010, process_name="code.exe", protocol="TCP", local_address="192.168.1.50", local_port=52123, remote_address="20.42.73.27", remote_port=443, state="ESTABLISHED")
        ],
        installed_browsers=["Microsoft Edge"],
        browser_processes=[
            BrowserProcessItem(browser_name="Microsoft Edge", pid=3344)
        ],
        os_info="windows 11.0",
    )

    data = batch.to_dict()
    assert data["agent_id"] == mock_identity.agent_id
    assert data["device_id"] == mock_identity.device_id
    assert len(data["endpoint_processes"]) == 1
    assert data["endpoint_processes"][0]["name"] == "code.exe"
    assert len(data["installed_software"]) == 1
    assert data["installed_software"][0]["name"] == "Node.js"
    assert len(data["listening_ports"]) == 1
    assert data["listening_ports"][0]["local_port"] == 443
    assert len(data["process_connections"]) == 1
    assert data["process_connections"][0]["remote_port"] == 443
    assert "Microsoft Edge" in data["installed_browsers"]

