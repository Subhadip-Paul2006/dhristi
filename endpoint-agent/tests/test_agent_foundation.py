# Drishti v0.1 — Endpoint Agent Unit Tests | Phase 01
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from common.config import AgentConfig
from common.identity import DeviceIdentity, create_new_identity
from common.lifecycle import AgentState, LifecycleManager
from common.platform import BasePlatformAdapter, get_platform_adapter
from storage.state import AgentStateStore
from transport.client import (
    AgentUnauthorizedError,
    BackendTransport,
    SessionNotFoundError,
    TransportError,
)
from windows.platform import WindowsPlatformAdapter
from macos.platform import MacOSPlatformAdapter


class MockPlatformAdapter(BasePlatformAdapter):
    def get_hostname(self) -> str:
        return "test-workstation"

    def get_os_name(self) -> str:
        return "windows"

    def get_os_version(self) -> str:
        return "Windows 11 Pro 23H2"

    def get_mac_address(self) -> str | None:
        return "00:11:22:33:44:55"

    def get_current_ip(self) -> str | None:
        return "192.168.1.150"


def test_device_identity_generation():
    ident = create_new_identity(
        hostname="lab-pc",
        os_name="windows",
        os_version="11.0",
        mac="aa:bb:cc:dd:ee:ff",
        current_ip="10.0.0.5",
        agent_version="0.1.0",
    )
    assert ident.agent_id is not None
    assert ident.device_id is not None
    assert ident.hostname == "lab-pc"
    assert ident.os == "windows"
    assert ident.mac == "aa:bb:cc:dd:ee:ff"
    assert ident.agent_version == "0.1.0"
    assert ident.created_at is not None

    d = ident.to_dict()
    restored = DeviceIdentity.from_dict(d)
    assert restored.agent_id == ident.agent_id
    assert restored.device_id == ident.device_id


def test_identity_persistence():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        store = AgentStateStore(temp_dir)
        adapter = MockPlatformAdapter()
        ident1 = store.get_or_create_identity(adapter)
        assert ident1.hostname == "test-workstation"

        # Reload from same state directory — agent_id and device_id must be stable!
        store2 = AgentStateStore(temp_dir)
        ident2 = store2.get_or_create_identity(adapter)
        assert ident2.agent_id == ident1.agent_id
        assert ident2.device_id == ident1.device_id
        assert ident2.created_at == ident1.created_at
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_auth_credential_storage():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        store = AgentStateStore(temp_dir)
        token, org = store.load_auth()
        assert token is None
        assert org is None

        store.save_auth("secret_agent_token_12345", "org_abc_789")
        loaded_token, loaded_org = store.load_auth()
        assert loaded_token == "secret_agent_token_12345"
        assert loaded_org == "org_abc_789"

        store.clear_auth()
        cleared_token, _ = store.load_auth()
        assert cleared_token is None
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_agent_lifecycle_transitions():
    mgr = LifecycleManager(AgentState.STARTING)
    assert mgr.current_state == AgentState.STARTING

    transitions = []
    mgr.add_listener(lambda old, new: transitions.append((old, new)))

    mgr.transition_to(AgentState.WAITING_FOR_PAIRING)
    mgr.transition_to(AgentState.CONNECTED)
    mgr.transition_to(AgentState.RECONNECTING)
    mgr.transition_to(AgentState.STOPPED)

    assert len(transitions) == 4
    assert transitions[0] == (AgentState.STARTING, AgentState.WAITING_FOR_PAIRING)
    assert transitions[1] == (AgentState.WAITING_FOR_PAIRING, AgentState.CONNECTED)
    assert transitions[2] == (AgentState.CONNECTED, AgentState.RECONNECTING)
    assert transitions[3] == (AgentState.RECONNECTING, AgentState.STOPPED)


def test_windows_platform_adapter():
    adapter = WindowsPlatformAdapter()
    hostname = adapter.get_hostname()
    os_name = adapter.get_os_name()
    os_version = adapter.get_os_version()
    assert isinstance(hostname, str) and len(hostname) > 0
    assert os_name == "windows"
    assert "Windows" in os_version


def test_macos_platform_adapter_abstraction():
    adapter = MacOSPlatformAdapter()
    os_name = adapter.get_os_name()
    assert os_name == "darwin"
    # Testing genuine interface abstraction
    assert isinstance(adapter.get_hostname(), str)
