# Drishti v0.1 — URL trust SSRF hardening tests | 11-Jul-2026
"""URL Trust Analyzer — network.py SSRF/DoS hardening.

These exercise the safety seams directly (no real sockets): resolved IPs are
checked against private/loopback/link-local/reserved/multicast ranges before
any TCP/TLS/HTTP connection, redirects are re-validated hop by hop, response
bodies are capped, and a stalling DNS server can't hang past the configured
timeout.
"""
from __future__ import annotations

import socket
import sys
import time
import types
from datetime import datetime, timezone
from unittest.mock import patch

import httpx
import pytest

from app.services.urltrust import network, whois_lookup


# ---- _is_safe_ip: internal/reserved ranges are blocked, public IPs pass ----

@pytest.mark.parametrize("ip", [
    "127.0.0.1",        # loopback
    "10.1.2.3",          # RFC1918 private
    "172.16.0.5",        # RFC1918 private
    "192.168.1.1",       # RFC1918 private
    "169.254.169.254",   # link-local / cloud metadata
    "::1",                # IPv6 loopback
    "fc00::1",            # IPv6 unique local
    "224.0.0.1",          # multicast
])
def test_is_safe_ip_blocks_internal_ranges(ip):
    assert network._is_safe_ip(ip) is False


@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"])
def test_is_safe_ip_allows_public_ips(ip):
    assert network._is_safe_ip(ip) is True


def test_is_safe_ip_rejects_garbage():
    assert network._is_safe_ip("not-an-ip") is False


# ---- resolve_dns / _resolve_ips: bounded by urltrust_timeout_seconds -------

def test_resolve_ips_times_out_on_stalled_dns():
    def slow_getaddrinfo(host, port):
        time.sleep(0.3)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    with patch.object(socket, "getaddrinfo", side_effect=slow_getaddrinfo):
        with pytest.raises(TimeoutError):
            network._resolve_ips("example.com", timeout=0.05)


def test_resolve_dns_degrades_to_none_on_timeout(monkeypatch):
    class FakeSettings:
        urltrust_timeout_seconds = 0.05

    monkeypatch.setattr(network, "get_settings", lambda: FakeSettings())

    def slow_getaddrinfo(host, port):
        time.sleep(0.3)
        return []

    with patch.object(socket, "getaddrinfo", side_effect=slow_getaddrinfo):
        assert network.resolve_dns("example.com") is None


# ---- inspect_tls / http_probe: blocked before any connection is attempted --

def test_inspect_tls_blocks_unsafe_ip_without_connecting(monkeypatch):
    monkeypatch.setattr(network, "_safe_ips", lambda host, timeout: None)

    def boom(*args, **kwargs):
        raise AssertionError("must not attempt a TCP connection to an unsafe host")

    monkeypatch.setattr(socket, "create_connection", boom)
    assert network.inspect_tls("169.254.169.254") is None


def test_http_probe_blocks_unsafe_host_without_requesting(monkeypatch):
    monkeypatch.setattr(network, "_safe_ips", lambda host, timeout: None)
    assert network.http_probe("http://169.254.169.254/latest/meta-data") is None


def test_http_probe_revalidates_each_redirect_hop(monkeypatch):
    """A URL that resolves safely at submission time must not be able to
    302 the live fetch into an internal address."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "good.example", "must not fetch the blocked hop"
        return httpx.Response(302, headers={"location": "http://169.254.169.254/secret"})

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", fake_client)

    def fake_safe_ips(host, timeout):
        return ["93.184.216.34"] if host == "good.example" else None

    monkeypatch.setattr(network, "_safe_ips", fake_safe_ips)

    assert network.http_probe("http://good.example/") is None


def test_http_probe_follows_safe_redirect_and_reports_chain(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        # The probe now connects to the validated IP and carries the real
        # hostname in the Host header (SSRF/DNS-rebind hardening), so route on
        # the Host header rather than request.url.host (which is the pinned IP).
        host = request.headers.get("host", "").split(":")[0]
        if host == "good.example":
            return httpx.Response(302, headers={"location": "https://also-good.example/final"})
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", fake_client)
    monkeypatch.setattr(network, "_safe_ips", lambda host, timeout: ["93.184.216.34"])

    result = network.http_probe("http://good.example/")
    assert result["status"] == 200
    assert result["final_url"] == "https://also-good.example/final"
    assert result["redirect_chain"] == [
        "http://good.example/",
        "https://also-good.example/final",
    ]


# ---- _drain: response body reading is capped -------------------------------

def test_drain_stops_reading_once_limit_reached():
    pulled = []

    def gen():
        for i in range(10_000):
            pulled.append(i)
            yield b"x" * 1024

    class FakeResponse:
        def iter_bytes(self):
            return gen()

    network._drain(FakeResponse(), limit=2048)
    assert len(pulled) <= 3


# ---- whois_lookup: WHOIS referral recursion is disabled --------------------

def test_domain_facts_disables_whois_recursion(monkeypatch):
    calls = {}

    class FakeNICClient:
        WHOIS_QUICK = 2

    def fake_whois(host, flags=0):
        calls["host"] = host
        calls["flags"] = flags
        return {
            "creation_date": datetime(2020, 1, 1, tzinfo=timezone.utc),
            "expiration_date": None,
            "registrar": "Fake Registrar",
        }

    fake_module = types.SimpleNamespace(whois=fake_whois, NICClient=FakeNICClient)
    monkeypatch.setitem(sys.modules, "whois", fake_module)

    facts = whois_lookup.domain_facts("example.com")

    assert calls["flags"] == FakeNICClient.WHOIS_QUICK
    assert facts["registrar"] == "Fake Registrar"


def test_domain_facts_returns_none_when_whois_raises(monkeypatch):
    def fake_whois(host, flags=0):
        raise OSError("blocked outbound")

    fake_module = types.SimpleNamespace(
        whois=fake_whois, NICClient=types.SimpleNamespace(WHOIS_QUICK=2)
    )
    monkeypatch.setitem(sys.modules, "whois", fake_module)

    assert whois_lookup.domain_facts("example.com") is None


def test_domain_facts_returns_none_when_quick_flag_unavailable(monkeypatch):
    """If a future/older python-whois has no WHOIS_QUICK, we must not fall
    back to a recursive lookup — treat WHOIS as unavailable instead."""

    def fake_whois(host, flags=0):
        raise AssertionError("must not call whois.whois without disabling recursion")

    fake_module = types.SimpleNamespace(whois=fake_whois)  # no NICClient attribute
    monkeypatch.setitem(sys.modules, "whois", fake_module)

    assert whois_lookup.domain_facts("example.com") is None
