# Drishti v0.1 — agent subnet auto-discovery + guard tests | 18-Jul-2026
"""discover_subnets() must enumerate candidates from interfaces + routes with
the REAL netmask (never a guessed /24) and correct evidence, refuse to sweep a
discovered /16, reject public/loopback/link-local CIDRs, and gate everything
behind consent — auto-discovery widens the input, never the permissions."""
import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).parent.parent.parent / "agent" / "drishti_watch.py"
_spec = importlib.util.spec_from_file_location("drishti_watch", _PATH)
dw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dw)


# ── mocked OS command output ──────────────────────────────────────────────────
_IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 192.168.1.42 netmask 0xfffffc00 broadcast 192.168.3.255
en1: flags=8863<UP,BROADCAST> mtu 1500
	inet 10.0.5.9 netmask 0xffffff00
"""

_NETSTAT = """\
Routing tables

Internet:
Destination        Gateway            Flags
default            192.168.1.1        UGScg
10.8.0.0/24        192.168.1.1        UGSc
172.16.0.0/16      192.168.1.1        UGSc
127.0.0.1          127.0.0.1          UGcg
"""


def _fake_run_macos(cmd):
    if cmd[0] == "ifconfig":
        return _IFCONFIG
    if cmd[0] == "netstat":
        return _NETSTAT
    return ""


@pytest.fixture(autouse=True)
def _force_macos(monkeypatch):
    monkeypatch.setattr(dw.platform, "system", lambda: "Darwin")


def test_interfaces_use_real_netmask_not_slash24():
    ifaces = dw._list_interfaces(_fake_run_macos)
    by_ip = {i["ip"]: i["cidr"] for i in ifaces}
    # en0 has a /22 netmask (0xfffffc00) — must NOT be truncated to /24
    assert by_ip["192.168.1.42"] == "192.168.0.0/22"
    assert by_ip["10.0.5.9"] == "10.0.5.0/24"
    # loopback dropped
    assert "127.0.0.1" not in by_ip


def test_routes_carry_gateway_evidence():
    routes = dw._list_routes(_fake_run_macos)
    cidrs = {r["cidr"]: r["gw"] for r in routes}
    assert cidrs.get("10.8.0.0/24") == "192.168.1.1"
    assert cidrs.get("172.16.0.0/16") == "192.168.1.1"


def test_discover_reports_slash16_skipped_never_swept(monkeypatch):
    # every candidate "reachable" so only the size cap can skip the /16
    monkeypatch.setattr(dw, "_ping", lambda ip, timeout_ms=1000: True)
    cands = dw.discover_subnets(
        max_hosts=1024,
        run_ifaces=_fake_run_macos, run_routes=_fake_run_macos,
        ping=lambda ip, timeout_ms=1000: True,
    )
    by_cidr = {c["cidr"]: c for c in cands}

    big = by_cidr["172.16.0.0/16"]
    assert big["scan"] is False
    assert "exceeds" in big["verdict"] and "SKIPPED" in big["verdict"]

    onlink = by_cidr["192.168.0.0/22"]
    assert onlink["kind"] == "on-link"
    assert onlink["scan"] is True
    assert "interface en0" in onlink["evidence"]

    routed = by_cidr["10.8.0.0/24"]
    assert routed["kind"] == "routed"
    assert "route via 192.168.1.1" in routed["evidence"]


def test_unreachable_routed_subnet_reported_not_scanned():
    cands = dw.discover_subnets(
        max_hosts=1024,
        run_ifaces=_fake_run_macos, run_routes=_fake_run_macos,
        ping=lambda ip, timeout_ms=1000: False,  # nothing answers
    )
    routed = next(c for c in cands if c["cidr"] == "10.8.0.0/24")
    assert routed["scan"] is False
    assert "unreachable" in routed["verdict"]


@pytest.mark.parametrize("cidr,ok", [
    ("192.168.1.0/24", True),
    ("10.0.5.0/24", True),
    ("8.8.8.0/24", False),       # public
    ("127.0.0.0/24", False),     # loopback
    ("169.254.0.0/16", False),   # link-local
    ("10.0.0.0/16", False),      # oversized
])
def test_cidr_guard(cidr, ok):
    net, reason = dw._cidr_guard(cidr, 1024)
    assert (net is not None) is ok
    if not ok:
        assert reason


def test_explicit_public_cidr_rejected():
    cands = dw.resolve_subnets("8.8.8.0/24", 1024)
    assert cands[0]["scan"] is False
    assert "RFC-1918" in cands[0]["verdict"]


def test_consent_gate_refuses_even_with_auto(monkeypatch):
    # consent covers auto-discovered subnets too — no back door
    with pytest.raises(SystemExit) as e:
        dw.run_devices("http://x", "t", "h", 8.0, consent=False, subnets_arg="auto")
    assert e.value.code == 2


def test_wifi_unavailable_never_fabricates(monkeypatch):
    monkeypatch.setattr(dw.platform, "system", lambda: "Darwin")

    def _no_tool(cmd):
        raise FileNotFoundError("airport gone")

    out = dw.discover_wifi(_no_tool)
    assert out["available"] is False
    assert out["networks"] == []
    assert out["reason"]


def test_wifi_linux_parses_and_flags_joined(monkeypatch):
    monkeypatch.setattr(dw.platform, "system", lambda: "Linux")
    nmcli = "yes:HomeNet:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:82:WPA2\n" \
            "no:Guest:11\\:22\\:33\\:44\\:55\\:66:11:47:WPA2\n"
    out = dw.discover_wifi(lambda cmd: nmcli)
    assert out["available"] is True
    assert out["joined_ssid"] == "HomeNet"
    joined = {n["ssid"]: n["joined"] for n in out["networks"]}
    assert joined == {"HomeNet": True, "Guest": False}
