# Drishti v0.1 — real packet capture adapter | Phase 02
from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import threading
import time
from typing import Any, Callable

logger = logging.getLogger("drishti")


def detect_capture_backends() -> dict[str, Any]:
    """Detect available capture backends in the system: Zeek, TShark, and Scapy."""
    zeek_bin = shutil.which("zeek")
    tshark_bin = shutil.which("tshark")
    if not tshark_bin and platform.system() == "Windows":
        # Check standard Wireshark install path on Windows
        for candidate in (
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ):
            if os.path.isfile(candidate):
                tshark_bin = candidate
                break

    scapy_avail = False
    try:
        from scapy.all import sniff  # type: ignore
        scapy_avail = True
    except Exception:
        scapy_avail = False

    active_backend = "UNAVAILABLE"
    if zeek_bin:
        active_backend = "ZEEK"
    elif tshark_bin:
        active_backend = "TSHARK"
    elif scapy_avail:
        active_backend = "SCAPY"

    return {
        "zeek": {"available": bool(zeek_bin), "path": zeek_bin, "status": "AVAILABLE" if zeek_bin else "NOT INSTALLED"},
        "tshark": {"available": bool(tshark_bin), "path": tshark_bin, "status": "AVAILABLE" if tshark_bin else "NOT INSTALLED"},
        "scapy": {"available": scapy_avail, "status": "AVAILABLE" if scapy_avail else "NOT INSTALLED"},
        "active_backend": active_backend,
        "capture_source": f"{active_backend} / MONITORED INTERFACE" if active_backend != "UNAVAILABLE" else "UNAVAILABLE",
    }


class TrafficVisibilityChecker:
    """Evaluates real network visibility for a target device on the current interface.

    Truthful degradation:
    Distinguishes between local device (observable), reachable LAN peer whose unicast
    frames are switched away (UNAVAILABLE / LIMITED), and offline devices.
    """

    @staticmethod
    def is_local_ip(ip: str) -> bool:
        ip = ip.strip()
        if ip in ("127.0.0.1", "::1", "localhost"):
            return True
        try:
            import socket
            hostname = socket.gethostname()
            local_ips = socket.gethostbyname_ex(hostname)[2]
            return ip in local_ips
        except Exception:
            return False

    @staticmethod
    def ping_device(ip: str, timeout_ms: int = 800) -> bool:
        """Pings target IP using OS-native ICMP echo without hanging."""
        try:
            param = "-n" if platform.system() == "Windows" else "-c"
            timeout_param = "-w" if platform.system() == "Windows" else "-W"
            timeout_val = str(timeout_ms) if platform.system() == "Windows" else str(max(1, timeout_ms // 1000))
            cmd = ["ping", param, "1", timeout_param, timeout_val, ip.strip()]
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.0)
            return res.returncode == 0
        except Exception:
            return False

    @classmethod
    def evaluate_visibility(cls, target_ip: str, packets_observed: int, session_duration: float) -> dict[str, Any]:
        """Returns truthful visibility classification: VISIBLE, LIMITED, or UNAVAILABLE."""
        target_ip = target_ip.strip()
        is_local = cls.is_local_ip(target_ip)

        if packets_observed > 0:
            return {
                "visibility": "VISIBLE",
                "reason": "Observable traffic actively arriving on interface.",
                "is_local": is_local,
            }

        # Zero packets observed so far
        if is_local:
            if session_duration < 3.0:
                return {
                    "visibility": "LIMITED",
                    "reason": "Awaiting local traffic activity on monitored interface.",
                    "is_local": True,
                }
            return {
                "visibility": "LIMITED",
                "reason": "Local interface idle; generate HTTP/DNS traffic to observe flows.",
                "is_local": True,
            }

        # Remote device check
        if session_duration >= 4.0:
            is_reachable = cls.ping_device(target_ip)
            if is_reachable:
                return {
                    "visibility": "UNAVAILABLE",
                    "reason": "Target device is reachable, but its unicast traffic is not observable from this monitoring interface without switch port-mirroring (SPAN) or endpoint agent.",
                    "is_local": False,
                }
            else:
                return {
                    "visibility": "UNAVAILABLE",
                    "reason": "Target device is not responding to ICMP or network reachability probes.",
                    "is_local": False,
                }

        return {
            "visibility": "LIMITED",
            "reason": "Probing target device network visibility...",
            "is_local": is_local,
        }


class ScapyCaptureAdapter:
    """Asynchronously sniffs real packets strictly filtered for target_ip using Scapy.

    Filter: `ip host <target_ip>`
    Strictly isolated: only packets involving target_ip are captured.
    Gracefully handles missing WinPcap/Npcap/permissions without crashing.
    """

    def __init__(
        self,
        target_ip: str,
        on_packet: Callable[..., None],
        iface: str | None = None,
    ) -> None:
        self.target_ip = target_ip.strip()
        self.on_packet = on_packet
        self.iface = iface

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.is_running = False
        self.available = True
        self.error_message: str | None = None

        backends = detect_capture_backends()
        self.backend_info = backends
        self.capture_source = backends["capture_source"]

    def start(self) -> bool:
        if self.is_running:
            return True

        self._stop_event.clear()

        try:
            from scapy.all import sniff  # type: ignore
        except Exception as e:
            self.available = False
            self.error_message = f"Capture dependency unavailable: {e}"
            self.capture_source = "UNAVAILABLE"
            logger.warning("Packet capture unavailable: %s", e)
            return False

        def _worker():
            self.is_running = True
            bpf_filter = f"ip host {self.target_ip}"
            logger.info("Starting Scapy capture worker for %s with filter: %s", self.target_ip, bpf_filter)

            def _handle_pkt(pkt):
                if self._stop_event.is_set():
                    return
                try:
                    from scapy.all import IP, TCP, UDP, ICMP, Raw  # type: ignore
                    if not pkt.haslayer(IP):
                        return

                    ip_layer = pkt[IP]
                    src = ip_layer.src
                    dst = ip_layer.dst
                    length = len(pkt)
                    ttl = getattr(ip_layer, "ttl", 64)

                    sport = 0
                    dport = 0
                    proto_num = ip_layer.proto
                    tcp_flags: dict[str, bool] | None = None
                    tcp_window = None

                    if pkt.haslayer(TCP):
                        tcp = pkt[TCP]
                        sport = tcp.sport
                        dport = tcp.dport
                        tcp_window = tcp.window
                        flags_int = int(tcp.flags)
                        tcp_flags = {
                            "SYN": bool(flags_int & 0x02),
                            "ACK": bool(flags_int & 0x10),
                            "FIN": bool(flags_int & 0x01),
                            "RST": bool(flags_int & 0x04),
                            "PSH": bool(flags_int & 0x08),
                            "URG": bool(flags_int & 0x20),
                        }
                    elif pkt.haslayer(UDP):
                        udp = pkt[UDP]
                        sport = udp.sport
                        dport = udp.dport
                    elif pkt.haslayer(ICMP):
                        sport = 0
                        dport = 0

                    payload_bytes = None
                    if pkt.haslayer(Raw):
                        payload_bytes = bytes(pkt[Raw].load)

                    self.on_packet(
                        src_ip=src,
                        dst_ip=dst,
                        src_port=sport,
                        dst_port=dport,
                        protocol=proto_num,
                        length=length,
                        tcp_flags=tcp_flags,
                        ttl=ttl,
                        tcp_window=tcp_window,
                        payload=payload_bytes,
                        timestamp=time.time(),
                    )
                except Exception as ex:
                    logger.debug("Error processing captured packet: %s", ex)

            try:
                from scapy.all import sniff  # type: ignore
                sniff(
                    filter=bpf_filter,
                    prn=_handle_pkt,
                    store=False,
                    stop_filter=lambda _p: self._stop_event.is_set(),
                    iface=self.iface,
                )
            except Exception as ex:
                self.available = False
                self.error_message = f"Interface capture failed (Npcap/permissions required): {ex}"
                self.capture_source = "UNAVAILABLE"
                logger.warning("Scapy sniffing encountered error for %s: %s", self.target_ip, ex)
            finally:
                self.is_running = False

        self._thread = threading.Thread(target=_worker, daemon=True, name=f"ScapyCapture-{self.target_ip}")
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop_event.set()
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        logger.info("Stopped capture adapter for %s", self.target_ip)
