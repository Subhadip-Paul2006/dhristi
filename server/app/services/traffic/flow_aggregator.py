# Drishti v0.1 — per-device real network flow aggregator | Phase 01
from __future__ import annotations

import math
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP, etc.

    start_time: float
    last_time: float
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_fwd_bytes: int = 0
    total_bwd_bytes: int = 0

    fwd_iat_samples: list[float] = field(default_factory=list)
    bwd_iat_samples: list[float] = field(default_factory=list)
    last_fwd_time: float | None = None
    last_bwd_time: float | None = None

    flag_syn_count: int = 0
    flag_ack_count: int = 0
    flag_fin_count: int = 0
    flag_rst_count: int = 0
    flag_psh_count: int = 0
    flag_urg_count: int = 0

    ttl_samples: list[int] = field(default_factory=list)
    tcp_window_samples: list[int] = field(default_factory=list)
    payload_sample_bytes: bytearray = field(default_factory=bytearray)

    @property
    def duration(self) -> float:
        return max(0.000001, self.last_time - self.start_time)

    @property
    def total_packets(self) -> int:
        return self.total_fwd_packets + self.total_bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.total_fwd_bytes + self.total_bwd_bytes

    @property
    def flow_packets_per_sec(self) -> float:
        return round(self.total_packets / self.duration, 2)

    @property
    def flow_bytes_per_sec(self) -> float:
        return round(self.total_bytes / self.duration, 2)

    @property
    def fwd_iat_mean(self) -> float:
        return sum(self.fwd_iat_samples) / len(self.fwd_iat_samples) if self.fwd_iat_samples else 0.0

    @property
    def fwd_iat_std(self) -> float:
        if len(self.fwd_iat_samples) < 2:
            return 0.0
        m = self.fwd_iat_mean
        return math.sqrt(sum((x - m) ** 2 for x in self.fwd_iat_samples) / (len(self.fwd_iat_samples) - 1))

    @property
    def fwd_iat_max(self) -> float:
        return max(self.fwd_iat_samples) if self.fwd_iat_samples else 0.0

    @property
    def fwd_iat_min(self) -> float:
        return min(self.fwd_iat_samples) if self.fwd_iat_samples else 0.0

    @property
    def bwd_iat_mean(self) -> float:
        return sum(self.bwd_iat_samples) / len(self.bwd_iat_samples) if self.bwd_iat_samples else 0.0

    @property
    def bwd_iat_std(self) -> float:
        if len(self.bwd_iat_samples) < 2:
            return 0.0
        m = self.bwd_iat_mean
        return math.sqrt(sum((x - m) ** 2 for x in self.bwd_iat_samples) / (len(self.bwd_iat_samples) - 1))

    @property
    def fwd_avg_bytes_per_pkt(self) -> float:
        return round(self.total_fwd_bytes / self.total_fwd_packets, 2) if self.total_fwd_packets > 0 else 0.0

    @property
    def bwd_avg_bytes_per_pkt(self) -> float:
        return round(self.total_bwd_bytes / self.total_bwd_packets, 2) if self.total_bwd_packets > 0 else 0.0

    @property
    def mean_ttl(self) -> float:
        return sum(self.ttl_samples) / len(self.ttl_samples) if self.ttl_samples else 64.0

    @property
    def mean_tcp_window(self) -> float:
        return sum(self.tcp_window_samples) / len(self.tcp_window_samples) if self.tcp_window_samples else 0.0

    @property
    def payload_entropy(self) -> float:
        return _shannon_entropy(bytes(self.payload_sample_bytes))


class FlowAggregator:
    """Aggregates raw observed packets strictly for a bound target device IP.

    STRICT DEVICE ISOLATION:
    If a packet does not match target_ip as either source or destination, it is
    immediately discarded without altering any session counters or metrics.
    """

    def __init__(self, target_ip: str, device_id: str, session_id: str) -> None:
        self.target_ip = target_ip.strip()
        self.device_id = device_id
        self.session_id = session_id

        self._lock = threading.Lock()
        self.flows: dict[tuple[str, str, int, int, int], FlowRecord] = {}
        self.destinations: dict[tuple[str, int, str], dict[str, Any]] = {}
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self.unique_dst_ports: set[int] = set()

        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.start_time: float = time.time()
        self.last_event_time: float | None = None

    def ingest_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int | str,
        length: int,
        tcp_flags: dict[str, bool] | None = None,
        ttl: int | None = None,
        tcp_window: int | None = None,
        payload: bytes | None = None,
        timestamp: float | None = None,
    ) -> bool:
        """Ingest a single observed network packet.

        Returns True if packet was accepted for this device; False if rejected by isolation filter.
        """
        src = (src_ip or "").strip()
        dst = (dst_ip or "").strip()

        # STRICT DEVICE ISOLATION ENFORCEMENT
        if src != self.target_ip and dst != self.target_ip:
            return False

        ts = timestamp if timestamp is not None else time.time()
        proto_num = protocol if isinstance(protocol, int) else (6 if protocol == "TCP" else (17 if protocol == "UDP" else 1))
        is_fwd = (src == self.target_ip)

        with self._lock:
            self.total_packets += 1
            self.total_bytes += length
            self.last_event_time = ts

            # Protocol tracking
            proto_name = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else ("ICMP" if proto_num == 1 else "OTHER"))
            if dst_port == 53 or src_port == 53:
                self.protocol_counts["DNS"] += 1
            elif dst_port in (80, 443, 8080, 8443) or src_port in (80, 443, 8080, 8443):
                self.protocol_counts["HTTP_HTTPS"] += 1
            self.protocol_counts[proto_name] += 1

            # Destination tracking (from perspective of target_ip)
            remote_ip = dst if is_fwd else src
            remote_port = dst_port if is_fwd else src_port
            if is_fwd:
                self.unique_dst_ports.add(dst_port)

            dest_key = (remote_ip, remote_port, proto_name)
            if dest_key not in self.destinations:
                self.destinations[dest_key] = {
                    "destination_ip": remote_ip,
                    "destination_port": remote_port,
                    "protocol": proto_name,
                    "connection_count": 0,
                    "last_seen": datetime.fromtimestamp(ts, tz=timezone.utc),
                }
            self.destinations[dest_key]["connection_count"] += 1
            self.destinations[dest_key]["last_seen"] = datetime.fromtimestamp(ts, tz=timezone.utc)

            # Bidirectional 5-tuple canonical key: canonical order
            if src < dst or (src == dst and src_port <= dst_port):
                flow_key = (src, dst, src_port, dst_port, proto_num)
            else:
                flow_key = (dst, src, dst_port, src_port, proto_num)

            flow = self.flows.get(flow_key)
            if flow is None:
                flow = FlowRecord(
                    src_ip=src,
                    dst_ip=dst,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto_num,
                    start_time=ts,
                    last_time=ts,
                )
                self.flows[flow_key] = flow

            flow.last_time = ts

            if is_fwd:
                flow.total_fwd_packets += 1
                flow.total_fwd_bytes += length
                if flow.last_fwd_time is not None:
                    flow.fwd_iat_samples.append(max(0.0, ts - flow.last_fwd_time))
                flow.last_fwd_time = ts
            else:
                flow.total_bwd_packets += 1
                flow.total_bwd_bytes += length
                if flow.last_bwd_time is not None:
                    flow.bwd_iat_samples.append(max(0.0, ts - flow.last_bwd_time))
                flow.last_bwd_time = ts

            if tcp_flags:
                if isinstance(tcp_flags, dict):
                    if tcp_flags.get("SYN"):
                        flow.flag_syn_count += 1
                    if tcp_flags.get("ACK"):
                        flow.flag_ack_count += 1
                    if tcp_flags.get("FIN"):
                        flow.flag_fin_count += 1
                    if tcp_flags.get("RST"):
                        flow.flag_rst_count += 1
                    if tcp_flags.get("PSH"):
                        flow.flag_psh_count += 1
                    if tcp_flags.get("URG"):
                        flow.flag_urg_count += 1
                elif isinstance(tcp_flags, str):
                    if "S" in tcp_flags:
                        flow.flag_syn_count += 1
                    if "A" in tcp_flags:
                        flow.flag_ack_count += 1
                    if "F" in tcp_flags:
                        flow.flag_fin_count += 1
                    if "R" in tcp_flags:
                        flow.flag_rst_count += 1
                    if "P" in tcp_flags:
                        flow.flag_psh_count += 1
                    if "U" in tcp_flags:
                        flow.flag_urg_count += 1


            if ttl is not None:
                flow.ttl_samples.append(ttl)
            if tcp_window is not None:
                flow.tcp_window_samples.append(tcp_window)
            if payload and len(flow.payload_sample_bytes) < 4096:
                flow.payload_sample_bytes.extend(payload[:512])

        return True

    def get_summary_metrics(self) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            duration = max(0.001, now - self.start_time)
            pps = round(self.total_packets / duration, 2)
            bps = round(self.total_bytes / duration, 2)
            return {
                "packet_count": self.total_packets,
                "flow_count": len(self.flows),
                "byte_count": self.total_bytes,
                "packets_per_sec": pps,
                "bytes_per_sec": bps,
                "active_connections": len(self.flows),
                "port_scan_score": len(self.unique_dst_ports),
            }

    def get_protocols(self) -> dict[str, int]:
        with self._lock:
            return {
                "tcp": self.protocol_counts.get("TCP", 0),
                "udp": self.protocol_counts.get("UDP", 0),
                "icmp": self.protocol_counts.get("ICMP", 0),
                "dns": self.protocol_counts.get("DNS", 0),
                "http_https": self.protocol_counts.get("HTTP_HTTPS", 0),
                "other": self.protocol_counts.get("OTHER", 0),
            }

    def get_top_destinations(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self.destinations.values())
            items.sort(key=lambda d: d["connection_count"], reverse=True)
            return items[:limit]

    def get_all_flows(self) -> list[FlowRecord]:
        with self._lock:
            return list(self.flows.values())
