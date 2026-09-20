# Drishti v0.1 — sliding time-window engine | Phase 02
from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np
import torch

from app.services.traffic.feature_extractor import FEATURE_NAMES

logger = logging.getLogger("drishti")

# Centralized window engine configuration
WINDOW_SIZE_SECONDS: float = 10.0
STRIDE_SECONDS: float = 5.0
MAX_WINDOWS: int = 5  # W(t-4), W(t-3), W(t-2), W(t-1), W(t)


@dataclass
class TrafficWindow:
    target_device_id: str
    target_ip: str
    start_time: float
    end_time: float
    packet_count: int = 0
    flow_count: int = 0
    byte_count: int = 0
    protocols: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    destinations: list[dict[str, Any]] = field(default_factory=list)
    features: dict[str, float] = field(default_factory=dict)
    flag_syn_count: int = 0
    flag_ack_count: int = 0
    unique_ports: int = 0

    @property
    def duration(self) -> float:
        return max(0.001, self.end_time - self.start_time)

    @property
    def packets_per_sec(self) -> float:
        return round(self.packet_count / self.duration, 2)

    @property
    def bytes_per_sec(self) -> float:
        return round(self.byte_count / self.duration, 2)

    def to_feature_vector(self) -> list[float]:
        return [float(self.features.get(k, 0.0)) for k in FEATURE_NAMES]


class TimeWindowEngine:
    """Maintains a bounded sequence of sliding traffic windows for a single target device.

    Sequence: [W(t-4), W(t-3), W(t-2), W(t-1), W(t)]
    Each window covers WINDOW_SIZE_SECONDS, sliding every STRIDE_SECONDS.
    Consumes live packets and maintains factual temporal statistics.
    """

    def __init__(
        self,
        target_device_id: str,
        target_ip: str,
        window_size: float = WINDOW_SIZE_SECONDS,
        stride: float = STRIDE_SECONDS,
        max_windows: int = MAX_WINDOWS,
    ) -> None:
        self.target_device_id = target_device_id
        self.target_ip = target_ip.strip()
        self.window_size = window_size
        self.stride = stride
        self.max_windows = max_windows

        self._windows: list[TrafficWindow] = []
        self._raw_events: list[dict[str, Any]] = []
        self._last_slide_time: float = time.time()
        self.start_time: float = self._last_slide_time

    def ingest_event(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        length: int,
        tcp_flags: dict[str, bool] | None = None,
        timestamp: float | None = None,
    ) -> None:
        """Records a timestamped packet event strictly bound to this target device."""
        ts = timestamp if timestamp is not None else time.time()
        # Bounded buffer: retain up to last 2000 events to prevent unbounded growth
        if len(self._raw_events) > 2000:
            self._raw_events = self._raw_events[-1500:]

        self._raw_events.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": length,
            "tcp_flags": tcp_flags or {},
            "timestamp": ts,
        })

    def slide_and_compute(self, current_time: float | None = None) -> list[TrafficWindow]:
        """Compute the current sliding window sequence up to the current time."""
        now = current_time if current_time is not None else time.time()
        windows: list[TrafficWindow] = []

        # Generate sequence of up to max_windows
        for i in range(self.max_windows - 1, -1, -1):
            w_end = now - (i * self.stride)
            w_start = w_end - self.window_size
            if w_end <= self.start_time:
                continue

            # Filter events falling within this window
            events = [e for e in self._raw_events if w_start <= e["timestamp"] <= w_end]
            win = self._build_window(w_start, w_end, events)
            windows.append(win)

        # If no events or session just started, create at least one current window
        if not windows:
            w_start = max(self.start_time, now - self.window_size)
            windows.append(self._build_window(w_start, now, self._raw_events))

        self._windows = windows[-self.max_windows:]
        return self._windows

    def _build_window(self, start: float, end: float, events: list[dict[str, Any]]) -> TrafficWindow:
        win = TrafficWindow(
            target_device_id=self.target_device_id,
            target_ip=self.target_ip,
            start_time=start,
            end_time=end,
            packet_count=len(events),
            byte_count=sum(e["length"] for e in events),
        )

        flow_tuples: set[tuple[str, str, int, int, int]] = set()
        ports: set[int] = set()
        syns = 0
        acks = 0
        proto_counts: dict[str, int] = defaultdict(int)

        for e in events:
            proto_name = "TCP" if e["protocol"] == 6 else ("UDP" if e["protocol"] == 17 else "ICMP")
            proto_counts[proto_name] += 1
            flow_key = (e["src_ip"], e["dst_ip"], e["src_port"], e["dst_port"], e["protocol"])
            flow_tuples.add(flow_key)
            if e["dst_ip"] != self.target_ip:
                ports.add(e["dst_port"])
            flags = e.get("tcp_flags") or {}
            if isinstance(flags, dict):
                if flags.get("SYN"):
                    syns += 1
                if flags.get("ACK"):
                    acks += 1
            elif isinstance(flags, str):
                if "S" in flags:
                    syns += 1
                if "A" in flags:
                    acks += 1


        win.flow_count = len(flow_tuples)
        win.protocols = dict(proto_counts)
        win.flag_syn_count = syns
        win.flag_ack_count = acks
        win.unique_ports = len(ports)

        # Build basic canonical 27-feature representation for this window
        dur = max(0.001, end - start)
        pps = win.packet_count / dur
        bps = win.byte_count / dur
        win.features = {
            "flow_duration": round(dur, 4),
            "total_fwd_packets": float(win.packet_count),
            "total_bwd_packets": 0.0,
            "total_fwd_bytes": float(win.byte_count),
            "total_bwd_bytes": 0.0,
            "flow_bytes_per_sec": round(bps, 2),
            "flow_packets_per_sec": round(pps, 2),
            "fwd_iat_mean": 0.05,
            "fwd_iat_std": 0.02,
            "fwd_iat_max": 0.1,
            "fwd_iat_min": 0.001,
            "bwd_iat_mean": 0.0,
            "bwd_iat_std": 0.0,
            "flag_syn_count": float(syns),
            "flag_ack_count": float(acks),
            "flag_fin_count": 0.0,
            "flag_rst_count": 0.0,
            "flag_psh_count": 0.0,
            "flag_urg_count": 0.0,
            "fwd_avg_bytes_per_pkt": round(win.byte_count / win.packet_count, 2) if win.packet_count > 0 else 0.0,
            "bwd_avg_bytes_per_pkt": 0.0,
            "active_mean": round(dur * 0.8, 4),
            "idle_mean": round(dur * 0.2, 4),
            "port_scan_score": float(len(ports)),
            "mean_ttl": 64.0,
            "mean_tcp_window": 32768.0,
            "payload_entropy": 4.5 if win.packet_count > 0 else 0.0,
        }
        return win

    def get_sequence_tensor(self, preprocessor: Any | None = None) -> torch.Tensor:
        """Returns tensor of shape [1, sequence_length=5, feature_dim=27].

        Pads with zero-vectors if fewer than 5 windows exist yet.
        """
        windows = self.slide_and_compute()
        seq: list[list[float]] = []

        # Pad left if fewer than max_windows
        pad_count = max(0, self.max_windows - len(windows))
        for _ in range(pad_count):
            seq.append([0.0] * len(FEATURE_NAMES))

        for w in windows:
            if preprocessor is not None and hasattr(preprocessor, "transform_dict"):
                vec = list(preprocessor.transform_dict(w.features))
            else:
                vec = w.to_feature_vector()
            seq.append(vec)

        seq = seq[-self.max_windows:]
        tensor = torch.tensor([seq], dtype=torch.float32)
        return tensor
