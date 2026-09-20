# Drishti v0.1 — per-device tracking session manager | Phase 01
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.models.base import utcnow
from app.models.tracking import LiveTrackingSession
from app.schemas.tracking import (
    CurrentBehaviourOut,
    ForecastResultOut,
    LiveTrafficMetrics,
    ProtocolBreakdown,
    TopDestinationItem,
    TrackingResultsOut,
    TrackingSessionOut,
    TrafficEvidenceItem,
)
from app.services.traffic.capture_adapter import ScapyCaptureAdapter, TrafficVisibilityChecker
from app.services.traffic.detection_engine import TrafficDetectionEngine
from app.services.traffic.feature_extractor import extract_session_features
from app.services.traffic.flow_aggregator import FlowAggregator
from app.services.traffic.graph_engine import NetworkGraphEngine
from app.services.traffic.time_window import TimeWindowEngine
from ml.forecasting.engine import forecasting_engine
from ml.inference.engine import inference_engine

logger = logging.getLogger("drishti")


class ActiveTrackingSession:
    """In-memory active tracking instance strictly bound to one target device and session."""

    def __init__(
        self,
        session_id: str,
        org_id: str,
        device_id: str,
        target_ip: str,
        target_mac: str | None = None,
        target_hostname: str | None = None,
        capture_source: str = "SCAPY / MONITORED INTERFACE",
    ) -> None:
        self.session_id = session_id
        self.org_id = org_id
        self.device_id = device_id
        self.target_ip = target_ip.strip()
        self.target_mac = target_mac
        self.target_hostname = target_hostname
        self.started_at = datetime.now(timezone.utc)
        self.ended_at: datetime | None = None
        self.status = "LIVE"
        self.capture_source = capture_source
        self.status_message: str | None = None
        self.previous_features: dict[str, float] | None = None

        # Phase 04: cache latest detection + forecast so list_devices() can read
        # them without triggering a new inference pass. These are set inside
        # get_results() and are always CURRENT DETECTION / FORECAST labels —
        # never confirmed attack status.
        self.last_detection: CurrentBehaviourOut | None = None
        self.last_forecast: ForecastResultOut | None = None

        self.aggregator = FlowAggregator(target_ip=self.target_ip, device_id=device_id, session_id=session_id)
        self.window_engine = TimeWindowEngine(target_device_id=device_id, target_ip=self.target_ip)
        self.graph_engine = NetworkGraphEngine(target_ip=self.target_ip)
        self.detection_engine = TrafficDetectionEngine()

        def _on_packet_ingest(**kwargs):
            accepted = self.aggregator.ingest_packet(**kwargs)
            if accepted:
                self.window_engine.ingest_event(
                    src_ip=kwargs.get("src_ip", ""),
                    dst_ip=kwargs.get("dst_ip", ""),
                    src_port=kwargs.get("src_port", 0),
                    dst_port=kwargs.get("dst_port", 0),
                    protocol=kwargs.get("protocol", 6),
                    length=kwargs.get("length", 0),
                    tcp_flags=kwargs.get("tcp_flags"),
                    timestamp=kwargs.get("timestamp"),
                )

        self.capture_adapter = ScapyCaptureAdapter(
            target_ip=self.target_ip,
            on_packet=_on_packet_ingest,
        )

    def start(self) -> None:
        success = self.capture_adapter.start()
        if not success:
            if not self.capture_adapter.available:
                self.status = "UNAVAILABLE"
                self.status_message = self.capture_adapter.error_message or "Live traffic capture unavailable from this monitoring point."
                self.capture_source = "UNAVAILABLE"
            else:
                self.status = "ERROR"
                self.status_message = "Failed to initiate packet sniffing."

    def stop(self) -> None:
        self.status = "STOPPED"
        self.ended_at = datetime.now(timezone.utc)
        self.capture_adapter.stop()


class SessionManager:
    """Coordinates per-device live network traffic tracking sessions.

    Maintains strict device isolation: Session A and Session B never share state or flows.
    """

    def __init__(self) -> None:
        self._active_sessions: dict[str, ActiveTrackingSession] = {}

    def start_tracking(
        self,
        db: Session,
        org_id: str,
        device_id: str,
        ip: str,
        mac: str | None = None,
        hostname: str | None = None,
    ) -> TrackingSessionOut:
        session_id = str(uuid4())

        # Determine capture source context
        capture_source = "SCAPY / MONITORED INTERFACE"

        # Create active in-memory session
        active = ActiveTrackingSession(
            session_id=session_id,
            org_id=org_id,
            device_id=device_id,
            target_ip=ip,
            target_mac=mac,
            target_hostname=hostname,
            capture_source=capture_source,
        )
        active.start()
        self._active_sessions[session_id] = active

        # Persist session row in database
        row = LiveTrackingSession(
            id=session_id,
            org_id=org_id,
            device_id=device_id,
            target_ip=ip,
            target_mac=mac,
            target_hostname=hostname,
            status=active.status,
            capture_source=active.capture_source,
            status_message=active.status_message,
            started_at=active.started_at,
        )
        db.add(row)
        db.commit()

        return self._to_session_out(active)

    def stop_tracking(self, db: Session, org_id: str, session_id: str) -> TrackingSessionOut:
        active = self._active_sessions.get(session_id)
        if active and active.org_id == org_id:
            active.stop()
            summary = active.aggregator.get_summary_metrics()
            # Update database
            row = db.scalar(select(LiveTrackingSession).where(LiveTrackingSession.id == session_id, LiveTrackingSession.org_id == org_id))
            if row:
                row.status = "STOPPED"
                row.ended_at = active.ended_at
                row.packet_count = summary["packet_count"]
                row.flow_count = summary["flow_count"]
                row.byte_count = summary["byte_count"]
                row.last_event_at = datetime.fromtimestamp(active.aggregator.last_event_time, tz=timezone.utc) if active.aggregator.last_event_time else None
                db.commit()
            return self._to_session_out(active)

        # If not active in memory, check DB
        row = db.scalar(select(LiveTrackingSession).where(LiveTrackingSession.id == session_id, LiveTrackingSession.org_id == org_id))
        if row is None:
            raise NotFoundError("Tracking session not found")
        row.status = "STOPPED"
        row.ended_at = utcnow()
        db.commit()
        return TrackingSessionOut(
            tracking_session_id=row.id,
            device_id=row.device_id,
            target_ip=row.target_ip,
            target_mac=row.target_mac,
            target_hostname=row.target_hostname,
            status=row.status,
            capture_source=row.capture_source,
            status_message=row.status_message,
            started_at=row.started_at,
            ended_at=row.ended_at,
            last_event_at=row.last_event_at,
            packet_count=row.packet_count,
            flow_count=row.flow_count,
            byte_count=row.byte_count,
        )

    def get_active_session_for_device(
        self, org_id: str, device_id: str
    ) -> "ActiveTrackingSession | None":
        """Phase 04: return the active tracking session for a device if one exists.

        Strictly device + org scoped — never returns another org's session.
        Returns None if no active LIVE session exists for this device.
        """
        for session in self._active_sessions.values():
            if session.org_id == org_id and session.device_id == device_id and session.status == "LIVE":
                return session
        return None

    def get_session(self, db: Session, org_id: str, session_id: str) -> TrackingSessionOut:
        active = self._active_sessions.get(session_id)
        if active and active.org_id == org_id:
            return self._to_session_out(active)

        row = db.scalar(select(LiveTrackingSession).where(LiveTrackingSession.id == session_id, LiveTrackingSession.org_id == org_id))
        if row is None:
            raise NotFoundError("Tracking session not found")
        return TrackingSessionOut(
            tracking_session_id=row.id,
            device_id=row.device_id,
            target_ip=row.target_ip,
            target_mac=row.target_mac,
            target_hostname=row.target_hostname,
            status=row.status,
            capture_source=row.capture_source,
            status_message=row.status_message,
            started_at=row.started_at,
            ended_at=row.ended_at,
            last_event_at=row.last_event_at,
            packet_count=row.packet_count,
            flow_count=row.flow_count,
            byte_count=row.byte_count,
        )

    def get_results(self, db: Session, org_id: str, session_id: str) -> TrackingResultsOut:
        active = self._active_sessions.get(session_id)
        if not active or active.org_id != org_id:
            # Fallback to DB stored historical row
            row = db.scalar(select(LiveTrackingSession).where(LiveTrackingSession.id == session_id, LiveTrackingSession.org_id == org_id))
            if row is None:
                raise NotFoundError("Tracking session not found")
            sess_out = TrackingSessionOut(
                tracking_session_id=row.id,
                device_id=row.device_id,
                target_ip=row.target_ip,
                target_mac=row.target_mac,
                target_hostname=row.target_hostname,
                status=row.status,
                capture_source=row.capture_source,
                status_message=row.status_message,
                started_at=row.started_at,
                ended_at=row.ended_at,
                last_event_at=row.last_event_at,
                packet_count=row.packet_count,
                flow_count=row.flow_count,
                byte_count=row.byte_count,
            )
            return TrackingResultsOut(
                session=sess_out,
                metrics=LiveTrafficMetrics(
                    packet_count=row.packet_count,
                    flow_count=row.flow_count,
                    byte_count=row.byte_count,
                ),
                protocols=ProtocolBreakdown(),
                top_destinations=[],
                current_behaviour=CurrentBehaviourOut(
                    verdict="INSUFFICIENT_DATA",
                    confidence=0.0,
                    signals=["Session stopped; historical counters preserved."],
                ),
                evidence=[],
                features=None,
                forecast=None,
            )

        summary = active.aggregator.get_summary_metrics()
        protocols_dict = active.aggregator.get_protocols()
        top_dest_raw = active.aggregator.get_top_destinations(limit=10)
        features = extract_session_features(active.aggregator)

        # Update graph topology with observed flows and record temporal graph snapshot
        active.graph_engine.update_from_flows(active.aggregator.get_all_flows())
        active.graph_engine.snapshot()

        # Slide time windows and format sequence tensor
        seq_tensor = active.window_engine.get_sequence_tensor(preprocessor=inference_engine.preprocessor)
        graph_tensors = active.graph_engine.get_graph_tensors()

        # Evaluate through AI Model Inference Engine (LSTM / Transformer / GNN / Fusion)
        current_behaviour = inference_engine.evaluate_live_traffic(
            seq_tensor=seq_tensor,
            graph_tensors=graph_tensors,
            total_packets=summary["packet_count"],
            flow_count=summary["flow_count"],
            features=features,
        )

        # Evaluate through Phase 03 Future Network Behaviour Forecasting Engine
        forecast = forecasting_engine.forecast_progression(
            seq_tensor=seq_tensor,
            graph_engine=active.graph_engine,
            current_features=features,
            previous_features=active.previous_features,
            current_verdict=current_behaviour.verdict,
            current_category=current_behaviour.attack_category,
            window_count=len(active.window_engine._windows),
            horizon=3,
        )
        active.previous_features = dict(features)

        # Phase 04: persist latest detection and forecast so device profile
        # can include AI state without re-running inference on every poll.
        # These are labeled CURRENT DETECTION / FORECAST — not confirmed attack.
        active.last_detection = current_behaviour
        active.last_forecast = forecast

        # Check truthful capture status & network visibility
        now = time.time()
        elapsed = now - active.started_at.timestamp()
        visibility_info = TrafficVisibilityChecker.evaluate_visibility(
            target_ip=active.target_ip,
            packets_observed=summary["packet_count"],
            session_duration=elapsed,
        )
        if visibility_info["visibility"] == "UNAVAILABLE" and active.status == "LIVE":
            active.status_message = visibility_info["reason"]

        # Build evidence items strictly retaining source identity
        evidence_items: list[TrafficEvidenceItem] = []
        for dest in top_dest_raw[:5]:
            evidence_items.append(
                TrafficEvidenceItem(
                    evidence_type="NETWORK_TRAFFIC",
                    source=active.capture_source,
                    observed_at=dest.get("last_seen") or datetime.now(timezone.utc),
                    device_id=active.device_id,
                    confidence="high",
                    details={
                        "destination_ip": dest["destination_ip"],
                        "destination_port": dest["destination_port"],
                        "protocol": dest["protocol"],
                        "connection_count": dest["connection_count"],
                    },
                )
            )

        top_dest_models = [
            TopDestinationItem(
                destination_ip=d["destination_ip"],
                destination_port=d["destination_port"],
                protocol=d["protocol"],
                connection_count=d["connection_count"],
                last_seen=d.get("last_seen"),
            )
            for d in top_dest_raw
        ]

        sess_out = self._to_session_out(active)
        return TrackingResultsOut(
            session=sess_out,
            metrics=LiveTrafficMetrics(
                packet_count=summary["packet_count"],
                flow_count=summary["flow_count"],
                byte_count=summary["byte_count"],
                packets_per_sec=summary["packets_per_sec"],
                bytes_per_sec=summary["bytes_per_sec"],
                active_connections=summary["active_connections"],
            ),
            protocols=ProtocolBreakdown(
                tcp=protocols_dict["tcp"],
                udp=protocols_dict["udp"],
                icmp=protocols_dict["icmp"],
                dns=protocols_dict["dns"],
                http_https=protocols_dict["http_https"],
                other=protocols_dict["other"],
            ),
            top_destinations=top_dest_models,
            current_behaviour=current_behaviour,
            evidence=evidence_items,
            features=features,
            model_status=inference_engine.get_status(),
            network_visibility=visibility_info["visibility"],
            visibility_reason=visibility_info["reason"],
            window_count=len(active.window_engine._windows),
            graph_summary=active.graph_engine.to_dict(),
            forecast=forecast,
        )


    def _to_session_out(self, active: ActiveTrackingSession) -> TrackingSessionOut:
        summary = active.aggregator.get_summary_metrics()
        last_ev = (
            datetime.fromtimestamp(active.aggregator.last_event_time, tz=timezone.utc)
            if active.aggregator.last_event_time
            else None
        )
        return TrackingSessionOut(
            tracking_session_id=active.session_id,
            device_id=active.device_id,
            target_ip=active.target_ip,
            target_mac=active.target_mac,
            target_hostname=active.target_hostname,
            status=active.status,
            capture_source=active.capture_source,
            status_message=active.status_message,
            started_at=active.started_at,
            ended_at=active.ended_at,
            last_event_at=last_ev,
            packet_count=summary["packet_count"],
            flow_count=summary["flow_count"],
            byte_count=summary["byte_count"],
        )


# Global singleton manager instance
tracking_manager = SessionManager()
session_manager = tracking_manager
