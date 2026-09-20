# Drishti v0.1 — SQLAlchemy model registry | 11-Jul-2026
"""Import every mapper so Base.metadata sees all tables."""
from app.models.asset import Asset, Connection, RiskZone, Service
from app.models.endpoint import EndpointAgent, EndpointPairingSession
from app.models.live import (
    AutoScanConfig,
    DeepScan,
    DevicePresenceSession,
    LiveObservation,
    NetworkCoverage,
    NetworkDevice,
)
from app.models.netconfig import NetconfigAnalysis
from app.models.org import Agent, Organization, User
from app.models.path import AttackPath, AttackPathStep
from app.models.remediation import Remediation
from app.models.scan import Scan, ThreatIntel
from app.models.urltrust import UrlAnalysis
from app.models.vuln import AssetVulnerability, Vulnerability

__all__ = [
    "Agent",
    "Asset",
    "AssetVulnerability",
    "AttackPath",
    "AutoScanConfig",
    "AttackPathStep",
    "Connection",
    "DeepScan",
    "DevicePresenceSession",
    "EndpointAgent",
    "EndpointPairingSession",
    "LiveObservation",
    "NetconfigAnalysis",
    "NetworkCoverage",
    "NetworkDevice",
    "Organization",
    "Remediation",
    "RiskZone",
    "Scan",
    "Service",
    "ThreatIntel",
    "UrlAnalysis",
    "User",
    "Vulnerability",
]
