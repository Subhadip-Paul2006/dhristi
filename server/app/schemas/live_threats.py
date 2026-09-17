# Drishti — network threat detection schema.
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class NetworkThreat(BaseModel):
    id: str
    # arp_spoof | rogue_device | risky_service | malicious_domain
    kind: str
    severity: str  # critical | high | medium | low
    title: str
    detail: str
    device_ip: str | None = None
    device_mac: str | None = None
    hostname: str | None = None
    evidence: list[str] = []
    recommendation: str = ""
    mitre: str | None = None  # MITRE ATT&CK technique, e.g. "T1557 · Adversary-in-the-Middle"
    first_seen: datetime | None = None
