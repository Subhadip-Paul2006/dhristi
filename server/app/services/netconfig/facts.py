# Drishti v0.1 — network-config fact gathering | 12-Jul-2026
"""Collect the REAL facts the network-config detectors reason over.

Two provenances, always kept distinct:
  • observed — assets, zones, connections and (if Live Watch ran) the discovered
    gateway/device inventory, read straight from this org's data.
  • declared — an optional user-supplied topology (port-forwards, DHCP servers,
    DMZ membership) the caller declares for analysis.

Nothing is invented here: a fact that wasn't observed or declared is simply
absent, and the detector that needs it reports 'unknown'."""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, NetworkDevice, RiskZone, Service
from app.schemas.netconfig import NetconfigInput


@dataclass
class AssetFact:
    id: str
    hostname: str | None
    ip: str
    zone_kind: str | None  # dmz | internal | crown_jewel | cloud | None
    zone_name: str | None
    criticality: str
    asset_type: str
    internet_facing: bool
    ports: list[int] = field(default_factory=list)
    declared_dmz: bool = False  # user declared this host as DMZ-resident


@dataclass
class NetworkFacts:
    assets: list[AssetFact]
    zone_kinds_present: set[str]
    # observed device-inventory facts (from Live Watch), if any
    has_device_inventory: bool
    observed_gateway_ip: str | None
    # declared config (optional)
    used_declared_config: bool
    declared_gateway_ip: str | None
    port_forwards: list[dict]  # {external_port, internal_ip, internal_port, proto}
    dhcp_servers: list[str]
    dhcp_snooping: bool | None
    dhcp_declared: bool  # whether the user gave us any DHCP data at all
    dhcp_inferred: bool = False  # DHCP server inferred from the live gateway (observed, not declared)

    def by_ip(self, ip: str) -> AssetFact | None:
        for a in self.assets:
            if a.ip == ip:
                return a
        return None

    def find(self, needle: str) -> AssetFact | None:
        return next((a for a in self.assets if a.ip == needle or a.hostname == needle), None)

    @property
    def gateway_ip(self) -> str | None:
        return self.declared_gateway_ip or self.observed_gateway_ip


def gather(db: Session, org_id: str, config: NetconfigInput | None) -> NetworkFacts:
    zones = {z.id: z for z in db.scalars(select(RiskZone).where(RiskZone.org_id == org_id)).all()}
    services = db.scalars(select(Service).where(Service.org_id == org_id)).all()
    ports_by_asset: dict[str, list[int]] = {}
    for s in services:
        ports_by_asset.setdefault(s.asset_id, []).append(s.port)

    declared_dmz = {d.strip().lower() for d in (config.dmz_hosts if config else [])}

    assets: list[AssetFact] = []
    zone_kinds: set[str] = set()
    for a in db.scalars(select(Asset).where(Asset.org_id == org_id)).all():
        zone = zones.get(a.zone_id)
        zk = zone.kind if zone else None
        if zk:
            zone_kinds.add(zk)
        is_declared_dmz = a.ip.lower() in declared_dmz or (a.hostname or "").lower() in declared_dmz
        assets.append(
            AssetFact(
                id=a.id,
                hostname=a.hostname,
                ip=a.ip,
                zone_kind=zk,
                zone_name=zone.name if zone else None,
                criticality=a.criticality,
                asset_type=a.asset_type,
                internet_facing=bool(a.internet_facing),
                ports=sorted(ports_by_asset.get(a.id, [])),
                declared_dmz=is_declared_dmz,
            )
        )

    # observed gateway from Live Watch device inventory — prefer a device the
    # agent still sees online (a stale gateway from a previous Wi-Fi must not win)
    devices = db.scalars(select(NetworkDevice).where(NetworkDevice.org_id == org_id)).all()
    gw = next((d.ip for d in devices if d.is_gateway and d.online), None) \
        or next((d.ip for d in devices if d.is_gateway), None)

    # declared DHCP (de-duped) if the caller supplied any
    declared_dhcp: list[str] = []
    if config is not None:
        seen: set[str] = set()
        for s in config.dhcp_servers:
            s = s.strip()
            if s and s not in seen:
                seen.add(s)
                declared_dhcp.append(s)
    declared_snooping = config.dhcp_snooping if config is not None else None
    dhcp_declared = bool(declared_dhcp) or declared_snooping is not None

    # Infer the DHCP responder from the live gateway when the user declared none:
    # on essentially every LAN the gateway is the DHCP server, so this lets the
    # DHCP posture be *checked* (single authorized responder) instead of "unknown".
    dhcp_inferred = False
    dhcp_servers = declared_dhcp
    if not declared_dhcp and gw and devices:
        dhcp_servers = [gw]
        dhcp_inferred = True

    return NetworkFacts(
        assets=assets,
        zone_kinds_present=zone_kinds,
        has_device_inventory=bool(devices),
        observed_gateway_ip=gw,
        used_declared_config=config is not None,
        declared_gateway_ip=config.gateway_ip if config is not None else None,
        port_forwards=[pf.model_dump() for pf in config.port_forwards] if config is not None else [],
        dhcp_servers=dhcp_servers,
        dhcp_snooping=declared_snooping,
        dhcp_declared=dhcp_declared,
        dhcp_inferred=dhcp_inferred,
    )
