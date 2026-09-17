"""The Acme Retail demo network (DATABASE.md §6).

Hero scenario: an attacker reaches the customer database (db-prod-01, $3.5M)
from the public web app in five hops.
"""
import logging
import secrets
from decimal import Decimal

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.security import hash_agent_token, hash_password
from app.models import (
    Agent,
    Asset,
    AssetVulnerability,
    AttackPath,
    AttackPathStep,
    Connection,
    Organization,
    Remediation,
    RiskZone,
    Scan,
    Service,
    User,
    Vulnerability,
)

logger = logging.getLogger("drishti")

ORG_SLUG = "acme-retail"
DEMO_USER_EMAIL = "analyst@acme-retail.dev"
DEMO_USER_PASSWORD = "drishti-demo"
DEMO_AGENT_TOKEN = "agent-demo-token"

# app_env values in which it is safe to seed the well-known demo agent token.
# Outside these (docker/production/unset), a fresh random token is generated
# instead so the public "agent-demo-token" is NEVER seeded into a real deploy.
_DEMO_TOKEN_ALLOWED_ENVS = {"local", "dev", "test"}


def _resolve_agent_token() -> tuple[str, bool]:
    """Return (token, is_demo). In dev envs use the public demo token so the
    documented local demo works; otherwise mint a random token so production
    databases never carry the well-known 'agent-demo-token'."""
    if get_settings().app_env in _DEMO_TOKEN_ALLOWED_ENVS:
        return DEMO_AGENT_TOKEN, True
    return secrets.token_urlsafe(32), False

ZONES = [
    {"name": "DMZ", "kind": "dmz"},
    {"name": "App Tier", "kind": "internal"},
    {"name": "Data Tier", "kind": "crown_jewel"},
    {"name": "Corp", "kind": "internal"},
]

ASSETS = [
    # hostname, ip, type, zone, criticality, business_value, internet_facing, os
    ("web-lb-01", "10.0.1.10", "webapp", "DMZ", "medium", 50_000, True, "Ubuntu 22.04"),
    ("web-app-01", "10.0.1.11", "webapp", "DMZ", "medium", 80_000, True, "Ubuntu 22.04"),
    ("api-gw-01", "10.0.2.10", "server", "App Tier", "high", 250_000, False, "Ubuntu 22.04"),
    ("app-svc-01", "10.0.2.11", "server", "App Tier", "high", 300_000, False, "Debian 12"),
    ("jump-01", "10.0.2.50", "server", "App Tier", "high", 120_000, False, "Ubuntu 22.04"),
    ("db-prod-01", "10.0.3.11", "database", "Data Tier", "critical", 3_500_000, False, "Ubuntu 22.04"),
    ("db-replica-01", "10.0.3.12", "database", "Data Tier", "high", 1_200_000, False, "Ubuntu 22.04"),
    ("hr-ws-07", "10.0.4.20", "workstation", "Corp", "low", 15_000, False, "Windows 11"),
    ("admin-ws-01", "10.0.4.5", "workstation", "Corp", "medium", 60_000, False, "Windows 11"),
    ("fw-edge-01", "10.0.0.1", "firewall", "DMZ", "high", 40_000, True, "PanOS 11"),
]

SERVICES = {
    "web-lb-01": [(443, "tcp", "nginx", "1.18.0")],
    "web-app-01": [(443, "tcp", "node-express", "4.18.2"), (22, "tcp", "openssh", "8.9")],
    "api-gw-01": [(8443, "tcp", "kong", "3.4.0"), (22, "tcp", "openssh", "8.9")],
    "app-svc-01": [(8080, "tcp", "spring-boot", "2.7.2"), (22, "tcp", "openssh", "8.9")],
    "jump-01": [(22, "tcp", "openssh", "8.9")],
    "db-prod-01": [(5432, "tcp", "postgresql", "14.2"), (22, "tcp", "openssh", "8.9")],
    "db-replica-01": [(5432, "tcp", "postgresql", "14.2")],
    "hr-ws-07": [(445, "tcp", "smb", "3.1.1")],
    "admin-ws-01": [(3389, "tcp", "rdp", "10.0"), (445, "tcp", "smb", "3.1.1")],
    "fw-edge-01": [(443, "tcp", "panos-mgmt", "11.0")],
}

VULNS = [
    # cve_id, title, cvss, severity, exploitability, cwe, description
    ("CVE-2024-0001", "Web app unauthenticated RCE", 9.8, "critical", 0.9, "CWE-94",
     "Unauthenticated remote code execution in the public storefront application."),
    ("CVE-2024-0002", "Outdated TLS / weak cipher", 5.3, "medium", 0.3, "CWE-326",
     "Load balancer accepts deprecated TLS 1.0/1.1 and weak cipher suites."),
    ("CVE-2024-0003", "API gateway SSRF", 8.1, "high", 0.6, "CWE-918",
     "Server-side request forgery in the API gateway allows pivoting to internal services."),
    ("CVE-2024-0004", "SSH weak credentials (jump host)", 7.5, "high", 0.7, "CWE-521",
     "Jump host permits password authentication with weak, shared credentials."),
    ("CVE-2024-0005", "PostgreSQL priv-esc", 8.8, "high", 0.7, "CWE-269",
     "Privilege escalation in PostgreSQL 14.2 allowing an application role to gain superuser."),
    ("CVE-2024-0006", "Workstation phishing/macro RCE", 7.8, "high", 0.5, "CWE-94",
     "Office macro execution enables code execution on corporate workstations."),
]

# finding: (hostname, cve_id, service port or None)
FINDINGS = [
    ("web-lb-01", "CVE-2024-0002", 443),
    ("web-app-01", "CVE-2024-0001", 443),
    ("api-gw-01", "CVE-2024-0003", 8443),
    ("jump-01", "CVE-2024-0004", 22),
    ("db-prod-01", "CVE-2024-0005", 5432),
    ("db-replica-01", "CVE-2024-0005", 5432),
    ("admin-ws-01", "CVE-2024-0006", None),
]

# (from, to, relation, note)
CONNECTIONS = [
    ("web-lb-01", "web-app-01", "network", "LB upstream"),
    ("web-app-01", "api-gw-01", "network", "app calls internal APIs"),
    ("api-gw-01", "app-svc-01", "network", "gateway routes to services"),
    ("app-svc-01", "jump-01", "trust", "service account trust"),
    ("jump-01", "db-prod-01", "admin", "admin access to prod DB"),
    ("app-svc-01", "db-replica-01", "network", "reads from replica"),
    ("admin-ws-01", "jump-01", "admin", "admins SSH via jump host"),
    ("hr-ws-07", "admin-ws-01", "network", "same corp subnet"),
]


def reset_network(db: Session, org: Organization) -> None:
    """Delete the org's network data (assets, findings, paths, scans).

    Leaves users and agents intact — used by /api/org/reset and
    /api/org/load-sample so an account keeps its members and agent tokens.
    """
    org_scoped = [
        AttackPath,
        Remediation,
        AssetVulnerability,
        Connection,
        Service,
        Asset,
        RiskZone,
        Scan,
    ]
    path_ids = db.scalars(select(AttackPath.id).where(AttackPath.org_id == org.id)).all()
    if path_ids:
        db.execute(delete(AttackPathStep).where(AttackPathStep.path_id.in_(path_ids)))
    for model in org_scoped:
        db.execute(delete(model).where(model.org_id == org.id))
    db.flush()


def reset_org(db: Session, org: Organization) -> None:
    """Delete all org-scoped rows (network + users + agents) so demo seeding is idempotent."""
    reset_network(db, org)
    db.execute(delete(Agent).where(Agent.org_id == org.id))
    db.execute(delete(User).where(User.org_id == org.id))
    db.flush()


def seed_identity(db: Session) -> Organization:
    """Create (or refresh) the org + demo user + agent — but NO fake network.

    This is what a real deployment boots with: you can log in and the agent can
    report, but the attack map / live watch start EMPTY and fill only with the
    real devices the agent discovers. No fabricated assets ever appear."""
    agent_token, is_demo_token = _resolve_agent_token()
    if is_demo_token:
        logger.warning(
            "Seeding org %r identity with well-known credentials (user %s / password %r, "
            "agent token %r). These are public in the source repo — do NOT expose this "
            "deployment to the internet or reuse these credentials outside local demos.",
            ORG_SLUG, DEMO_USER_EMAIL, DEMO_USER_PASSWORD, DEMO_AGENT_TOKEN,
        )
    else:
        logger.warning(
            "Seeding org %r identity in a non-dev APP_ENV: the public demo agent token "
            "is SKIPPED and a random agent token was generated instead. The demo user "
            "password %r is still well-known — rotate it before exposing this deployment.",
            ORG_SLUG, DEMO_USER_PASSWORD,
        )
    org = db.scalar(select(Organization).where(Organization.slug == ORG_SLUG))
    if org is None:
        org = Organization(name="Acme Retail", slug=ORG_SLUG)
        db.add(org)
        db.flush()
    else:
        reset_org(db, org)

    db.add(
        User(
            org_id=org.id,
            name="Demo Analyst",
            email=DEMO_USER_EMAIL,
            password_hash=hash_password(DEMO_USER_PASSWORD),
            role="analyst",
        )
    )
    db.add(
        Agent(
            org_id=org.id,
            agent_key="agent-demo",
            token_hash=hash_agent_token(agent_token),
            label="Demo network agent",
            status="active",
        )
    )
    db.commit()
    return org


def seed_acme(db: Session) -> Organization:
    """Create (or refresh) the Acme Retail org WITH the sample network. Used by
    tests, the smoke run, and the opt-in demo mode. A live deployment uses
    seed_identity() instead, so no fabricated assets ever ship to the map."""
    org = seed_identity(db)
    seed_network(db, org)
    db.commit()
    return org


def seed_network(db: Session, org: Organization) -> None:
    """Seed the Acme sample network (zones/assets/services/vulns/findings/
    connections) into the GIVEN org. Does not touch users/agents, does not
    commit — callers reset first for idempotency and commit afterwards.
    Reused by /api/org/load-sample to give any new org real engine data.
    """
    zones: dict[str, RiskZone] = {}
    for z in ZONES:
        zone = RiskZone(org_id=org.id, name=z["name"], kind=z["kind"])
        db.add(zone)
        zones[z["name"]] = zone
    db.flush()

    assets: dict[str, Asset] = {}
    for hostname, ip, atype, zone_name, crit, value, exposed, os_name in ASSETS:
        asset = Asset(
            org_id=org.id,
            zone_id=zones[zone_name].id,
            hostname=hostname,
            ip=ip,
            os=os_name,
            asset_type=atype,
            criticality=crit,
            business_value=Decimal(value),
            internet_facing=exposed,
        )
        db.add(asset)
        assets[hostname] = asset
    db.flush()

    services: dict[tuple[str, int], Service] = {}
    for hostname, svc_list in SERVICES.items():
        for port, proto, name, version in svc_list:
            svc = Service(
                org_id=org.id,
                asset_id=assets[hostname].id,
                port=port,
                protocol=proto,
                name=name,
                version=version,
            )
            db.add(svc)
            services[(hostname, port)] = svc
    db.flush()

    vulns: dict[str, Vulnerability] = {}
    for cve, title, cvss, severity, exploitability, cwe, desc in VULNS:
        vuln = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve))
        if vuln is None:
            vuln = Vulnerability(
                cve_id=cve,
                title=title,
                cvss=Decimal(str(cvss)),
                severity=severity,
                exploitability=Decimal(str(exploitability)),
                cwe=cwe,
                description=desc,
            )
            db.add(vuln)
        vulns[cve] = vuln
    db.flush()

    for hostname, cve, port in FINDINGS:
        db.add(
            AssetVulnerability(
                org_id=org.id,
                asset_id=assets[hostname].id,
                vulnerability_id=vulns[cve].id,
                service_id=services.get((hostname, port)).id if port else None,
                status="open",
            )
        )

    for src, dst, relation, note in CONNECTIONS:
        db.add(
            Connection(
                org_id=org.id,
                from_asset_id=assets[src].id,
                to_asset_id=assets[dst].id,
                relation=relation,
                note=note,
            )
        )
    db.flush()
