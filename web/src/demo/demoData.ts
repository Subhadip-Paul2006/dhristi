// Drishti — Frontend-Only Synthetic Demo Data Provider
// Deterministic synthetic data for Vercel demo deployment (Zero Backend Required)
// All data is explicitly labeled as SIMULATED / SYNTHETIC.

import type {
  AssetDetail,
  AssetSummary,
  CveRow,
  Dashboard,
  Distribution,
  EndpointAgent,
  EndpointTelemetryOut,
  EndpointVulnerabilitiesResponse,
  Finding,
  GraphResponse,
  ImpactNarrative,
  LiveThreat,
  Me,
  Member,
  MlAnalysis,
  NetconfigAnalysis,
  NetworkCoverage,
  NetworkDevice,
  NetworkSummary,
  NetworkThreat,
  NodeHardening,
  OrgInfo,
  PathDetail,
  PathSummary,
  Remediation,
  Stats,
  TokenPair,
  UrlAnalysisResult,
  UrlHistoryItem,
} from "../api/types";

// ============================================================================
// 1. IDENTITY & AUTHENTICATION
// ============================================================================

export const DEMO_USER: Me = {
  id: "user-demo-analyst-01",
  name: "Demo Security Analyst",
  email: "analyst@acme-retail.dev",
  role: "analyst",
  org_id: "org-acme-retail-01",
  org_name: "Acme Retail [SIMULATED]",
  org_slug: "acme-retail",
};

export const DEMO_TOKENS: TokenPair = {
  access_token: "drishti-synthetic-demo-access-token-jwt-simulated",
  refresh_token: "drishti-synthetic-demo-refresh-token-simulated",
  token_type: "bearer",
};

export const DEMO_ORG: OrgInfo = {
  id: "org-acme-retail-01",
  name: "Acme Retail [SIMULATED LAB]",
  slug: "acme-retail",
  asset_count: 10,
  open_findings: 6,
  path_count: 3,
  member_count: 3,
};

export const DEMO_MEMBERS: Member[] = [
  { id: "mem-01", name: "Demo Security Analyst", email: "analyst@acme-retail.dev", role: "analyst" },
  { id: "mem-02", name: "SecOps Lead (Simulated)", email: "lead@acme-retail.dev", role: "admin" },
  { id: "mem-03", name: "Compliance Officer (Simulated)", email: "audit@acme-retail.dev", role: "viewer" },
];

// ============================================================================
// 2. SYNTHETIC FINDINGS (NO FABRICATED CVEs)
// ============================================================================

export const DEMO_FINDINGS: Finding[] = [
  {
    id: "finding-demo-001",
    status: "open",
    cve_id: null,
    title: "[SYNTHETIC DEMO FINDING] Public Web Service Unauthenticated RCE",
    severity: "critical",
    cvss: 9.8,
    exploitability: 0.95,
    description: "SIMULATED FINDING: Input sanitization failure in public storefront HTTP handler exposes unauthenticated remote code execution vector.",
    asset_id: "asset-web-app-01",
    asset_hostname: "web-app-01",
    asset_ip: "10.0.1.11",
    service_port: 443,
    detected_at: "2026-09-20T10:14:00Z",
    source: "network",
    observed_product: "node-express",
    observed_version: "4.18.2",
    fixed_version: "4.19.2",
    in_kev: false,
    finding_state: "active",
  },
  {
    id: "finding-demo-002",
    status: "open",
    cve_id: null,
    title: "[SYNTHETIC DEMO FINDING] Deprecated TLS 1.0/1.1 Protocol Enabled",
    severity: "medium",
    cvss: 5.3,
    exploitability: 0.35,
    description: "SIMULATED FINDING: Edge load balancer accepts obsolete TLS 1.0/1.1 protocols with weak CBC cipher suites susceptible to downgrade attacks.",
    asset_id: "asset-web-lb-01",
    asset_hostname: "web-lb-01",
    asset_ip: "10.0.1.10",
    service_port: 443,
    detected_at: "2026-09-20T10:14:00Z",
    source: "network",
    observed_product: "nginx",
    observed_version: "1.18.0",
    fixed_version: "1.24.0",
    in_kev: false,
    finding_state: "active",
  },
  {
    id: "finding-demo-003",
    status: "open",
    cve_id: null,
    title: "[SYNTHETIC DEMO FINDING] API Gateway Server-Side Request Forgery",
    severity: "high",
    cvss: 8.1,
    exploitability: 0.7,
    description: "SIMULATED FINDING: Unchecked redirect URL in API gateway webhook dispatcher allows pivoting to internal VPC microservices.",
    asset_id: "asset-api-gw-01",
    asset_hostname: "api-gw-01",
    asset_ip: "10.0.2.10",
    service_port: 8443,
    detected_at: "2026-09-20T10:15:00Z",
    source: "network",
    observed_product: "kong-gateway",
    observed_version: "3.4.0",
    fixed_version: "3.6.1",
    in_kev: false,
    finding_state: "active",
  },
  {
    id: "finding-demo-004",
    status: "open",
    cve_id: null,
    title: "[SYNTHETIC DEMO FINDING] Bastion Host Password Authentication Enabled",
    severity: "high",
    cvss: 7.5,
    exploitability: 0.65,
    description: "SIMULATED FINDING: Administrative SSH jump host permits interactive password authentication without mandatory FIDO2 hardware keys.",
    asset_id: "asset-jump-01",
    asset_hostname: "jump-01",
    asset_ip: "10.0.2.50",
    service_port: 22,
    detected_at: "2026-09-20T10:16:00Z",
    source: "endpoint",
    observed_product: "openssh-server",
    observed_version: "8.9p1",
    fixed_version: "Config update",
    in_kev: false,
    finding_state: "active",
  },
  {
    id: "finding-demo-005",
    status: "open",
    cve_id: null,
    title: "[SYNTHETIC DEMO FINDING] Database Role Privilege Escalation Vector",
    severity: "high",
    cvss: 8.8,
    exploitability: 0.7,
    description: "SIMULATED FINDING: Over-privileged application connection pool role has superuser schema inheritance on production customer table.",
    asset_id: "asset-db-prod-01",
    asset_hostname: "db-prod-01",
    asset_ip: "10.0.3.11",
    service_port: 5432,
    detected_at: "2026-09-20T10:17:00Z",
    source: "network",
    observed_product: "postgresql",
    observed_version: "14.2",
    fixed_version: "14.11",
    in_kev: false,
    finding_state: "active",
  },
  {
    id: "finding-demo-006",
    status: "open",
    cve_id: null,
    title: "[SYNTHETIC DEMO FINDING] Workstation Scripting Execution Policy",
    severity: "high",
    cvss: 7.8,
    exploitability: 0.55,
    description: "SIMULATED FINDING: IT admin workstation allows unsigned macro/script execution in corporate user profiles without AppLocker constraint.",
    asset_id: "asset-admin-ws-01",
    asset_hostname: "admin-ws-01",
    asset_ip: "10.0.4.5",
    service_port: null,
    detected_at: "2026-09-20T10:18:00Z",
    source: "endpoint",
    observed_product: "windows-policy",
    observed_version: "10.0.22631",
    fixed_version: "GPO Hardened",
    in_kev: false,
    finding_state: "active",
  },
];

// ============================================================================
// 3. ASSETS & INVENTORY
// ============================================================================

export const DEMO_ASSETS: AssetSummary[] = [
  {
    id: "asset-fw-edge-01",
    hostname: "fw-edge-01",
    ip: "10.0.0.1",
    asset_type: "firewall",
    zone: "DMZ",
    criticality: "high",
    business_value: 40000,
    internet_facing: true,
    risk_score: 42,
    blast_radius_count: 8,
    open_findings: 0,
  },
  {
    id: "asset-web-lb-01",
    hostname: "web-lb-01",
    ip: "10.0.1.10",
    asset_type: "webapp",
    zone: "DMZ",
    criticality: "medium",
    business_value: 50000,
    internet_facing: true,
    risk_score: 58,
    blast_radius_count: 5,
    open_findings: 1,
  },
  {
    id: "asset-web-app-01",
    hostname: "web-app-01",
    ip: "10.0.1.11",
    asset_type: "webapp",
    zone: "DMZ",
    criticality: "high",
    business_value: 80000,
    internet_facing: true,
    risk_score: 95,
    blast_radius_count: 6,
    open_findings: 1,
  },
  {
    id: "asset-api-gw-01",
    hostname: "api-gw-01",
    ip: "10.0.2.10",
    asset_type: "server",
    zone: "App Tier",
    criticality: "high",
    business_value: 250000,
    internet_facing: false,
    risk_score: 84,
    blast_radius_count: 5,
    open_findings: 1,
  },
  {
    id: "asset-app-svc-01",
    hostname: "app-svc-01",
    ip: "10.0.2.11",
    asset_type: "server",
    zone: "App Tier",
    criticality: "high",
    business_value: 300000,
    internet_facing: false,
    risk_score: 65,
    blast_radius_count: 4,
    open_findings: 0,
  },
  {
    id: "asset-jump-01",
    hostname: "jump-01",
    ip: "10.0.2.50",
    asset_type: "server",
    zone: "App Tier",
    criticality: "high",
    business_value: 120000,
    internet_facing: false,
    risk_score: 82,
    blast_radius_count: 4,
    open_findings: 1,
  },
  {
    id: "asset-db-prod-01",
    hostname: "db-prod-01",
    ip: "10.0.3.11",
    asset_type: "database",
    zone: "Data Tier",
    criticality: "critical",
    business_value: 3500000,
    internet_facing: false,
    risk_score: 92,
    blast_radius_count: 1,
    open_findings: 1,
  },
  {
    id: "asset-db-replica-01",
    hostname: "db-replica-01",
    ip: "10.0.3.12",
    asset_type: "database",
    zone: "Data Tier",
    criticality: "high",
    business_value: 1200000,
    internet_facing: false,
    risk_score: 70,
    blast_radius_count: 1,
    open_findings: 0,
  },
  {
    id: "asset-admin-ws-01",
    hostname: "admin-ws-01",
    ip: "10.0.4.5",
    asset_type: "workstation",
    zone: "Corp",
    criticality: "medium",
    business_value: 60000,
    internet_facing: false,
    risk_score: 76,
    blast_radius_count: 3,
    open_findings: 1,
  },
  {
    id: "asset-android-fleet-01",
    hostname: "android-fleet-01",
    ip: "10.0.4.25",
    asset_type: "mobile",
    zone: "Corp",
    criticality: "low",
    business_value: 20000,
    internet_facing: false,
    risk_score: 35,
    blast_radius_count: 2,
    open_findings: 0,
  },
];

export function getDemoAssetDetail(id: string): AssetDetail {
  const base = DEMO_ASSETS.find((a) => a.id === id) || DEMO_ASSETS[0];
  const findings = DEMO_FINDINGS.filter((f) => f.asset_id === base.id);

  const services = [
    { id: "svc-01", port: 443, protocol: "tcp", name: "https", version: "TLS 1.3" },
    { id: "svc-02", port: 22, protocol: "tcp", name: "ssh", version: "OpenSSH 8.9" },
  ];

  return {
    ...base,
    os: base.hostname?.includes("ws")
      ? "Windows 11 Enterprise (23H2)"
      : base.hostname?.includes("android")
      ? "Android 15 (VanillaIceCream API 35)"
      : "Ubuntu 22.04 LTS",
    services,
    findings,
    downstream_value: 3500000,
  };
}

// ============================================================================
// 4. ATTACK PATHS & GRAPH
// ============================================================================

export const DEMO_PATHS: PathSummary[] = [
  {
    id: "path-hero-001",
    entry_label: "Internet Ingress (web-lb-01)",
    target_asset_id: "asset-db-prod-01",
    target_hostname: "db-prod-01",
    hop_count: 5,
    path_risk: 0.94,
    likelihood: 0.88,
    impact_usd: 3500000,
    narrative: "[SIMULATED ATTACK PATH] External ingress through unauthenticated storefront HTTP handler leads directly to crown jewel customer records.",
  },
  {
    id: "path-admin-002",
    entry_label: "Corporate Workstation (admin-ws-01)",
    target_asset_id: "asset-db-prod-01",
    target_hostname: "db-prod-01",
    hop_count: 4,
    path_risk: 0.78,
    likelihood: 0.65,
    impact_usd: 1200000,
    narrative: "[SIMULATED ATTACK PATH] Internal phishing compromise on IT administrative workstation enables lateral pivoting across bastion jump host.",
  },
  {
    id: "path-replica-003",
    entry_label: "Internal Ingress (api-gw-01)",
    target_asset_id: "asset-db-replica-01",
    target_hostname: "db-replica-01",
    hop_count: 3,
    path_risk: 0.62,
    likelihood: 0.52,
    impact_usd: 800000,
    narrative: "[SIMULATED ATTACK PATH] Internal API gateway SSRF pivots to backend reporting database read replica.",
  },
];

export function getDemoPathDetail(id: string): PathDetail {
  const summary = DEMO_PATHS.find((p) => p.id === id) || DEMO_PATHS[0];
  return {
    ...summary,
    steps: [
      {
        step_index: 1,
        asset_id: "asset-web-lb-01",
        asset_hostname: "web-lb-01",
        asset_ip: "10.0.1.10",
        asset_type: "webapp",
        zone: "DMZ",
        via_cve: null,
        via_title: "[SIMULATED] Outdated TLS Configuration",
        via_severity: "medium",
        via_cvss: 5.3,
        edge_weight: 0.3,
      },
      {
        step_index: 2,
        asset_id: "asset-web-app-01",
        asset_hostname: "web-app-01",
        asset_ip: "10.0.1.11",
        asset_type: "webapp",
        zone: "DMZ",
        via_cve: null,
        via_title: "[SIMULATED] Public Web Service Unauthenticated RCE",
        via_severity: "critical",
        via_cvss: 9.8,
        edge_weight: 0.95,
      },
      {
        step_index: 3,
        asset_id: "asset-api-gw-01",
        asset_hostname: "api-gw-01",
        asset_ip: "10.0.2.10",
        asset_type: "server",
        zone: "App Tier",
        via_cve: null,
        via_title: "[SIMULATED] API Gateway SSRF Vulnerability",
        via_severity: "high",
        via_cvss: 8.1,
        edge_weight: 0.7,
      },
      {
        step_index: 4,
        asset_id: "asset-jump-01",
        asset_hostname: "jump-01",
        asset_ip: "10.0.2.50",
        asset_type: "server",
        zone: "App Tier",
        via_cve: null,
        via_title: "[SIMULATED] Bastion SSH Password Authentication",
        via_severity: "high",
        via_cvss: 7.5,
        edge_weight: 0.65,
      },
      {
        step_index: 5,
        asset_id: "asset-db-prod-01",
        asset_hostname: "db-prod-01",
        asset_ip: "10.0.3.11",
        asset_type: "database",
        zone: "Data Tier",
        via_cve: null,
        via_title: "[SIMULATED] Database Superuser Privilege Escalation",
        via_severity: "high",
        via_cvss: 8.8,
        edge_weight: 0.85,
      },
    ],
    drivers: [
      "Public-facing RCE vulnerability on web-app-01 ($3.5M crown jewel reachability)",
      "Unrestricted egress from DMZ to internal microservices tier",
      "Shared credential usage across bastion host jump-01",
    ],
  };
}

export const DEMO_GRAPH: GraphResponse = {
  nodes: [
    {
      id: "asset-fw-edge-01",
      type: "asset",
      position: { x: 50, y: 220 },
      data: {
        label: "fw-edge-01",
        asset_type: "firewall",
        zone: "DMZ",
        criticality: "high",
        risk_score: 42,
        business_value: 40000,
        internet_facing: true,
        open_findings: 0,
        is_crown_jewel: false,
        in_blast_radius: null,
        online: true,
        ip: "10.0.0.1",
      },
    },
    {
      id: "asset-web-lb-01",
      type: "asset",
      position: { x: 220, y: 150 },
      data: {
        label: "web-lb-01",
        asset_type: "webapp",
        zone: "DMZ",
        criticality: "medium",
        risk_score: 58,
        business_value: 50000,
        internet_facing: true,
        open_findings: 1,
        is_crown_jewel: false,
        in_blast_radius: null,
        online: true,
        ip: "10.0.1.10",
      },
    },
    {
      id: "asset-web-app-01",
      type: "asset",
      position: { x: 420, y: 150 },
      data: {
        label: "web-app-01",
        asset_type: "webapp",
        zone: "DMZ",
        criticality: "high",
        risk_score: 95,
        business_value: 80000,
        internet_facing: true,
        open_findings: 1,
        is_crown_jewel: false,
        in_blast_radius: null,
        online: true,
        ip: "10.0.1.11",
        threat: true,
        threat_kind: "RCE Exposure",
        threat_severity: "critical",
        threat_title: "[SIMULATED VULN] Unauthenticated Web RCE",
      },
    },
    {
      id: "asset-api-gw-01",
      type: "asset",
      position: { x: 620, y: 180 },
      data: {
        label: "api-gw-01",
        asset_type: "server",
        zone: "App Tier",
        criticality: "high",
        risk_score: 84,
        business_value: 250000,
        internet_facing: false,
        open_findings: 1,
        is_crown_jewel: false,
        in_blast_radius: null,
        online: true,
        ip: "10.0.2.10",
      },
    },
    {
      id: "asset-jump-01",
      type: "asset",
      position: { x: 820, y: 220 },
      data: {
        label: "jump-01",
        asset_type: "server",
        zone: "App Tier",
        criticality: "high",
        risk_score: 82,
        business_value: 120000,
        internet_facing: false,
        open_findings: 1,
        is_crown_jewel: false,
        in_blast_radius: null,
        online: true,
        ip: "10.0.2.50",
      },
    },
    {
      id: "asset-db-prod-01",
      type: "asset",
      position: { x: 1040, y: 220 },
      data: {
        label: "db-prod-01",
        asset_type: "database",
        zone: "Data Tier",
        criticality: "critical",
        risk_score: 92,
        business_value: 3500000,
        internet_facing: false,
        open_findings: 1,
        is_crown_jewel: true,
        in_blast_radius: null,
        online: true,
        ip: "10.0.3.11",
      },
    },
    {
      id: "asset-admin-ws-01",
      type: "asset",
      position: { x: 620, y: 350 },
      data: {
        label: "admin-ws-01",
        asset_type: "workstation",
        zone: "Corp",
        criticality: "medium",
        risk_score: 76,
        business_value: 60000,
        internet_facing: false,
        open_findings: 1,
        is_crown_jewel: false,
        in_blast_radius: null,
        online: true,
        ip: "10.0.4.5",
      },
    },
    {
      id: "asset-android-fleet-01",
      type: "asset",
      position: { x: 420, y: 350 },
      data: {
        label: "android-fleet-01",
        asset_type: "mobile",
        zone: "Corp",
        criticality: "low",
        risk_score: 35,
        business_value: 20000,
        internet_facing: false,
        open_findings: 0,
        is_crown_jewel: false,
        in_blast_radius: null,
        online: true,
        ip: "10.0.4.25",
      },
    },
  ],
  edges: [
    {
      id: "e-fw-lb",
      source: "asset-fw-edge-01",
      target: "asset-web-lb-01",
      data: { relation: "network", weight: 0.1, via_cve: null, on_top_path: true, path_id: "path-hero-001" },
    },
    {
      id: "e-lb-app",
      source: "asset-web-lb-01",
      target: "asset-web-app-01",
      data: { relation: "network", weight: 0.3, via_cve: null, on_top_path: true, path_id: "path-hero-001" },
    },
    {
      id: "e-app-gw",
      source: "asset-web-app-01",
      target: "asset-api-gw-01",
      data: { relation: "network", weight: 0.4, via_cve: null, on_top_path: true, path_id: "path-hero-001" },
    },
    {
      id: "e-gw-jump",
      source: "asset-api-gw-01",
      target: "asset-jump-01",
      data: { relation: "trust", weight: 0.5, via_cve: null, on_top_path: true, path_id: "path-hero-001" },
    },
    {
      id: "e-jump-db",
      source: "asset-jump-01",
      target: "asset-db-prod-01",
      data: { relation: "admin", weight: 0.8, via_cve: null, on_top_path: true, path_id: "path-hero-001" },
    },
    {
      id: "e-ws-jump",
      source: "asset-admin-ws-01",
      target: "asset-jump-01",
      data: { relation: "admin", weight: 0.4, via_cve: null, on_top_path: false, path_id: "path-admin-002" },
    },
    {
      id: "e-mobile-ws",
      source: "asset-android-fleet-01",
      target: "asset-admin-ws-01",
      data: { relation: "network", weight: 0.2, via_cve: null, on_top_path: false, path_id: null },
    },
  ],
  meta: {
    entry_nodes: ["asset-fw-edge-01", "asset-web-lb-01"],
    crown_jewels: ["asset-db-prod-01"],
    focus: null,
    blast_radius_ids: [],
  },
};

// ============================================================================
// 5. DASHBOARD & STATS
// ============================================================================

export const DEMO_DASHBOARD: Dashboard = {
  total_exposure_usd: 3500000,
  open_findings: 6,
  critical_assets: 1,
  top_path_risk: 0.94,
  top_paths: DEMO_PATHS,
  zone_summary: [
    { name: "DMZ", kind: "dmz", asset_count: 3, worst_risk: 0.95 },
    { name: "App Tier", kind: "internal", asset_count: 3, worst_risk: 0.84 },
    { name: "Data Tier", kind: "crown_jewel", asset_count: 2, worst_risk: 0.92 },
    { name: "Corp", kind: "internal", asset_count: 2, worst_risk: 0.76 },
  ],
  severity_breakdown: {
    critical: 1,
    high: 4,
    medium: 1,
    low: 0,
  },
};

export const DEMO_STATS: Stats = {
  nodes: 10,
  edges: 8,
  paths: 3,
  recompute_ms: 18.4,
  top_path_risk: 0.94,
  assets: 10,
  open_findings: 6,
  ai_calls: 12,
  ai_mock_calls: 12,
};

// ============================================================================
// 6. LIVE WATCH & NETWORK DEVICES
// ============================================================================

export const DEMO_NETWORK_DEVICES: NetworkDevice[] = [
  {
    id: "dev-win-01",
    ip: "10.0.4.5",
    mac: "00:1A:2B:3C:4D:5E",
    subnet: "10.0.4.0/24",
    subnet_inferred: false,
    discovery: "arp",
    label: "IT Admin Workstation",
    hostname: "admin-ws-01",
    vendor: "Dell Inc.",
    is_self: false,
    is_gateway: false,
    online: true,
    first_seen: "2026-09-20T08:00:00Z",
    last_seen: "2026-09-23T12:00:00Z",
    scanned: true,
    vuln_count: 1,
    worst_severity: "high",
    last_scanned_at: "2026-09-23T10:00:00Z",
    device_type: "workstation",
    os_info: "Windows 11 Enterprise (23H2)",
    open_ports: [135, 445, 3389],
    risk_score: 76,
    capability_state: "FULL ENDPOINT TELEMETRY",
    presence_state: "continuous",
    paired_endpoint_status: "ONLINE",
    paired_endpoint_hostname: "WIN-ADMIN-01",
    device_security_score: 0.74,
  },
  {
    id: "dev-and-01",
    ip: "10.0.4.25",
    mac: "02:00:00:7A:B1:2C",
    subnet: "10.0.4.0/24",
    subnet_inferred: false,
    discovery: "arp",
    label: "Field Tech Android Fleet",
    hostname: "android-fleet-01",
    vendor: "Google Pixel 8",
    is_self: false,
    is_gateway: false,
    online: true,
    first_seen: "2026-09-21T09:30:00Z",
    last_seen: "2026-09-23T12:02:00Z",
    scanned: true,
    vuln_count: null,
    worst_severity: null,
    last_scanned_at: null,
    device_type: "mobile",
    os_info: "Android 15 (VanillaIceCream API 35)",
    open_ports: [],
    risk_score: 35,
    capability_state: "FULL ENDPOINT TELEMETRY",
    presence_state: "continuous",
    paired_endpoint_status: "ONLINE",
    paired_endpoint_hostname: "Pixel-8-Enterprise",
    vpn_status: "ACTIVE [DEFENSIVE SHIELD]",
    device_security_score: 0.88,
  },
  {
    id: "dev-srv-01",
    ip: "10.0.1.11",
    mac: "52:54:00:A1:B2:C3",
    subnet: "10.0.1.0/24",
    subnet_inferred: false,
    discovery: "arp",
    label: "Storefront Web Application",
    hostname: "web-app-01",
    vendor: "QEMU / KVM Virtual",
    is_self: false,
    is_gateway: false,
    online: true,
    first_seen: "2026-09-18T00:00:00Z",
    last_seen: "2026-09-23T12:05:00Z",
    scanned: true,
    vuln_count: 1,
    worst_severity: "critical",
    last_scanned_at: "2026-09-23T06:00:00Z",
    device_type: "server",
    os_info: "Ubuntu 22.04 LTS (Kernel 6.2.0)",
    open_ports: [22, 80, 443],
    risk_score: 95,
    capability_state: "AGENT CONNECTED",
    presence_state: "continuous",
    device_security_score: 0.45,
  },
  {
    id: "dev-db-01",
    ip: "10.0.3.11",
    mac: "52:54:00:D3:E4:F5",
    subnet: "10.0.3.0/24",
    subnet_inferred: false,
    discovery: "arp",
    label: "Production Customer Database",
    hostname: "db-prod-01",
    vendor: "QEMU / KVM Virtual",
    is_self: false,
    is_gateway: false,
    online: true,
    first_seen: "2026-09-18T00:00:00Z",
    last_seen: "2026-09-23T12:05:00Z",
    scanned: true,
    vuln_count: 1,
    worst_severity: "high",
    last_scanned_at: "2026-09-23T06:00:00Z",
    device_type: "database",
    os_info: "Ubuntu 22.04 LTS",
    open_ports: [22, 5432],
    risk_score: 92,
    capability_state: "NETWORK ONLY",
    presence_state: "continuous",
    device_security_score: 0.52,
  },
  {
    id: "dev-gw-01",
    ip: "10.0.0.1",
    mac: "00:0C:29:4F:8D:11",
    subnet: "10.0.0.0/24",
    subnet_inferred: false,
    discovery: "arp",
    label: "Perimeter Security Gateway",
    hostname: "fw-edge-01",
    vendor: "Palo Alto Networks",
    is_self: false,
    is_gateway: true,
    online: true,
    first_seen: "2026-09-15T00:00:00Z",
    last_seen: "2026-09-23T12:05:00Z",
    scanned: true,
    vuln_count: null,
    worst_severity: null,
    last_scanned_at: null,
    device_type: "firewall",
    os_info: "PanOS 11.0",
    open_ports: [443],
    risk_score: 42,
    capability_state: "NETWORK ONLY",
    presence_state: "continuous",
    device_security_score: 0.90,
  },
];

export const DEMO_ENDPOINT_AGENTS: EndpointAgent[] = [
  {
    id: "agent-win-01",
    organization_id: "org-acme-retail-01",
    agent_id: "agent-win-01",
    device_id: "dev-win-01",
    hostname: "WIN-ADMIN-01",
    os: "Windows",
    os_version: "11 Enterprise (23H2)",
    mac: "00:1A:2B:3C:4D:5E",
    current_ip: "10.0.4.5",
    agent_version: "1.0.0",
    status: "ONLINE",
    paired_at: "2026-09-20T08:00:00Z",
    registered_at: "2026-09-20T08:00:00Z",
    last_heartbeat: "2026-09-23T12:05:00Z",
    created_at: "2026-09-20T08:00:00Z",
    updated_at: "2026-09-23T12:05:00Z",
  },
  {
    id: "agent-and-01",
    organization_id: "org-acme-retail-01",
    agent_id: "agent-and-01",
    device_id: "dev-and-01",
    hostname: "Pixel-8-Enterprise",
    os: "Android",
    os_version: "15 (API 35)",
    mac: "02:00:00:7A:B1:2C",
    current_ip: "10.0.4.25",
    agent_version: "1.0.0",
    status: "ONLINE",
    paired_at: "2026-09-21T09:30:00Z",
    registered_at: "2026-09-21T09:30:00Z",
    last_heartbeat: "2026-09-23T12:04:30Z",
    created_at: "2026-09-21T09:30:00Z",
    updated_at: "2026-09-23T12:04:30Z",
  },
];

export function getDemoEndpointTelemetry(deviceId: string): EndpointTelemetryOut {
  const isAndroid = deviceId.includes("and");
  return {
    device_id: deviceId,
    agent_id: isAndroid ? "agent-and-01" : "agent-win-01",
    hostname: isAndroid ? "Pixel-8-Enterprise" : "WIN-ADMIN-01",
    os_name: isAndroid ? "Android" : "Windows",
    os_version: isAndroid ? "15 (API 35)" : "11 Enterprise (23H2)",
    os_info: isAndroid ? "Google Tensor G3, Android 15 VanillaIceCream" : "AMD Ryzen 7 PRO 7840U, 32 GB RAM",
    last_updated: "2026-09-23T12:05:00Z",
    is_stale: false,
    is_software_stale: false,
    source: "endpoint-agent",
    device_model: isAndroid ? "Pixel 8 Pro" : "ThinkPad T14s Gen 4",
    manufacturer: isAndroid ? "Google" : "Lenovo",
    cpu_info: {
      cores: isAndroid ? 9 : 16,
      usage_percent: isAndroid ? null : 24.5,
      architecture: isAndroid ? "aarch64" : "x86_64",
    },
    memory_info: {
      total_bytes: isAndroid ? 12884901888 : 34359738368,
      available_bytes: isAndroid ? 6442450944 : 21474836480,
      used_bytes: isAndroid ? 6442450944 : 12884901888,
    },
    battery_info: isAndroid
      ? { percentage: 86, charging: false, health: "GOOD", temperature_c: 29.5 }
      : undefined,
    endpoint_processes: [
      { pid: 404, name: "System", exe_path: "C:\\Windows\\system32\\ntoskrnl.exe", cpu_percent: 0.8, memory_mb: 14.5 },
      { pid: 1120, name: "lsass.exe", exe_path: "C:\\Windows\\system32\\lsass.exe", cpu_percent: 0.2, memory_mb: 28.4 },
      { pid: 2840, name: "svchost.exe", exe_path: "C:\\Windows\\system32\\svchost.exe", cpu_percent: 1.1, memory_mb: 42.1 },
      { pid: 5612, name: "msedge.exe", exe_path: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", cpu_percent: 4.2, memory_mb: 185.0 },
      { pid: 7890, name: "DrishtiAgent.exe", exe_path: "C:\\Program Files\\Drishti\\DrishtiAgent.exe", cpu_percent: 0.4, memory_mb: 35.0 },
    ],
    installed_software: [
      { name: "Google Chrome", version: "128.0.6613.120", install_location: "C:\\Program Files\\Google\\Chrome" },
      { name: "OpenSSH for Windows", version: "8.9.1.0", install_location: "C:\\Windows\\System32\\OpenSSH" },
      { name: "Wireshark", version: "4.2.4", install_location: "C:\\Program Files\\Wireshark" },
      { name: "Visual Studio Code", version: "1.93.0", install_location: "C:\\Program Files\\Microsoft VS Code" },
    ],
    listening_ports: [
      { port: 135, protocol: "tcp", bind_address: "0.0.0.0", process_name: "svchost.exe", pid: 884 },
      { port: 445, protocol: "tcp", bind_address: "0.0.0.0", process_name: "System", pid: 4 },
      { port: 3389, protocol: "tcp", bind_address: "0.0.0.0", process_name: "TermService", pid: 1420 },
    ],
    process_connections: [
      { pid: 9140, process_name: "ssh.exe", protocol: "tcp", local_address: "10.0.4.5", local_port: 54120, remote_address: "10.0.2.50", remote_port: 22, state: "ESTABLISHED" },
      { pid: 5612, process_name: "msedge.exe", protocol: "tcp", local_address: "10.0.4.5", local_port: 54122, remote_address: "10.0.0.1", remote_port: 443, state: "ESTABLISHED" },
    ],
    services: [
      { name: "TermService", display_name: "Remote Desktop Services", status: "RUNNING" },
      { name: "LanmanServer", display_name: "Server (SMB)", status: "RUNNING" },
    ],
    active_apps: isAndroid ? ["com.google.android.chrome", "com.drishti.agent"] : ["msedge.exe", "powershell.exe"],
    installed_browsers: ["Chrome", "Edge"],
    browser_processes: [],
  };
}

export function getDemoEndpointVulnerabilities(deviceId: string): EndpointVulnerabilitiesResponse {
  return {
    device_id: deviceId,
    total_findings: 1,
    vulnerable_count: 1,
    known_exploited_count: 0,
    potential_match_count: 0,
    source_statuses: [
      { source_name: "NVD_LOCAL_CACHE", available: true, is_stale: false },
      { source_name: "CISA_KEV", available: true, is_stale: false },
    ],
    findings: [
      {
        finding_id: "find-ep-01",
        device_id: deviceId,
        org_id: "org-acme-retail-01",
        finding_state: "VULNERABLE",
        evidence_source: "endpoint_software",
        evidence_type: "SOFTWARE_VERSION_AUDIT",
        observed_product: "PowerShell 7.4.2",
        observed_version: "7.4.2",
        cve_id: null,
        title: "[SYNTHETIC DEMO FINDING] Workstation Script Execution Policy",
        summary: "SIMULATED FINDING: Administrative workstation permits script execution in non-privileged user space without constrained language mode.",
        cvss: 7.8,
        severity: "HIGH",
        in_kev: false,
        ghsa_ids: [],
        intel_sources: ["Local Heuristic Analysis"],
        source_freshness: "Simulated",
        source_details: { simulated: true },
      },
    ],
  };
}

// ============================================================================
// 7. REMEDIATION PLAYBOOKS (DETERMINISTIC & NOT EXECUTED)
// ============================================================================

export function getDemoRemediation(findingId: string, preferredKind: string): Remediation {
  const finding = DEMO_FINDINGS.find((f) => f.id === findingId) || DEMO_FINDINGS[0];

  const ansiblePlaybook = `---
# [DEMO PLAYBOOK // SYNTHETIC DEFENSE SPECIFICATION]
# Target Finding: ${finding.title}
# Host: ${finding.asset_hostname} (${finding.asset_ip})
# Status: NOT EXECUTED (DEMO ONLY)

- name: Remediate Security Finding on ${finding.asset_hostname}
  hosts: ${finding.asset_hostname}
  become: yes
  tasks:
    - name: Ensure hardened configuration package is current
      apt:
        name: "${finding.observed_product || 'security-updates'}"
        state: latest
        update_cache: yes

    - name: Deploy restricted firewall boundary rule
      iptables:
        chain: INPUT
        protocol: tcp
        destination_port: "${finding.service_port || '443'}"
        source: "10.0.0.0/16"
        jump: ACCEPT
        comment: "DRISHTI-DEMO-HARDENING: Restrict to VPC internal"

    - name: Drop untrusted external ingress
      iptables:
        chain: INPUT
        protocol: tcp
        destination_port: "${finding.service_port || '443'}"
        jump: DROP`;

  const shellScript = `#!/usr/bin/env bash
# [DEMO REMEDIATION SCRIPT // NOT EXECUTED]
# Target: ${finding.asset_hostname} (${finding.asset_ip})

echo "Applying defensive remediation for ${finding.title}..."
sudo ufw deny from any to any port ${finding.service_port || 443} proto tcp comment "Drishti demo block"
sudo ufw allow from 10.0.0.0/8 to any port ${finding.service_port || 443} proto tcp comment "Drishti internal only"
sudo systemctl reload ufw
echo "Remediation verified successfully (Simulated)."`;

  return {
    id: `rem-${finding.id}`,
    refused: false,
    reason: null,
    kind: preferredKind || "ansible",
    title: `Remediate ${finding.title}`,
    summary: `[DEMO REMEDIATION // NOT EXECUTED] Defensive mitigation guide and automation recipe for ${finding.title}. Generated in demo environment.`,
    script: preferredKind === "shell" ? shellScript : ansiblePlaybook,
    steps: [
      "Step 1: Isolate network interface to internal RFC1918 traffic.",
      "Step 2: Apply vendor security patch to fixed version.",
      "Step 3: Validate listening ports and reload service daemon.",
    ],
    estimated_risk_reduction: 0.85,
    requires_restart: false,
    disclaimer: "DEMO REMEDIATION: Deterministic simulated playbook. No commands have been executed on real systems.",
    reviewed: true,
    model: "Llama-3.3-70B-Instruct (Simulated Output)",
  };
}

export function getDemoImpact(_pathId: string): ImpactNarrative {
  return {
    refused: false,
    reason: null,
    impact_usd: 3500000,
    headline: "[SIMULATED SCENARIO] Infiltration from DMZ Web Storefront to Core Customer Database",
    narrative: "[SIMULATED ANALYSIS] Attack path walks across five interconnected tiers starting from the public web load balancer and terminating at the crown jewel PostgreSQL database ($3,500,000 asset value). Compromise of the intermediate API gateway exposes all downstream service accounts in the 10.0.2.0/24 subnet.",
    drivers: [
      "Initial ingress via unauthenticated storefront container vulnerability",
      "Lateral pivot across administrative jump host jump-01",
      "Crown jewel database access resulting in $3.5M theoretical data breach liability",
    ],
    highest_leverage_action: "Apply network boundary rule at API gateway to terminate external pivot path.",
  };
}

// ============================================================================
// 8. TELEGRAM ALERT (SIMULATED UI ONLY)
// ============================================================================

export const DEMO_TELEGRAM_STATUS = {
  configured: true,
  running: true,
  chat_ids_count: 1,
  chat_ids_masked: ["@drishti_soc_demo"],
  alerted_count: 4,
};

export const DEMO_TELEGRAM_TEST = {
  success: true,
  results: [{ chat_id: "@drishti_soc_demo", delivered: true }],
};

// ============================================================================
// 9. URL TRUST ANALYZER (SIMULATED)
// ============================================================================

export function getDemoUrlAnalysis(url: string): UrlAnalysisResult {
  const isSuspicious = url.toLowerCase().includes("phish") || url.toLowerCase().includes("malware") || url.toLowerCase().includes("bad");
  return {
    url,
    final_url: url.startsWith("http") ? url : `https://${url}`,
    score: isSuspicious ? 0.28 : 0.94,
    band: isSuspicious ? "High Risk" : "Trusted",
    evaluated_count: 4,
    signals: [
      { key: "ssl", label: "SSL Certificate", status: isSuspicious ? "fail" : "pass", detail: isSuspicious ? "Self-signed certificate with mismatching CN" : "Valid Let's Encrypt Authority X3 certificate", weight: 0.3, counted: true },
      { key: "whois", label: "Domain Age / WHOIS", status: isSuspicious ? "warn" : "pass", detail: isSuspicious ? "Domain registered < 7 days ago" : "Domain registered 4+ years ago", weight: 0.25, counted: true },
      { key: "gsb", label: "Google Safe Browsing", status: isSuspicious ? "fail" : "pass", detail: isSuspicious ? "Simulated heuristic flag" : "No known malicious flags", weight: 0.25, counted: true },
      { key: "vt", label: "VirusTotal Detection", status: isSuspicious ? "fail" : "pass", detail: isSuspicious ? "3/88 engines flagged domain" : "0/88 security engines flagged", weight: 0.2, counted: true },
    ],
    website: {
      scheme: "https",
      host: new URL(url.startsWith("http") ? url : `https://${url}`).hostname,
      https: true,
      tls: { valid: !isSuspicious, issuer: "Let's Encrypt", expires: "2027-01-01" },
      domain_age_days: isSuspicious ? 4 : 1420,
      registrar: "Cloudflare, Inc.",
      http_status: 200,
      redirect_chain: [],
      redirects_offsite: false,
    },
    providers: {
      safe_browsing: {
        configured: true,
        verdict: isSuspicious ? "flagged" : "clean",
        threats: isSuspicious ? ["MALWARE_HEURISTIC"] : null,
        error: null,
      },
      virustotal: {
        configured: true,
        malicious: isSuspicious ? 3 : 0,
        suspicious: isSuspicious ? 1 : 0,
        harmless: 84,
        reputation: isSuspicious ? -15 : 95,
        error: null,
      },
    },
    ai_summary: isSuspicious
      ? "[SIMULATED AI OUTPUT] High probability credential harvesting site based on recent domain creation and deceptive branding."
      : "[SIMULATED AI OUTPUT] Established corporate web domain with valid TLS encryption and clean telemetry signals.",
    generated_at: "2026-09-23T12:00:00Z",
    disclaimer: "SIMULATED TELEMETRY: Analysis produced deterministically for offline demonstration.",
  };
}

export const DEMO_URL_HISTORY: UrlHistoryItem[] = [
  { id: "hist-01", url: "https://auth.acme-retail.dev/login", score: 0.96, band: "Trusted", created_at: "2026-09-23T11:40:00Z" },
  { id: "hist-02", url: "https://phishing-portal-simulated.net", score: 0.19, band: "High Risk", created_at: "2026-09-23T11:15:00Z" },
  { id: "hist-03", url: "https://cdn.internal-tools.dev", score: 0.91, band: "Trusted", created_at: "2026-09-23T10:30:00Z" },
];

// ============================================================================
// 10. REPORTS & ML CLASSIFICATION
// ============================================================================

export const DEMO_REPORT_CVES: CveRow[] = [
  { cve_id: null, title: "[SYNTHETIC] Public Web Service Unauthenticated RCE", cvss: 9.8, severity: "critical", affected_count: 1, affected: [{ hostname: "web-app-01", ip: "10.0.1.11" }] },
  { cve_id: null, title: "[SYNTHETIC] API Gateway Server-Side Request Forgery", cvss: 8.1, severity: "high", affected_count: 1, affected: [{ hostname: "api-gw-01", ip: "10.0.2.10" }] },
  { cve_id: null, title: "[SYNTHETIC] Database Schema Role Superuser Escalation", cvss: 8.8, severity: "high", affected_count: 1, affected: [{ hostname: "db-prod-01", ip: "10.0.3.11" }] },
  { cve_id: null, title: "[SYNTHETIC] Bastion SSH Password Auth Enabled", cvss: 7.5, severity: "high", affected_count: 1, affected: [{ hostname: "jump-01", ip: "10.0.2.50" }] },
  { cve_id: null, title: "[SYNTHETIC] Macro Execution Policy on Admin Desktop", cvss: 7.8, severity: "high", affected_count: 1, affected: [{ hostname: "admin-ws-01", ip: "10.0.4.5" }] },
  { cve_id: null, title: "[SYNTHETIC] Outdated TLS 1.0/1.1 Protocol Suite", cvss: 5.3, severity: "medium", affected_count: 1, affected: [{ hostname: "web-lb-01", ip: "10.0.1.10" }] },
];

export const DEMO_REPORT_DISTRIBUTION: Distribution = {
  total_assets: 10,
  average_risk: 0.68,
  bands: [
    { band: "Critical", count: 1, pct: 10 },
    { band: "High", count: 4, pct: 40 },
    { band: "Medium", count: 1, pct: 10 },
    { band: "Low", count: 4, pct: 40 },
  ],
};

export const DEMO_REPORT_ML: MlAnalysis = {
  available: true,
  algorithm_note: "[SIMULATED AI OUTPUT] Graph Spectral Clustering & Yen's Path Reachability Analysis",
  anomalies: [
    { hostname: "web-app-01", ip: "10.0.1.11", anomaly_score: 0.94, risk_score: 0.95, reason: "High public exposure with unconstrained lateral pivot edges" },
    { hostname: "jump-01", ip: "10.0.2.50", anomaly_score: 0.81, risk_score: 0.82, reason: "Bottleneck node bridging DMZ tier to crown jewel data tier" },
  ],
  segments: [
    { segment: 1, risk_pct: 42, label: "DMZ Public Exposure Cluster", members: ["web-lb-01", "web-app-01", "fw-edge-01"] },
    { segment: 2, risk_pct: 38, label: "Internal Core Transit Cluster", members: ["api-gw-01", "app-svc-01", "jump-01"] },
    { segment: 3, risk_pct: 20, label: "Protected Data & Corp Cluster", members: ["db-prod-01", "db-replica-01", "admin-ws-01", "android-fleet-01"] },
  ],
};

export const DEMO_REPORT_HARDENING: NodeHardening[] = [
  {
    hostname: "jump-01",
    ip: "10.0.2.50",
    current_score: 82,
    projected_score: 34,
    reduction_pct: 58.5,
    band_before: "High",
    band_after: "Low",
    actions: [
      { kind: "CLOSE_PORT", label: "Disable password authentication on SSH (Port 22)", risk_reduction_pct: 35 },
      { kind: "VLAN_SEGMENT", label: "Restrict access strictly to administrative subnet", risk_reduction_pct: 23.5 },
    ],
  },
  {
    hostname: "web-app-01",
    ip: "10.0.1.11",
    current_score: 95,
    projected_score: 40,
    reduction_pct: 57.9,
    band_before: "Critical",
    band_after: "Medium",
    actions: [
      { kind: "PATCH", label: "Upgrade storefront application to patched runtime", risk_reduction_pct: 45 },
      { kind: "ISOLATE_CONNECTION", label: "Filter egress to internal API Gateway webhook endpoint", risk_reduction_pct: 12.9 },
    ],
  },
];

export const DEMO_REPORT_SUMMARY: NetworkSummary = {
  refused: false,
  reason: null,
  headline: "[SIMULATED REPORT] Acme Retail Attack Surface Exposure Summary",
  narrative: "Comprehensive simulation of the Acme Retail hybrid network architecture reveals 10 inventory nodes spanning DMZ, App, Data, and Corporate tiers. A high-priority critical path terminates at the customer database db-prod-01 ($3.5M valuation). Remediation of initial storefront access points eliminates 85% of total reachability risk.",
  top_risks: [
    "Unauthenticated RCE vector on storefront container web-app-01",
    "Cross-tier pivoting through bastion jump host jump-01",
    "Crown jewel database access without multi-factor authorization",
  ],
  priority_actions: [
    "Apply container patch to storefront application",
    "Enforce FIDO2 key requirement on SSH jump host",
    "Segment database subnet behind dedicated VPC security group",
  ],
};

export const DEMO_NETCONFIG_ANALYSIS: NetconfigAnalysis = {
  available: true,
  findings: [
    {
      id: "nc-find-01",
      category: "NAT",
      title: "[SIMULATED] Inbound Port Forward to DMZ Web Application",
      severity: "medium",
      status: "real",
      source: "observed",
      evidence: "Port 443 forwarded from external WAN to 10.0.1.10",
      affected: ["10.0.1.10"],
      remediation_hint: "Ensure strict ingress rate limiting and WAF filtering.",
      finding_id: "finding-demo-002",
    },
    {
      id: "nc-find-02",
      category: "DMZ",
      title: "[SIMULATED] Bastion Host Direct Ingress Exposure",
      severity: "high",
      status: "real",
      source: "declared",
      evidence: "Administrative jump host port 22 exposed to corporate network",
      affected: ["10.0.2.50"],
      remediation_hint: "Restrict SSH ingress exclusively to authorized VPN gateway IP.",
      finding_id: "finding-demo-004",
    },
  ],
  recomputed_risk: {
    total_assets: 10,
    average_risk: 0.68,
    real_findings: 2,
    unknown_findings: 0,
    passed_checks: 46,
    top_path_risk: 0.94,
  },
  used_declared_config: false,
  generated_at: "2026-09-23T12:00:00Z",
};

export const DEMO_LIVE_THREATS: LiveThreat[] = [
  {
    id: "threat-sim-01",
    domain: "bad-actor-phish.net",
    band: "High Risk",
    score: 0.18,
    hit_count: 14,
    source_host: "10.0.1.11",
    reasons: ["Self-signed SSL certificate", "Newly registered domain (<7 days)", "Heuristic malware detection flag"],
    first_seen: "2026-09-23T11:45:00Z",
    last_seen: "2026-09-23T12:05:00Z",
  },
];

export const DEMO_NETWORK_THREATS: NetworkThreat[] = [
  {
    id: "net-threat-01",
    kind: "risky_service",
    severity: "medium",
    title: "[SIMULATED NETWORK THREAT] Outbound Connection to Untrusted Domain",
    detail: "Host web-app-01 (10.0.1.11) initiated outbound DNS probe towards bad-actor-phish.net.",
    device_ip: "10.0.1.11",
    device_mac: "52:54:00:A1:B2:C3",
    hostname: "web-app-01",
    evidence: ["Observed 5-tuple flow: 10.0.1.11:51240 -> 198.51.100.42:443 [TCP]"],
    recommendation: "Block domain at DNS resolver and inspect web-app-01 egress logs.",
    mitre: "Command and Control (T1071)",
    first_seen: "2026-09-23T11:50:00Z",
  },
];

export const DEMO_NETWORK_COVERAGE: NetworkCoverage[] = [
  { id: "cov-01", ssid: "Acme-Corp-Secure", subnet: "10.0.1.0/24", gateway_ip: "10.0.1.1", label: "DMZ Web Subnet", status: "inventoried", evidence: "Observed via passive network discovery", device_count: 3, last_seen: "2026-09-23T12:00:00Z" },
  { id: "cov-02", ssid: "Acme-Corp-Secure", subnet: "10.0.2.0/24", gateway_ip: "10.0.2.1", label: "Application Services Subnet", status: "inventoried", evidence: "Observed via passive network discovery", device_count: 3, last_seen: "2026-09-23T12:00:00Z" },
  { id: "cov-03", ssid: "Acme-Corp-Secure", subnet: "10.0.3.0/24", gateway_ip: "10.0.3.1", label: "Protected Data Subnet", status: "inventoried", evidence: "Observed via passive network discovery", device_count: 2, last_seen: "2026-09-23T12:00:00Z" },
  { id: "cov-04", ssid: "Acme-Corp-Secure", subnet: "10.0.4.0/24", gateway_ip: "10.0.4.1", label: "Corporate Fleet Subnet", status: "inventoried", evidence: "Observed via passive network discovery", device_count: 2, last_seen: "2026-09-23T12:00:00Z" },
];
