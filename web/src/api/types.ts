// Drishti v0.1 — API type contracts mirroring backend schemas | 11-Jul-2026
/** Typed API contracts — mirror the backend Pydantic schemas exactly (CLAUDE.md §5). */

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface Me {
  id: string;
  name: string | null;
  email: string;
  role: string;
  org_id: string;
  org_name: string;
  org_slug: string | null;
}

export interface RegisterOut extends TokenPair {
  user: { id: string; name: string | null; email: string; role: string };
  org: { id: string; name: string; slug: string };
}

export interface OrgInfo {
  id: string;
  name: string;
  slug: string;
  asset_count: number;
  open_findings: number;
  path_count: number;
  member_count: number;
}

export interface Member {
  id: string;
  name: string | null;
  email: string;
  role: string;
}

export interface AgentToken {
  agent_key: string;
  token: string;
  org_slug: string;
}

// ---- Graph (React Flow contract, BACKEND.md §4.3) ----
export interface GraphNodeData {
  label: string;
  asset_type: string;
  zone: string | null;
  criticality: string;
  risk_score: number;
  business_value: number;
  internet_facing: boolean;
  open_findings: number;
  is_crown_jewel: boolean;
  in_blast_radius: boolean | null;
  // live-device fields
  is_device?: boolean;
  is_gateway?: boolean;
  online?: boolean;
  mac?: string | null;
  vendor?: string | null;
  ip?: string | null;
 // active threat on this node
  threat?: boolean;
  threat_kind?: string | null;
  threat_severity?: string | null;
  threat_title?: string | null;
  mitre?: string | null;
}
export interface GraphNode {
  id: string;
  type: string;
  data: GraphNodeData;
  position: { x: number; y: number };
}
export interface GraphEdgeData {
  relation: string;
  weight: number;
  via_cve: string | null;
  on_top_path: boolean;
  /** highest-risk cached attack path this edge belongs to (edge click → path drawer) */
  path_id: string | null;
}
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  data: GraphEdgeData;
}
export interface GraphMeta {
  entry_nodes: string[];
  crown_jewels: string[];
  focus: string | null;
  blast_radius_ids: string[];
}
export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  meta: GraphMeta;
}

// ---- Assets / findings ----
export interface AssetSummary {
  id: string;
  hostname: string | null;
  ip: string;
  asset_type: string;
  zone: string | null;
  criticality: string;
  business_value: number;
  internet_facing: boolean;
  risk_score: number | null;
  blast_radius_count: number | null;
  open_findings: number;
}
export interface ServiceOut {
  id: string;
  port: number;
  protocol: string;
  name: string;
  version: string | null;
}
export interface Finding {
  id: string;
  status: string;
  cve_id: string | null;
  title: string;
  severity: string;
  cvss: number;
  exploitability: number;
  description: string | null;
  asset_id: string;
  asset_hostname: string | null;
  asset_ip: string;
  service_port: number | null;
  detected_at: string | null;
  source?: "network" | "endpoint";
  observed_product?: string | null;
  observed_version?: string | null;
  fixed_version?: string | null;
  in_kev?: boolean;
  finding_state?: string | null;
}

export interface AssetDetail extends AssetSummary {
  os: string | null;
  services: ServiceOut[];
  findings: Finding[];
  downstream_value: number;
}
export interface BlastRadius {
  asset_id: string;
  count: number;
  downstream_value: number;
  reachable_ids: string[];
}

// ---- Paths ----
export interface PathStep {
  step_index: number;
  asset_id: string;
  asset_hostname: string | null;
  asset_ip: string;
  asset_type: string;
  zone: string | null;
  via_cve: string | null;
  via_title: string | null;
  via_severity: string | null;
  via_cvss: number | null;
  edge_weight: number | null;
}
export interface PathSummary {
  id: string;
  entry_label: string;
  target_asset_id: string;
  target_hostname: string | null;
  hop_count: number;
  path_risk: number;
  likelihood: number;
  impact_usd: number;
  narrative: string | null;
}
export interface PathDetail extends PathSummary {
  steps: PathStep[];
  drivers: string[];
}

// ---- Dashboard ----
export interface ZoneSummary {
  name: string;
  kind: string;
  asset_count: number;
  worst_risk: number;
}
export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
}
export interface Dashboard {
  total_exposure_usd: number;
  open_findings: number;
  critical_assets: number;
  top_path_risk: number;
  top_paths: PathSummary[];
  zone_summary: ZoneSummary[];
  severity_breakdown: SeverityBreakdown;
}
export interface Stats {
  nodes: number;
  edges: number;
  paths: number;
  recompute_ms: number;
  top_path_risk: number;
  assets: number;
  open_findings: number;
  ai_calls: number;
  ai_mock_calls: number;
}

// ---- AI ----
export interface Remediation {
  id: string | null;
  refused: boolean;
  reason: string | null;
  kind: string;
  title: string;
  summary: string;
  script: string;
  steps: string[];
  estimated_risk_reduction: number | null;
  requires_restart: boolean;
  disclaimer: string;
  reviewed: boolean;
  model: string | null;
  context?: Record<string, unknown> | null;
}
export interface ImpactNarrative {
  refused: boolean;
  reason: string | null;
  impact_usd: number;
  headline: string;
  narrative: string;
  drivers: string[];
  highest_leverage_action: string;
}

// ---- Network Intelligence Report (mirrors server/app/schemas/report.py) ----
export interface AffectedHost {
  hostname: string | null;
  ip: string;
}
export interface CveRow {
  cve_id: string | null;
  title: string;
  cvss: number;
  severity: string;
  affected_count: number;
  affected: AffectedHost[];
}
export interface RiskBand {
  band: string;
  count: number;
  pct: number;
}
export interface Distribution {
  total_assets: number;
  average_risk: number;
  bands: RiskBand[];
}
export interface AnomalousNode {
  hostname: string | null;
  ip: string;
  anomaly_score: number;
  risk_score: number;
  reason: string;
}
export interface SecuritySegment {
  segment: number;
  risk_pct: number;
  label: string;
  members: string[];
}
export interface MlAnalysis {
  available: boolean;
  algorithm_note: string;
  anomalies: AnomalousNode[];
  segments: SecuritySegment[];
}
export interface NetworkSummary {
  refused: boolean;
  reason: string | null;
  headline: string;
  narrative: string;
  top_risks: string[];
  priority_actions: string[];
}
export interface HardeningAction {
  kind: string; // CLOSE_PORT | PATCH | VLAN_SEGMENT | ISOLATE_CONNECTION
  label: string;
  risk_reduction_pct: number;
}
export interface NodeHardening {
  hostname: string | null;
  ip: string;
  current_score: number;
  projected_score: number;
  reduction_pct: number;
  band_before: string;
  band_after: string;
  actions: HardeningAction[];
}

// ---- Network Configuration analysis (mirrors server/app/schemas/netconfig.py) ----
export interface PortForward {
  external_port: number;
  internal_ip: string;
  internal_port: number;
  proto: string;
}
export interface NetconfigInput {
  port_forwards: PortForward[];
  dhcp_servers: string[];
  dhcp_snooping: boolean | null;
  dmz_hosts: string[];
  gateway_ip: string | null;
}
export interface NetconfigFinding {
  id: string;
  category: string; // NAT | DMZ | DHCP
  title: string;
  severity: string; // critical | high | medium | low | none
  status: string; // real | unknown | passed
  source: string; // observed | declared
  evidence: string;
  affected: string[];
  remediation_hint: string;
  finding_id: string | null; // AssetVulnerability id → /app/remediate/:id
}
export interface NetconfigRiskSummary {
  total_assets: number;
  average_risk: number;
  real_findings: number;
  unknown_findings: number;
  passed_checks: number;
  top_path_risk: number | null;
}
export interface NetconfigAnalysis {
  available: boolean;
  findings: NetconfigFinding[];
  recomputed_risk: NetconfigRiskSummary;
  used_declared_config: boolean;
  generated_at: string | null;
}

// ---- Live network watch (mirrors server/app/schemas/live.py) ----
export interface LiveThreat {
  id: string;
  domain: string;
  band: string; // Trusted | Caution | High Risk
  score: number;
  hit_count: number;
  source_host: string | null;
  reasons: string[];
  verdict_json?: Record<string, any>;
  first_seen: string;
  last_seen: string;
}
export interface NetworkThreat {
  id: string;
  kind: "arp_spoof" | "rogue_device" | "risky_service" | "malicious_domain";
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  detail: string;
  device_ip: string | null;
  device_mac: string | null;
  hostname: string | null;
  evidence: string[];
  recommendation: string;
  mitre: string | null;
  first_seen: string | null;
}
export interface BlockCommand {
  platform: string;
  command: string;
}
export interface BlockFix {
  refused: boolean;
  reason: string | null;
  domain: string;
  band: string;
  summary: string;
  why_risky: string[];
  commands: BlockCommand[];
  disclaimer: string;
}

export interface ActivityItem {
  name: string;
  evidence_type?: string;
  source?: string;
  observed_at?: string | null;
  details?: string | null;
  browser?: string | null;
  url?: string | null;
  domain?: string | null;
  title?: string | null;
  category?: "USER_APPLICATION" | "BACKGROUND_PROCESS" | "SYSTEM_PROCESS" | string | null;
}

export interface NetworkDevice {
  id: string;
  ip: string;
  mac: string | null; // null for off-link (L3-discovered) devices — no ARP MAC
  subnet: string | null; // observed CIDR, e.g. "10.0.5.0/24"
  subnet_inferred: boolean; // true = /24 guessed for a legacy row, not observed
  discovery: string; // "arp" | "l3"
  label: string | null;
  hostname: string | null;
  vendor: string | null;
  is_self: boolean;
  is_gateway: boolean;
  online: boolean;
  first_seen: string;
  last_seen: string;
  scanned: boolean;
  vuln_count: number | null; // null = not scanned yet (never 0)
  worst_severity: string | null; // critical | high | medium | low
  last_scanned_at: string | null;
  active_domains?: string[];
  active_apps?: string[];
  recent_destinations?: ActivityItem[];
  endpoint_processes?: ActivityItem[];
  active_browser_tabs?: ActivityItem[];
  current_session_started_at?: string | null;
  current_session_duration_seconds?: number;
  total_observed_duration_seconds?: number;
  session_count?: number;
  observation_count?: number;
  observation_source?: string | null;
  presence_state?: "new" | "continuous" | "offline";
  open_ports?: number[];
  services?: DeepScanService[];
  cves?: DeepScanCve[];
  os_info?: string | null;
  device_type?: string | null;
  installed_software?: ActivityItem[];
  process_connections?: ActivityItem[];
  installed_browsers?: string[];
  vpn_status?: string | null;
  vpn_adapters?: string[];
  security_findings?: string[];
  risk_score?: number | null;
  capability_state?: "NETWORK ONLY" | "AGENT CONNECTED" | "BROWSER EXTENSION CONNECTED" | "FULL ENDPOINT TELEMETRY" | string;
  listening_ports?: ActivityItem[];
  browser_processes?: ActivityItem[];
  endpoint_services?: ActivityItem[];
  is_telemetry_stale?: boolean;
  // Phase 04 — Unified Device Security Profile
  ai_detection?: CurrentBehaviour | null;
  ai_forecast?: ForecastResult | null;
  ai_tracking_active?: boolean;
  ai_tracking_session_id?: string | null;
  device_security_score?: number | null;
  endpoint_vuln_findings?: EndpointFindingOut[];
  aiDetection?: CurrentBehaviour | null;
  aiForecast?: ForecastResult | null;
  aiTrackingActive?: boolean;
  deviceSecurityScore?: number | null;
  endpointVulnFindings?: EndpointFindingOut[];
  // Endpoint Agent fields (Phase 01 / End-to-End Grid Integration)
  paired_endpoint_agent_id?: string | null;
  paired_endpoint_device_id?: string | null;
  paired_endpoint_status?: "ONLINE" | "STALE" | "OFFLINE" | string | null;
  paired_endpoint_hostname?: string | null;
  paired_endpoint_os?: string | null;
  paired_endpoint_os_version?: string | null;
  paired_endpoint_agent_version?: string | null;
  paired_endpoint_last_heartbeat?: string | null;
  paired_endpoint_paired_at?: string | null;
}

export type EndpointFinding = EndpointFindingOut;
export interface EndpointFindingOut {
  finding_id: string;
  finding_state: "OPEN" | "EXPOSED" | "POTENTIAL_MATCH" | "VULNERABLE" | "KNOWN_EXPLOITED" | "NO_CONFIRMED_VULNERABILITY" | string;
  evidence_source: "endpoint_software" | "network_service" | string;
  observed_product: string;
  observed_version?: string | null;
  cve_id?: string | null;
  title?: string | null;
  summary?: string | null;
  cvss: number;
  severity: string;
  in_kev: boolean;
  kev_date_added?: string | null;
  ghsa_ids: string[];
  affected_range_text?: string | null;
  fixed_version_text?: string | null;
  intel_sources: string[];
  source_freshness: string;
  source_status_reason?: string | null;
}

// One network known to exist (whether or not it's been inventoried). The gap
// between seen and inventoried is the finding. Mirrors CoverageOut on the server.
export interface NetworkCoverage {
  id: string;
  ssid: string | null;
  subnet: string | null;
  gateway_ip: string | null;
  label: string | null;
  // inventoried | reachable_not_scanned | seen_not_joined | unreachable
  status: string;
  evidence: string;
  device_count: number;
  last_seen: string;
}
export interface AutoScanConfig {
  enabled: boolean;
  interval_seconds: number;
  scan_subnet: boolean;
  last_run_at: string | null;
  running: boolean;
  eligible_count: number;
  scanned_count: number;
}

// ---- Deep Scan (mirrors server/app/schemas/live.py) ----
export interface DeepScanService {
  port: number;
  protocol: string;
  service_name: string;
  product: string | null;
  version: string | null;
}
export interface DeepScanCve {
  id: string;
  cvss: number;
  severity: string; // low | medium | high | critical
  summary: string;
  affected_service: string;
  finding_id: string | null; // routes into /app/remediate/:findingId
  source?: string; // "endpoint_software" | "cve_database"
  evidence_type?: string;
  intel_sources?: string[];
  in_kev?: boolean;
  ghsa_ids?: string[];
  finding_state?: "OPEN" | "EXPOSED" | "POTENTIAL_MATCH" | "VULNERABLE" | "KNOWN_EXPLOITED" | "NO_CONFIRMED_VULNERABILITY" | string;
  source_freshness?: "live" | "cached" | "stale" | "source_unavailable" | string;
  source_status_reason?: string | null;
  affected_range_text?: string | null;
  fixed_version_text?: string | null;
}

export interface CorrelatedFindingOut {
  finding_id: string;
  device_id: string;
  org_id: string;
  finding_state: "OPEN" | "EXPOSED" | "POTENTIAL_MATCH" | "VULNERABLE" | "KNOWN_EXPLOITED" | "NO_CONFIRMED_VULNERABILITY" | string;
  observed_product: string;
  evidence_source: "endpoint_software" | "network_service" | string;
  evidence_type: string;
  observed_vendor?: string | null;
  observed_version?: string | null;
  cve_id?: string | null;
  title?: string | null;
  summary?: string | null;
  cvss: number;
  severity: string;
  in_kev: boolean;
  kev_date_added?: string | null;
  ghsa_ids: string[];
  affected_range_text?: string | null;
  fixed_version_text?: string | null;
  intel_sources: string[];
  source_freshness: string;
  source_status_reason?: string | null;
  source_details: Record<string, any>;
  observed_at?: string | null;
}

export interface SourceStatusOut {
  source_name: string;
  available: boolean;
  last_sync?: string | null;
  error_reason?: string | null;
  is_stale: boolean;
}

export interface EndpointVulnerabilitiesResponse {
  device_id: string;
  findings: CorrelatedFindingOut[];
  total_findings: number;
  vulnerable_count: number;
  known_exploited_count: number;
  potential_match_count: number;
  source_statuses: SourceStatusOut[];
}

export interface DeepScanResult {
  available: boolean;
  target: string;
  unavailable_reason: string | null;
  os: string | null;
  ports: number[];
  services: DeepScanService[];
  cves: DeepScanCve[];
  cve_lookup_unavailable: boolean;
  cve_lookup_reason: string | null;
  asset_id: string | null;
  risk_score: number | null;
  top_path_risk: number | null;
  top_path_formed: boolean;
  scanned_at: string | null;
}
export interface DeepScanRangeResult {
  available: boolean;
  cidr: string;
  unavailable_reason: string | null;
  hosts_discovered: number;
  hosts_scanned: number;
  host_cap: number;
  capped: boolean;
  hosts: DeepScanResult[];
  scanned_at: string | null;
}

// ---- URL Trust Analyzer (mirrors server/app/schemas/urltrust.py) ----
export type SignalStatus =
  | "pass"
  | "warn"
  | "fail"
  | "unknown"
  | "not_configured"
  | "unreachable";
export type TrustBand = "Trusted" | "Caution" | "High Risk";

export interface UrlSignal {
  key: string;
  label: string;
  status: SignalStatus;
  detail: string;
  weight: number;
  counted: boolean;
}
export interface UrlTls {
  valid: boolean | null;
  issuer: string | null;
  expires: string | null;
}
export interface UrlWebsite {
  scheme: string;
  host: string;
  https: boolean;
  tls: UrlTls;
  domain_age_days: number | null;
  registrar: string | null;
  http_status: number | null;
  redirect_chain: string[];
  redirects_offsite: boolean | null;
}
export interface SafeBrowsingResult {
  configured: boolean;
  verdict: "clean" | "flagged" | null;
  threats: string[] | null;
  error: string | null;
}
export interface VirusTotalResult {
  configured: boolean;
  malicious: number | null;
  suspicious: number | null;
  harmless: number | null;
  reputation: number | null;
  error: string | null;
}
export interface UrlProviders {
  safe_browsing: SafeBrowsingResult;
  virustotal: VirusTotalResult;
}
export interface UrlAnalysisResult {
  url: string;
  final_url: string | null;
  score: number;
  band: TrustBand;
  evaluated_count: number;
  signals: UrlSignal[];
  website: UrlWebsite;
  providers: UrlProviders;
  ai_summary: string | null;
  generated_at: string;
  disclaimer: string;
}
export interface UrlHistoryItem {
  id: string;
  url: string;
  score: number;
  band: TrustBand;
  created_at: string;
}

// ---- Live Network Traffic Tracking & Phase 03 Forecasting ----
export interface TrackingSession {
  tracking_session_id: string;
  device_id: string;
  target_ip: string;
  target_mac?: string | null;
  target_hostname?: string | null;
  status: "STARTING" | "LIVE" | "STOPPED" | "ERROR" | "UNAVAILABLE";
  capture_source: string;
  status_message?: string | null;
  started_at: string;
  ended_at?: string | null;
  last_event_at?: string | null;
  packet_count: number;
  flow_count: number;
  byte_count: number;
}

export interface LiveTrafficMetrics {
  packet_count: number;
  flow_count: number;
  byte_count: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  active_connections: number;
}

export interface ProtocolBreakdown {
  tcp: number;
  udp: number;
  icmp: number;
  dns: number;
  http_https: number;
  other: number;
}

export interface TopDestinationItem {
  destination_ip: string;
  destination_port: number;
  protocol: string;
  connection_count: number;
  last_seen?: string | null;
}

export interface CurrentBehaviour {
  verdict: "NORMAL" | "SUSPICIOUS" | "ANOMALOUS" | "INSUFFICIENT_DATA";
  confidence: number;
  signals: string[];
  attack_category?: string | null;
}

export interface TrafficEvidenceItem {
  evidence_type: string;
  source: string;
  observed_at: string;
  device_id: string;
  confidence: string;
  details: Record<string, any>;
}

export interface ForecastStep {
  step: string; // T+1 | T+2 | T+3
  state:
    | "NORMAL_CONTINUATION"
    | "SUSPICIOUS_CONTINUATION"
    | "LIKELY_ESCALATION"
    | "POTENTIAL_LATERAL_MOVEMENT"
    | "POTENTIAL_RECONNAISSANCE_CONTINUATION"
    | "INSUFFICIENT_HISTORY"
    | string;
  probability: number;
  status_label: "PREDICTED" | string;
  contributing_signals: string[];
}

export interface MitreMapping {
  tactic: string;
  tactic_id: string;
  technique: string;
  technique_id: string;
  capec_id?: string | null;
  capec_name?: string | null;
  confidence: number;
}

export interface Explainability {
  top_signals: string[];
  state_transition: string;
  graph_dynamics: string[];
  feature_deltas: Record<string, number>;
}

export interface ForecastResult {
  is_available: boolean;
  status: string;
  horizon_steps: ForecastStep[];
  mitre_attack?: MitreMapping | null;
  explainability?: Explainability | null;
  composite_risk_score: number;
  composite_risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  risk_formula: string;
  model_used: string;
}

export interface TrackingResults {
  session: TrackingSession;
  metrics: LiveTrafficMetrics;
  protocols: ProtocolBreakdown;
  top_destinations: TopDestinationItem[];
  current_behaviour: CurrentBehaviour;
  evidence: TrafficEvidenceItem[];
  features?: Record<string, number> | null;
  model_status?: Record<string, string> | null;
  network_visibility?: "VISIBLE" | "LIMITED" | "UNAVAILABLE" | string | null;
  visibility_reason?: string | null;
  window_count?: number | null;
  graph_summary?: {
    nodes: Array<{ id: string; is_target?: boolean; packet_count: number; byte_count: number }>;
    edges: Array<{ source: string; target: string; packet_count: number; byte_count: number; protocol: number }>;
  } | null;
  forecast?: ForecastResult | null;
}

// ---- Endpoint Agent Foundation (Phase 01) ----
export interface EndpointAgent {
  id: string;
  organization_id: string;
  agent_id: string;
  device_id: string;
  hostname: string;
  os: string;
  os_version: string;
  mac: string | null;
  current_ip: string | null;
  agent_version: string;
  status: "ONLINE" | "STALE" | "OFFLINE" | string;
  paired_at: string | null;
  registered_at: string | null;
  last_heartbeat: string | null;
  created_at: string;
  updated_at: string;
}

export interface EndpointPairingSubmitResult {
  success: boolean;
  message: string;
  agent: EndpointAgent;
}

// ---- Endpoint Telemetry (Phase 02) ----
export interface ProcessTelemetryItem {
  pid: number;
  name: string;
  category?: string;
  cpu_percent?: number | null;
  memory_mb?: number | null;
  exe_path?: string | null;
  username?: string | null;
  started_at?: string | null;
  observed_at?: string | null;
}

export interface SoftwareTelemetryItem {
  name: string;
  version?: string | null;
  vendor?: string | null;
  install_date?: string | null;
  install_location?: string | null;
  source?: string;
  observed_at?: string | null;
}

export interface ServiceTelemetryItem {
  name: string;
  display_name: string;
  status: string;
  start_type?: string;
  pid?: number | null;
  observed_at?: string | null;
}

export interface ListeningPortTelemetryItem {
  port: number;
  protocol: string;
  bind_address: string;
  pid?: number | null;
  process_name?: string | null;
  observed_at?: string | null;
}

export interface SocketConnectionTelemetryItem {
  pid: number;
  process_name: string;
  protocol: string;
  local_address: string;
  local_port: number;
  remote_address: string;
  remote_port: number;
  state: string;
  observed_at?: string | null;
}

export interface BrowserProcessTelemetryItem {
  browser_name: string;
  pid: number;
  exe_path?: string | null;
  observed_at?: string | null;
}

export interface EndpointTelemetryOut {
  device_id: string;
  agent_id: string;
  hostname?: string | null;
  os_name?: string | null;
  os_version?: string | null;
  endpoint_processes: ProcessTelemetryItem[];
  active_apps: string[];
  installed_software: SoftwareTelemetryItem[];
  services: ServiceTelemetryItem[];
  listening_ports: ListeningPortTelemetryItem[];
  process_connections: SocketConnectionTelemetryItem[];
  installed_browsers: string[];
  browser_processes: BrowserProcessTelemetryItem[];
  os_info?: string | null;
  last_updated?: string | null;
  is_stale: boolean;
  is_software_stale: boolean;
  source: string;
  device_model?: string | null;
  manufacturer?: string | null;
  sdk_version?: number | null;
  cpu_info?: {
    cores?: number;
    usage_percent?: number | null;
    per_core_supported?: boolean;
    per_core_usage?: number[];
    architecture?: string;
  } | null;
  memory_info?: {
    total_bytes?: number;
    available_bytes?: number;
    used_bytes?: number;
    low_memory?: boolean;
  } | null;
  storage_info?: {
    total_bytes?: number;
    available_bytes?: number;
    used_bytes?: number;
  } | null;
  battery_info?: {
    percentage?: number;
    charging?: boolean;
    health?: string;
    temperature_c?: number;
  } | null;
  network_info?: {
    connection_type?: string;
    local_ip?: string;
    interface?: string;
    link_speed_kbps?: number;
  } | null;
  security_posture?: {
    screen_lock?: boolean;
    encryption?: string;
    developer_options?: boolean;
    usb_debugging?: boolean;
    verified_boot?: string;
    security_patch?: string;
    biometric_capability?: string;
    root_detected?: boolean;
  } | null;
  applications?: {
    package_name: string;
    label: string;
    version_name?: string | null;
    version_code?: number | null;
    classification?: "USER_APP" | "SYSTEM_APP" | string;
    is_enabled?: boolean;
  }[];
}

