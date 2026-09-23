// Drishti v0.1 — typed API client for backend communication | 11-Jul-2026
/**
 * Typed API client. Centralizes auth: attaches the access token, refreshes once
 * on 401, then logs out (apiClient.test.ts). Normalizes the backend error
 * envelope into a typed ApiError.
 *
 * Token storage: the short-lived ACCESS token lives only in this in-memory store
 * (never persisted). The longer-lived REFRESH token is persisted to localStorage
 * so a page refresh restores the session — on load we mint a fresh access token
 * from it (restoreSession). A proper httpOnly cookie would be stricter, but this
 * keeps the access token (the one attached to every request) out of storage.
 */
import type {
  AgentToken,
  AssetDetail,
  AssetSummary,
  BlastRadius,
  Dashboard,
  Finding,
  GraphResponse,
  ImpactNarrative,
  Me,
  Member,
  OrgInfo,
  AutoScanConfig,
  BlockFix,
  CveRow,
  DeepScanRangeResult,
  DeepScanResult,
  Distribution,
  EndpointAgent,
  EndpointPairingSubmitResult,
  EndpointTelemetryOut,
  EndpointVulnerabilitiesResponse,
  LiveThreat,
  MlAnalysis,
  NetconfigAnalysis,
  NetconfigInput,
  NetworkCoverage,
  NetworkDevice,
  NetworkSummary,
  NetworkThreat,
  NodeHardening,
  PathDetail,
  PathSummary,
  RegisterOut,
  Remediation,
  Stats,
  TokenPair,
  TrackingResults,
  TrackingSession,
  UrlAnalysisResult,
  UrlHistoryItem,
} from "./types";

import {
  DEMO_ASSETS,
  DEMO_DASHBOARD,
  DEMO_ENDPOINT_AGENTS,
  DEMO_FINDINGS,
  DEMO_GRAPH,
  DEMO_LIVE_THREATS,
  DEMO_MEMBERS,
  DEMO_NETCONFIG_ANALYSIS,
  DEMO_NETWORK_COVERAGE,
  DEMO_NETWORK_DEVICES,
  DEMO_NETWORK_THREATS,
  DEMO_ORG,
  DEMO_PATHS,
  DEMO_REPORT_CVES,
  DEMO_REPORT_DISTRIBUTION,
  DEMO_REPORT_HARDENING,
  DEMO_REPORT_ML,
  DEMO_REPORT_SUMMARY,
  DEMO_STATS,
  DEMO_TELEGRAM_STATUS,
  DEMO_TELEGRAM_TEST,
  DEMO_TOKENS,
  DEMO_URL_HISTORY,
  DEMO_USER,
  getDemoAssetDetail,
  getDemoEndpointTelemetry,
  getDemoEndpointVulnerabilities,
  getDemoImpact,
  getDemoPathDetail,
  getDemoRemediation,
  getDemoUrlAnalysis,
} from "../demo/demoData";

export function isDemoMode(): boolean {
  return import.meta.env.VITE_DEMO_MODE === "true";
}

export class ApiError extends Error {
  code: string;
  status: number;
  detail: unknown;
  constructor(status: number, code: string, message: string, detail?: unknown) {
    super(message);
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}

interface TokenStore {
  access: string | null;
  refresh: string | null;
}

const REFRESH_KEY = "drishti_refresh";

function readStoredRefresh(): string | null {
  try {
    return localStorage.getItem(REFRESH_KEY);
  } catch {
    return null; // storage disabled (private mode / SSR)
  }
}

// access is always memory-only; refresh is seeded from localStorage so a page
// reload can restore the session.
const tokens: TokenStore = { access: null, refresh: readStoredRefresh() };
let onLogout: (() => void) | null = null;

export function setTokens(pair: TokenPair | null) {
  tokens.access = pair?.access_token ?? null;
  tokens.refresh = pair?.refresh_token ?? null;
  try {
    if (isDemoMode()) {
      if (pair) {
        localStorage.setItem("drishti_demo_session", "true");
      } else {
        localStorage.removeItem("drishti_demo_session");
      }
      return;
    }
    if (tokens.refresh) localStorage.setItem(REFRESH_KEY, tokens.refresh);
    else localStorage.removeItem(REFRESH_KEY);
  } catch {
    /* storage unavailable — session just won't survive a reload */
  }
}
export function hasSession(): boolean {
  if (isDemoMode()) {
    try {
      return localStorage.getItem("drishti_demo_session") === "true";
    } catch {
      return false;
    }
  }
  return tokens.access != null || tokens.refresh != null;
}

/**
 * On a fresh page load the access token is gone but a persisted refresh token
 * may remain. Exchange it for a new access token so the session survives a
 * reload. Returns false when there's nothing to restore.
 */
export async function restoreSession(): Promise<boolean> {
  if (isDemoMode()) {
    try {
      return localStorage.getItem("drishti_demo_session") === "true";
    } catch {
      return false;
    }
  }
  if (tokens.access) return true;
  if (!tokens.refresh) return false;
  return refreshOnce();
}
export function registerLogout(fn: () => void) {
  onLogout = fn;
}

async function parseError(res: Response): Promise<ApiError> {
  let code = "internal_error";
  let message = res.statusText || "Request failed";
  let detail: unknown = null;
  try {
    const body = await res.json();
    if (body?.error) {
      code = body.error.code ?? code;
      message = body.error.message ?? message;
      detail = body.error.detail ?? null;
    }
  } catch {
    /* non-JSON error body */
  }
  return new ApiError(res.status, code, message, detail);
}

// Same-origin by default (a reverse-proxy/rewrite serves /api). Set VITE_API_BASE
// to the backend's absolute URL for a split deploy (frontend + backend on
// different hosts); the backend must then allow that origin via CORS_ORIGINS.
const API_BASE = (import.meta.env.VITE_API_BASE ?? "").replace(/\/$/, "");

async function rawRequest(path: string, init: RequestInit): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set("Content-Type", "application/json");
  if (tokens.access) headers.set("Authorization", `Bearer ${tokens.access}`);
  return fetch(API_BASE + path, { ...init, headers });
}

async function tryRefresh(): Promise<boolean> {
  if (!tokens.refresh) return false;
  try {
    const res = await fetch(API_BASE + "/api/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: tokens.refresh }),
    });
    if (!res.ok) return false;
    setTokens(await res.json());
    return true;
  } catch {
    return false;
  }
}

let refreshInFlight: Promise<boolean> | null = null;

function refreshOnce(): Promise<boolean> {
  // coalesce concurrent 401s into a single refresh attempt (ERROR_HANDLING.md §3.2)
  if (!refreshInFlight) {
    refreshInFlight = tryRefresh().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let res = await rawRequest(path, init);
  if (res.status === 401 && tokens.refresh) {
    // refresh once (shared across concurrent callers), then retry once
    if (await refreshOnce()) {
      res = await rawRequest(path, init);
    }
    if (res.status === 401) {
      setTokens(null);
      onLogout?.();
      throw await parseError(res);
    }
  }
  if (!res.ok) throw await parseError(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

const get = <T>(path: string) => request<T>(path);
const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });
const patch = <T>(path: string, body: unknown) =>
  request<T>(path, { method: "PATCH", body: JSON.stringify(body) });
const del = <T>(path: string) => request<T>(path, { method: "DELETE" });

export const api = {
  login: (email: string, password: string) => {
    if (isDemoMode()) {
      if (email === "analyst@acme-retail.dev" && password === "drishti-demo") {
        return Promise.resolve(DEMO_TOKENS);
      }
      return Promise.reject(new ApiError(401, "invalid_credentials", "Invalid demo credentials."));
    }
    return request<TokenPair>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  },
  register: (body: { name: string; email: string; password: string; org_name: string }) => {
    if (isDemoMode()) {
      return Promise.resolve({
        ...DEMO_TOKENS,
        user: { id: "user-demo-analyst-01", name: body.name, email: body.email, role: "analyst" },
        org: { id: "org-acme-retail-01", name: body.org_name, slug: "acme-retail" },
      });
    }
    return request<RegisterOut>("/api/auth/register", { method: "POST", body: JSON.stringify(body) });
  },
  me: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_USER);
    return get<Me>("/api/auth/me");
  },
  patchMe: (body: { name?: string; current_password?: string; new_password?: string }) => {
    if (isDemoMode()) return Promise.resolve({ ...DEMO_USER, name: body.name ?? DEMO_USER.name });
    return patch<Me>("/api/auth/me", body);
  },
  org: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_ORG);
    return get<OrgInfo>("/api/org");
  },
  orgMembers: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_MEMBERS);
    return get<Member[]>("/api/org/members");
  },
  loadSample: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_ORG);
    return post<OrgInfo>("/api/org/load-sample");
  },
  resetOrg: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_ORG);
    return post<OrgInfo>("/api/org/reset");
  },
  agentToken: () => {
    if (isDemoMode()) return Promise.resolve({ agent_key: "agent-demo", token: "agent-demo-token", org_slug: "acme-retail" });
    return post<AgentToken>("/api/org/agent-token");
  },
  dashboard: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_DASHBOARD);
    return get<Dashboard>("/api/dashboard");
  },
  stats: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_STATS);
    return get<Stats>("/api/stats");
  },
  graph: (focus?: string | null) => {
    if (isDemoMode()) return Promise.resolve(DEMO_GRAPH);
    return get<GraphResponse>(focus ? `/api/graph?focus=${encodeURIComponent(focus)}` : "/api/graph");
  },
  paths: (k = 25) => {
    if (isDemoMode()) return Promise.resolve(DEMO_PATHS.slice(0, k));
    return get<PathSummary[]>(`/api/paths?k=${k}`);
  },
  path: (id: string) => {
    if (isDemoMode()) return Promise.resolve(getDemoPathDetail(id));
    return get<PathDetail>(`/api/paths/${id}`);
  },
  blastRadius: (assetId: string) => {
    if (isDemoMode()) {
      return Promise.resolve({
        asset_id: assetId,
        count: 4,
        downstream_value: 3500000,
        reachable_ids: ["asset-db-prod-01"],
      });
    }
    return get<BlastRadius>(`/api/assets/${assetId}/blast-radius`);
  },
  assets: (query = "") => {
    if (isDemoMode()) return Promise.resolve(DEMO_ASSETS);
    return get<AssetSummary[]>(`/api/assets${query}`);
  },
  asset: (id: string) => {
    if (isDemoMode()) return Promise.resolve(getDemoAssetDetail(id));
    return get<AssetDetail>(`/api/assets/${id}`);
  },
  findings: (query = "") => {
    if (isDemoMode()) return Promise.resolve(DEMO_FINDINGS);
    return get<Finding[]>(`/api/findings${query}`);
  },
  getFinding: (id: string) => {
    if (isDemoMode()) return Promise.resolve(DEMO_FINDINGS.find((f) => f.id === id) || DEMO_FINDINGS[0]);
    return get<Finding>(`/api/findings/${id}`);
  },
  patchFinding: (id: string, status: string) => {
    if (isDemoMode()) {
      const found = DEMO_FINDINGS.find((f) => f.id === id) || DEMO_FINDINGS[0];
      return Promise.resolve({ ...found, status });
    }
    return patch<Finding>(`/api/findings/${id}`, { status });
  },
  remediate: (finding_id: string, preferred_kind: string, regenerate = false) => {
    if (isDemoMode()) return Promise.resolve(getDemoRemediation(finding_id, preferred_kind));
    return post<Remediation>("/api/ai/remediate", { finding_id, preferred_kind, regenerate });
  },
  impact: (path_id: string) => {
    if (isDemoMode()) return Promise.resolve(getDemoImpact(path_id));
    return post<ImpactNarrative>("/api/ai/impact", { path_id });
  },
  recompute: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_STATS);
    return post<Stats>("/api/recompute");
  },
  analyzeUrl: (url: string) => {
    if (isDemoMode()) return Promise.resolve(getDemoUrlAnalysis(url));
    return post<UrlAnalysisResult>("/api/url-analyzer/analyze", { url });
  },
  urlHistory: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_URL_HISTORY);
    return get<UrlHistoryItem[]>("/api/url-analyzer/history");
  },
  reportCves: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_REPORT_CVES);
    return get<CveRow[]>("/api/report/cves");
  },
  reportDistribution: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_REPORT_DISTRIBUTION);
    return get<Distribution>("/api/report/distribution");
  },
  reportMl: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_REPORT_ML);
    return get<MlAnalysis>("/api/report/ml");
  },
  reportHardening: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_REPORT_HARDENING);
    return get<NodeHardening[]>("/api/report/hardening");
  },
  reportSummary: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_REPORT_SUMMARY);
    return post<NetworkSummary>("/api/report/summary");
  },
  netconfigAnalyze: (consent: boolean, config?: NetconfigInput) => {
    if (isDemoMode()) return Promise.resolve(DEMO_NETCONFIG_ANALYSIS);
    return post<NetconfigAnalysis>("/api/netconfig/analyze", { consent, config });
  },
  netconfigLast: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_NETCONFIG_ANALYSIS);
    return get<NetconfigAnalysis>("/api/netconfig/last");
  },
  liveThreats: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_LIVE_THREATS);
    return get<LiveThreat[]>("/api/live/threats");
  },
  liveBlock: (id: string) => {
    if (isDemoMode()) {
      return Promise.resolve({
        refused: false,
        reason: null,
        domain: "bad-actor-phish.net",
        band: "High Risk",
        summary: "[SIMULATED BLOCK] Egress rule staged for DNS boundary isolation.",
        why_risky: ["Heuristic detection", "Newly registered domain"],
        commands: [{ platform: "iptables", command: "iptables -A OUTPUT -d bad-actor-phish.net -j DROP" }],
        disclaimer: "SIMULATED COMMAND: Not executed.",
      });
    }
    return post<BlockFix>(`/api/live/block/${id}`);
  },
  liveClear: () => {
    if (isDemoMode()) return Promise.resolve({ cleared: 1 });
    return del<{ cleared: number }>("/api/live/threats");
  },
  resolveLiveThreat: (id: string) => {
    if (isDemoMode()) return Promise.resolve({ resolved: true, threat_id: id });
    return post<{ resolved: boolean; threat_id: string }>(`/api/live/threats/${id}/resolve`);
  },
  liveCheck: (domain: string) => {
    if (isDemoMode()) {
      return Promise.resolve({ id: "sim-check", domain, band: "Trusted", score: 0.95, is_threat: false });
    }
    return post<{ id: string; domain: string; band: string; score: number; is_threat: boolean }>(
      "/api/live/check",
      { domain },
    );
  },
  liveDevices: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_NETWORK_DEVICES);
    return get<NetworkDevice[]>("/api/live/devices");
  },
  liveCoverage: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_NETWORK_COVERAGE);
    return get<NetworkCoverage[]>("/api/live/coverage");
  },
  liveClearDevices: () => {
    if (isDemoMode()) return Promise.resolve({ cleared: 0 });
    return del<{ cleared: number }>("/api/live/devices");
  },
  networkThreats: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_NETWORK_THREATS);
    return get<NetworkThreat[]>("/api/live/network-threats");
  },
  demoAttack: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_NETWORK_THREATS);
    return post<NetworkThreat[]>("/api/live/demo-attack");
  },
  clearDemoAttack: () => {
    if (isDemoMode()) return Promise.resolve({ cleared: 1 });
    return del<{ cleared: number }>("/api/live/demo-attack");
  },
  autoscanGet: (): Promise<AutoScanConfig> => {
    if (isDemoMode()) {
      return Promise.resolve({
        enabled: false,
        interval_seconds: 60,
        scan_subnet: false,
        last_run_at: "2026-09-23T12:00:00Z",
        running: false,
        eligible_count: 10,
        scanned_count: 10,
      });
    }
    return get<AutoScanConfig>("/api/live/autoscan");
  },
  autoscanSet: (body: Partial<Pick<AutoScanConfig, "enabled" | "interval_seconds" | "scan_subnet">>): Promise<AutoScanConfig> => {
    if (isDemoMode()) {
      return Promise.resolve({
        enabled: body.enabled ?? false,
        interval_seconds: body.interval_seconds ?? 60,
        scan_subnet: body.scan_subnet ?? false,
        last_run_at: "2026-09-23T12:00:00Z",
        running: false,
        eligible_count: 10,
        scanned_count: 10,
      });
    }
    return request<AutoScanConfig>("/api/live/autoscan", { method: "PUT", body: JSON.stringify(body) });
  },
  deepScan: (ip: string, consent: boolean): Promise<DeepScanResult> => {
    if (isDemoMode()) {
      return Promise.resolve({
        available: true,
        target: ip,
        unavailable_reason: null,
        os: "Ubuntu 22.04 LTS (Simulated)",
        ports: [22, 80, 443],
        services: [
          { port: 22, protocol: "tcp", service_name: "ssh", product: "OpenSSH", version: "8.9p1" },
          { port: 443, protocol: "tcp", service_name: "https", product: "nginx", version: "1.18.0" },
        ],
        cves: [],
        cve_lookup_unavailable: false,
        cve_lookup_reason: null,
        asset_id: "asset-web-app-01",
        risk_score: 85,
        top_path_risk: 0.94,
        top_path_formed: true,
        scanned_at: "2026-09-23T12:00:00Z",
      });
    }
    return post<DeepScanResult>("/api/live/deep-scan", { ip, consent });
  },
  deepScanRange: (cidr: string, consent: boolean): Promise<DeepScanRangeResult> => {
    if (isDemoMode()) {
      return Promise.resolve({
        available: true,
        cidr,
        unavailable_reason: null,
        hosts_discovered: 10,
        hosts_scanned: 10,
        host_cap: 50,
        capped: false,
        hosts: [],
        scanned_at: "2026-09-23T12:00:00Z",
      });
    }
    return post<DeepScanRangeResult>("/api/live/deep-scan-range", { cidr, consent });
  },
  deepScanLast: (assetId: string): Promise<DeepScanResult> => {
    if (isDemoMode()) {
      return Promise.resolve({
        available: true,
        target: "10.0.1.11",
        unavailable_reason: null,
        os: "Ubuntu 22.04 LTS",
        ports: [22, 443],
        services: [
          { port: 22, protocol: "tcp", service_name: "ssh", product: "OpenSSH", version: "8.9p1" },
          { port: 443, protocol: "tcp", service_name: "https", product: "nginx", version: "1.18.0" },
        ],
        cves: [],
        cve_lookup_unavailable: false,
        cve_lookup_reason: null,
        asset_id: assetId,
        risk_score: 75,
        top_path_risk: 0.94,
        top_path_formed: true,
        scanned_at: "2026-09-23T12:00:00Z",
      });
    }
    return get<DeepScanResult>(`/api/live/deep-scan/${assetId}`);
  },
  telegramStatus: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_TELEGRAM_STATUS);
    return get<{
      configured: boolean;
      running: boolean;
      chat_ids_count: number;
      chat_ids_masked: string[];
      alerted_count: number;
    }>("/api/live/telegram-status");
  },
  telegramTest: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_TELEGRAM_TEST);
    return post<{
      success: boolean;
      results: Array<{ chat_id: string; delivered: boolean }>;
    }>("/api/live/telegram-test");
  },
  startLiveTracking: (data: { device_id: string; ip: string; mac?: string | null; hostname?: string | null }): Promise<TrackingSession> => {
    if (isDemoMode()) {
      return Promise.resolve({
        tracking_session_id: "session-sim-01",
        device_id: data.device_id,
        target_ip: data.ip,
        target_mac: data.mac ?? null,
        target_hostname: data.hostname ?? null,
        status: "LIVE" as const,
        capture_source: "pcap",
        started_at: "2026-09-23T12:00:00Z",
        packet_count: 1240,
        flow_count: 48,
        byte_count: 852000,
      });
    }
    return post<TrackingSession>("/api/live/tracking/start", data);
  },
  stopLiveTracking: (tracking_session_id: string): Promise<TrackingSession> => {
    if (isDemoMode()) {
      return Promise.resolve({
        tracking_session_id,
        device_id: "dev-win-01",
        target_ip: "10.0.4.5",
        target_mac: "00:1A:2B:3C:4D:5E",
        target_hostname: "admin-ws-01",
        status: "STOPPED" as const,
        capture_source: "pcap",
        started_at: "2026-09-23T12:00:00Z",
        ended_at: "2026-09-23T12:05:00Z",
        packet_count: 1240,
        flow_count: 48,
        byte_count: 852000,
      });
    }
    return post<TrackingSession>("/api/live/tracking/stop", { tracking_session_id });
  },
  getLiveTrackingResults: (tracking_session_id: string): Promise<TrackingResults> => {
    if (isDemoMode()) {
      return Promise.resolve({
        session: {
          tracking_session_id,
          device_id: "dev-win-01",
          target_ip: "10.0.4.5",
          target_mac: "00:1A:2B:3C:4D:5E",
          target_hostname: "admin-ws-01",
          status: "LIVE" as const,
          capture_source: "pcap",
          started_at: "2026-09-23T12:00:00Z",
          packet_count: 1240,
          flow_count: 48,
          byte_count: 852000,
        },
        metrics: {
          packet_count: 1240,
          flow_count: 48,
          byte_count: 852000,
          packets_per_sec: 14.2,
          bytes_per_sec: 8400,
          active_connections: 5,
        },
        protocols: {
          tcp: 38,
          udp: 10,
          icmp: 0,
          dns: 8,
          http_https: 30,
          other: 0,
        },
        top_destinations: [
          { destination_ip: "10.0.2.50", destination_port: 22, protocol: "tcp", connection_count: 1 },
          { destination_ip: "10.0.0.1", destination_port: 443, protocol: "tcp", connection_count: 4 },
        ],
        current_behaviour: {
          verdict: "SUSPICIOUS" as const,
          confidence: 0.84,
          signals: ["[SIMULATED INFERENCE] Active SSH socket connection from administrative workstation to bastion jump host."],
          attack_category: "Lateral Movement (Simulated)",
        },
        evidence: [],
      });
    }
    return get<TrackingResults>(`/api/live/tracking/${tracking_session_id}/results`);
  },
  pairEndpointAgent: (_pairing_code: string) => {
    if (isDemoMode()) {
      return Promise.resolve({
        success: true,
        message: "Demo endpoint agent successfully paired (Simulated).",
        agent: DEMO_ENDPOINT_AGENTS[0],
      });
    }
    return post<EndpointPairingSubmitResult>("/api/endpoint/pairing/pair", { pairing_code: _pairing_code });
  },
  listEndpointAgents: () => {
    if (isDemoMode()) return Promise.resolve(DEMO_ENDPOINT_AGENTS);
    return get<EndpointAgent[]>("/api/endpoint/agents");
  },
  getEndpointAgent: (agent_id: string) => {
    if (isDemoMode()) {
      return Promise.resolve(DEMO_ENDPOINT_AGENTS.find((a) => a.agent_id === agent_id) || DEMO_ENDPOINT_AGENTS[0]);
    }
    return get<EndpointAgent>(`/api/endpoint/agents/${agent_id}`);
  },
  getEndpointTelemetry: (deviceId: string) => {
    if (isDemoMode()) return Promise.resolve(getDemoEndpointTelemetry(deviceId));
    return get<EndpointTelemetryOut>(`/api/endpoint/telemetry/${encodeURIComponent(deviceId)}`);
  },
  getEndpointVulnerabilities: (deviceId: string) => {
    if (isDemoMode()) return Promise.resolve(getDemoEndpointVulnerabilities(deviceId));
    return get<EndpointVulnerabilitiesResponse>(`/api/endpoint/vulnerabilities/${encodeURIComponent(deviceId)}`);
  },
};

