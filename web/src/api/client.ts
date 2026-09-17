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
  UrlAnalysisResult,
  UrlHistoryItem,
} from "./types";

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
    if (tokens.refresh) localStorage.setItem(REFRESH_KEY, tokens.refresh);
    else localStorage.removeItem(REFRESH_KEY);
  } catch {
    /* storage unavailable — session just won't survive a reload */
  }
}
export function hasSession(): boolean {
  return tokens.access != null || tokens.refresh != null;
}

/**
 * On a fresh page load the access token is gone but a persisted refresh token
 * may remain. Exchange it for a new access token so the session survives a
 * reload. Returns false when there's nothing to restore.
 */
export async function restoreSession(): Promise<boolean> {
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
  login: (email: string, password: string) =>
    request<TokenPair>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  register: (body: { name: string; email: string; password: string; org_name: string }) =>
    request<RegisterOut>("/api/auth/register", { method: "POST", body: JSON.stringify(body) }),
  me: () => get<Me>("/api/auth/me"),
  patchMe: (body: { name?: string; current_password?: string; new_password?: string }) =>
    patch<Me>("/api/auth/me", body),
  org: () => get<OrgInfo>("/api/org"),
  orgMembers: () => get<Member[]>("/api/org/members"),
  loadSample: () => post<OrgInfo>("/api/org/load-sample"),
  resetOrg: () => post<OrgInfo>("/api/org/reset"),
  agentToken: () => post<AgentToken>("/api/org/agent-token"),
  dashboard: () => get<Dashboard>("/api/dashboard"),
  stats: () => get<Stats>("/api/stats"),
  graph: (focus?: string | null) =>
    get<GraphResponse>(focus ? `/api/graph?focus=${encodeURIComponent(focus)}` : "/api/graph"),
  paths: (k = 25) => get<PathSummary[]>(`/api/paths?k=${k}`),
  path: (id: string) => get<PathDetail>(`/api/paths/${id}`),
  blastRadius: (assetId: string) => get<BlastRadius>(`/api/assets/${assetId}/blast-radius`),
  assets: (query = "") => get<AssetSummary[]>(`/api/assets${query}`),
  asset: (id: string) => get<AssetDetail>(`/api/assets/${id}`),
  findings: (query = "") => get<Finding[]>(`/api/findings${query}`),
  patchFinding: (id: string, status: string) =>
    patch<Finding>(`/api/findings/${id}`, { status }),
  remediate: (finding_id: string, preferred_kind: string, regenerate = false) =>
    post<Remediation>("/api/ai/remediate", { finding_id, preferred_kind, regenerate }),
  impact: (path_id: string) => post<ImpactNarrative>("/api/ai/impact", { path_id }),
  recompute: () => post<Stats>("/api/recompute"),
  analyzeUrl: (url: string) => post<UrlAnalysisResult>("/api/url-analyzer/analyze", { url }),
  urlHistory: () => get<UrlHistoryItem[]>("/api/url-analyzer/history"),
  reportCves: () => get<CveRow[]>("/api/report/cves"),
  reportDistribution: () => get<Distribution>("/api/report/distribution"),
  reportMl: () => get<MlAnalysis>("/api/report/ml"),
  reportHardening: () => get<NodeHardening[]>("/api/report/hardening"),
  reportSummary: () => post<NetworkSummary>("/api/report/summary"),
  netconfigAnalyze: (consent: boolean, config?: NetconfigInput) =>
    post<NetconfigAnalysis>("/api/netconfig/analyze", { consent, config }),
  netconfigLast: () => get<NetconfigAnalysis>("/api/netconfig/last"),
  liveThreats: () => get<LiveThreat[]>("/api/live/threats"),
  liveBlock: (id: string) => post<BlockFix>(`/api/live/block/${id}`),
  liveClear: () => del<{ cleared: number }>("/api/live/threats"),
  resolveLiveThreat: (id: string) => post<{ resolved: boolean; threat_id: string }>(`/api/live/threats/${id}/resolve`),
  liveCheck: (domain: string) =>
    post<{ id: string; domain: string; band: string; score: number; is_threat: boolean }>(
      "/api/live/check",
      { domain },
    ),
  liveDevices: () => get<NetworkDevice[]>("/api/live/devices"),
  liveCoverage: () => get<NetworkCoverage[]>("/api/live/coverage"),
  liveClearDevices: () => del<{ cleared: number }>("/api/live/devices"),
  networkThreats: () => get<NetworkThreat[]>("/api/live/network-threats"),
  demoAttack: () => post<NetworkThreat[]>("/api/live/demo-attack"),
  clearDemoAttack: () => del<{ cleared: number }>("/api/live/demo-attack"),
  autoscanGet: () => get<AutoScanConfig>("/api/live/autoscan"),
  autoscanSet: (body: Partial<Pick<AutoScanConfig, "enabled" | "interval_seconds" | "scan_subnet">>) =>
    request<AutoScanConfig>("/api/live/autoscan", { method: "PUT", body: JSON.stringify(body) }),
  deepScan: (ip: string, consent: boolean) =>
    post<DeepScanResult>("/api/live/deep-scan", { ip, consent }),
  deepScanRange: (cidr: string, consent: boolean) =>
    post<DeepScanRangeResult>("/api/live/deep-scan-range", { cidr, consent }),
  deepScanLast: (assetId: string) => get<DeepScanResult>(`/api/live/deep-scan/${assetId}`),
};
