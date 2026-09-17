// Drishti Web Guard — MV3 background service worker
// Listens on webNavigation, asks the Drishti URL Trust Analyzer for a verdict,
// and redirects to a warning page when the analyzer returns "High Risk".
//
// Hard rules honoured here:
//  - The analyzer's `band` field IS the verdict. We never recompute it from the
//    score. Block iff band === "High Risk" (exact string match).
//  - Fail OPEN: any error / network failure / >3s timeout → let the page load.
//  - Only ever talks to the configured Drishti server; no other network calls.

const DEFAULTS = {
  serverBaseUrl: "http://localhost:8000",
  blockingEnabled: true,
};
const API_TIMEOUT_MS = 3000;
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

const BADGE = {
  Trusted: { text: "✓", color: "#2ec27e" }, // teal
  Caution: { text: "!", color: "#f59e42" }, // amber
  "High Risk": { text: "✕", color: "#ef4655" }, // coral
};

// ── in-memory state (rebuilt from storage.session on worker wake) ─────────────
const memCache = new Map(); // hostname -> { result, expires }
const inFlight = new Map(); // hostname -> Promise<result|null>
let refreshInFlight = null; // single-flight token refresh

// ── config / storage helpers ──────────────────────────────────────────────────
async function getConfig() {
  const c = await chrome.storage.local.get(["serverBaseUrl", "blockingEnabled"]);
  return {
    serverBaseUrl: (c.serverBaseUrl || DEFAULTS.serverBaseUrl).replace(/\/+$/, ""),
    blockingEnabled: c.blockingEnabled !== false, // default true
  };
}

async function getTokens() {
  return chrome.storage.local.get(["accessToken", "refreshToken"]);
}

async function setTokens(access, refresh) {
  await chrome.storage.local.set({ accessToken: access, refreshToken: refresh, loggedOut: false });
}

async function markLoggedOut() {
  await chrome.storage.local.set({ loggedOut: true });
}

// ── session allowlist (Proceed-anyway) ────────────────────────────────────────
async function getAllowlist() {
  const s = await chrome.storage.session.get("allowlist");
  return new Set(s.allowlist || []);
}

async function addToAllowlist(hostname) {
  const set = await getAllowlist();
  set.add(hostname);
  await chrome.storage.session.set({ allowlist: [...set] });
}

// ── verdict cache (memory + storage.session, ~10-min TTL) ──────────────────────
async function cacheGet(hostname) {
  const now = Date.now();
  const mem = memCache.get(hostname);
  if (mem && mem.expires > now) return mem.result;
  const s = await chrome.storage.session.get("cache");
  const entry = (s.cache || {})[hostname];
  if (entry && entry.expires > now) {
    memCache.set(hostname, entry);
    return entry.result;
  }
  return null;
}

async function cacheSet(hostname, result) {
  const entry = { result, expires: Date.now() + CACHE_TTL_MS };
  memCache.set(hostname, entry);
  const s = await chrome.storage.session.get("cache");
  const cache = s.cache || {};
  cache[hostname] = entry;
  await chrome.storage.session.set({ cache });
}

// ── skip rules — never analyze these ──────────────────────────────────────────
function isPrivateIp(host) {
  // RFC-1918 + loopback + link-local, IPv4 only (hostnames pass through)
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

function shouldSkip(url, serverBaseUrl) {
  if (url.protocol !== "http:" && url.protocol !== "https:") return true;
  const host = url.hostname;
  if (host === "localhost" || host === "127.0.0.1" || host === "::1") return true;
  if (isPrivateIp(host)) return true;
  try {
    if (host === new URL(serverBaseUrl).hostname) return true; // never analyze Drishti itself
  } catch {
    /* bad configured URL — ignore, don't skip on its account */
  }
  return false;
}

// ── the API call (with one 401→refresh→retry, 3s timeout, fail-open) ──────────
async function authedFetch(path, options, serverBaseUrl, allowRetry = true) {
  const { accessToken } = await getTokens();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  let resp;
  try {
    resp = await fetch(serverBaseUrl + path, {
      ...options,
      headers: {
        "content-type": "application/json",
        ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
      },
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
  if (resp.status === 401 && allowRetry) {
    const refreshed = await refreshTokens(serverBaseUrl);
    if (refreshed) return authedFetch(path, options, serverBaseUrl, false);
    await markLoggedOut();
    return null; // refresh failed → fail open
  }
  return resp;
}

async function refreshTokens(serverBaseUrl) {
  if (refreshInFlight) return refreshInFlight; // single-flight
  refreshInFlight = (async () => {
    try {
      const { refreshToken } = await getTokens();
      if (!refreshToken) return false;
      const resp = await fetch(serverBaseUrl + "/api/auth/refresh", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (!resp.ok) return false;
      const data = await resp.json();
      await setTokens(data.access_token, data.refresh_token);
      return true;
    } catch {
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();
  return refreshInFlight;
}

async function analyze(fullUrl, serverBaseUrl) {
  try {
    const resp = await authedFetch(
      "/api/url-analyzer/analyze",
      { method: "POST", body: JSON.stringify({ url: fullUrl }) },
      serverBaseUrl,
    );
    if (!resp || !resp.ok) {
      console.log("[Drishti Web Guard] analyzer unavailable, failing open", resp && resp.status);
      return null;
    }
    return await resp.json();
  } catch (e) {
    console.log("[Drishti Web Guard] analyze error, failing open:", e.message);
    return null;
  }
}

// dedupe concurrent navigations to the same hostname
function analyzeDeduped(hostname, fullUrl, serverBaseUrl) {
  if (inFlight.has(hostname)) return inFlight.get(hostname);
  const p = (async () => {
    const result = await analyze(fullUrl, serverBaseUrl);
    if (result) await cacheSet(hostname, result);
    return result;
  })().finally(() => inFlight.delete(hostname));
  inFlight.set(hostname, p);
  return p;
}

// ── reasons: the analyzer's counted fail/warn signals, in its own words ───────
function topReasons(result, max = 5) {
  const bad = new Set(["fail", "warn"]);
  return (result.signals || [])
    .filter((s) => bad.has(s.status) && s.counted !== false)
    .map((s) => s.detail || s.label)
    .filter(Boolean)
    .slice(0, max);
}

function warningUrl(originalUrl, result) {
  const params = new URLSearchParams({
    url: originalUrl,
    score: String(Math.round(result.score)),
    verdict: result.band, // exact string from the API
    reasons: JSON.stringify(topReasons(result)),
  });
  return chrome.runtime.getURL("warning.html") + "?" + params.toString();
}

function setBadge(tabId, band) {
  const b = BADGE[band];
  if (!b) return;
  chrome.action.setBadgeBackgroundColor({ tabId, color: b.color }).catch(() => {});
  chrome.action.setBadgeText({ tabId, text: b.text }).catch(() => {});
}

// ── the navigation gate ────────────────────────────────────────────────────────
async function onBeforeNavigate(details) {
  if (details.frameId !== 0) return; // top frame only
  try {
    const { serverBaseUrl, blockingEnabled } = await getConfig();
    if (!blockingEnabled) return;

    let url;
    try {
      url = new URL(details.url);
    } catch {
      return; // unparseable → let it load
    }
    if (shouldSkip(url, serverBaseUrl)) return;

    const host = url.hostname;
    const allow = await getAllowlist();
    if (allow.has(host)) return; // user already chose "Proceed anyway"

    let result = await cacheGet(host);
    if (!result) result = await analyzeDeduped(host, details.url, serverBaseUrl);
    if (!result || !result.band) return; // fail open

    if (result.band === "High Risk") {
      chrome.tabs.update(details.tabId, { url: warningUrl(details.url, result) });
    } else {
      // Caution → amber badge, Trusted → teal badge. Never blocks.
      setBadge(details.tabId, result.band);
    }
  } catch (e) {
    // Absolutely never let an error here block navigation.
    console.log("[Drishti Web Guard] listener error, failing open:", e.message);
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(onBeforeNavigate);

// ── messages from warning.js / options.js ─────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "allow-host" && msg.hostname) {
    // Proceed-anyway: add to allowlist BEFORE the page tells us to navigate, so
    // the re-navigation isn't re-blocked (no redirect loop).
    addToAllowlist(msg.hostname).then(() => sendResponse({ ok: true }));
    return true; // async response
  }
  if (msg?.type === "clear-allowlist") {
    chrome.storage.session.set({ allowlist: [] }).then(() => sendResponse({ ok: true }));
    return true;
  }
  return false;
});
