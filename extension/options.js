// Drishti Web Guard — options page controller.
// Server base URL, login (→ tokens in storage.local), blocking toggle, clear
// allowlist. Login/refresh live here because the analyzer needs a user JWT.

const DEFAULT_SERVER = "http://localhost:8000";

const $ = (id) => document.getElementById(id);

function flashSaved(el) {
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 1200);
}

async function load() {
  const c = await chrome.storage.local.get([
    "serverBaseUrl",
    "blockingEnabled",
    "accessToken",
    "loggedOut",
  ]);
  $("serverBaseUrl").value = c.serverBaseUrl || DEFAULT_SERVER;
  $("blockingEnabled").checked = c.blockingEnabled !== false; // default on
  renderAuth(Boolean(c.accessToken) && !c.loggedOut);
}

function renderAuth(loggedIn) {
  const box = $("statusBox");
  const form = $("loginForm");
  const logout = $("logout");
  box.className = "status " + (loggedIn ? "in" : "out");
  box.textContent = loggedIn ? "Signed in — the analyzer is active." : "Signed out — sites will not be checked until you log in.";
  form.style.display = loggedIn ? "none" : "block";
  logout.style.display = loggedIn ? "inline-block" : "none";
}

function serverBase() {
  return ($("serverBaseUrl").value || DEFAULT_SERVER).replace(/\/+$/, "");
}

// ── server URL ────────────────────────────────────────────────────────────────
$("saveServer").addEventListener("click", async () => {
  await chrome.storage.local.set({ serverBaseUrl: serverBase() });
  flashSaved($("serverSaved"));
});

// ── login ─────────────────────────────────────────────────────────────────────
$("login").addEventListener("click", async () => {
  const email = $("email").value.trim();
  const password = $("password").value;
  const box = $("statusBox");
  if (!email || !password) {
    box.className = "status out";
    box.textContent = "Enter an email and password.";
    return;
  }
  box.className = "status out";
  box.textContent = "Signing in…";
  try {
    const resp = await fetch(serverBase() + "/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!resp.ok) {
      box.className = "status out";
      box.textContent = resp.status === 401 ? "Invalid email or password." : `Login failed (${resp.status}).`;
      return;
    }
    const data = await resp.json();
    await chrome.storage.local.set({
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      loggedOut: false,
    });
    $("password").value = "";
    renderAuth(true);
  } catch (e) {
    box.className = "status out";
    box.textContent = "Could not reach the server. Check the base URL.";
    console.log("[Drishti Web Guard] login error:", e.message);
  }
});

$("logout").addEventListener("click", async () => {
  await chrome.storage.local.remove(["accessToken", "refreshToken"]);
  await chrome.storage.local.set({ loggedOut: true });
  renderAuth(false);
});

// ── blocking toggle ─────────────────────────────────────────────────────────────
$("blockingEnabled").addEventListener("change", async (e) => {
  await chrome.storage.local.set({ blockingEnabled: e.target.checked });
});

// ── clear allowlist ─────────────────────────────────────────────────────────────
$("clearAllow").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "clear-allowlist" }, () => {
    const btn = $("clearAllow");
    const original = btn.textContent;
    btn.textContent = "Cleared ✓";
    setTimeout(() => (btn.textContent = original), 1200);
  });
});

load();
