# Drishti Web Guard — Chrome Extension (MV3)

A defensive browser extension that warns you **before** you open a suspicious
website. It uses the Drishti backend's **URL Trust Analyzer** as the *only*
verdict source — it never re-implements or second-guesses any scanning logic.
It inspects and warns; it never attacks.

## How it works

1. A background service worker listens on `chrome.webNavigation.onBeforeNavigate`
   (top frame only, `frameId === 0`).
2. For each navigation it decides in this order:
   - **Skip** non-`http(s)` schemes, `chrome://`, `chrome-extension://`,
     `localhost`, `127.0.0.1`, private RFC-1918 IPs, and the Drishti server's own
     origin.
   - If the hostname is in the **session allowlist** (you clicked "Proceed
     anyway"), do nothing.
   - Check the **verdict cache** (per hostname, ~10-minute TTL, memory +
     `storage.session`).
   - Otherwise call `POST /api/url-analyzer/analyze`. Concurrent navigations to
     the same hostname share one in-flight request.
3. The extension blocks **iff the analyzer's `band` field equals the exact string
   `"High Risk"`** — it never recomputes the verdict from the score. On a block it
   redirects the tab to `warning.html`.
4. **Caution** → amber toolbar badge (no block). **Trusted** → teal badge.
5. **Fail open**: on any API error, network failure, or 3-second timeout, the
   extension logs to the console and lets the page load. It never blocks on
   uncertainty.

MV3 has no synchronous request blocking, so the redirect-to-warning pattern is
intentional — a brief flash of the original page before the warning appears is
expected and acceptable.

## Auth

The analyzer requires a signed-in Drishti **user** (JWT access token). Access
tokens expire in ~15 minutes, so:

- Log in from the **options page** (email + password → `POST /api/auth/login`).
- Tokens are stored in `chrome.storage.local`.
- On a `401`, the worker calls `POST /api/auth/refresh` once and retries the
  request. If refresh also fails, it **fails open** and the options page shows a
  signed-out state.

## Permissions (minimal)

| Permission | Why |
|---|---|
| `webNavigation` | detect navigations to check |
| `storage` | tokens, config, cache, session allowlist |
| `tabs` | redirect a tab to the warning page, set per-tab badges |
| host: `http://localhost:8000/*` | call the Drishti API (the only host it talks to) |

`optional_host_permissions` covers the case where you point the extension at a
non-localhost Drishti server (see below). No analytics, no third-party calls —
the extension only ever contacts the configured server.

## Load unpacked

1. Start the Drishti backend (from the repo root):
   ```bash
   make server-dev      # or: cd server && .venv/bin/uvicorn app.main:app --reload
   ```
   It listens on `http://localhost:8000` and auto-seeds a demo org on first boot.
2. Open `chrome://extensions`.
3. Toggle **Developer mode** (top-right) on.
4. Click **Load unpacked** and select this `extension/` folder.
5. Click the extension's **Details → Extension options** (or the ⚙ icon) and:
   - confirm the server base URL (`http://localhost:8000`),
   - log in with the demo credentials:
     - **email:** `analyst@acme-retail.dev`
     - **password:** `drishti-demo`
   - leave "Warn before high-risk sites" enabled.

> Pointing at a different server: set the new base URL in options, then add a
> matching `host_permissions` entry (or accept the optional host permission
> prompt). The default build only grants `http://localhost:8000/*`.

## Demo script

With the backend running and the extension logged in:

1. **High Risk → blocked.** Visit `https://good.com@evil/`. The local analyzer
   flags the `@`-obfuscated authority and embedded credentials → `band = "High
   Risk"`, score `30`. The tab redirects to the Drishti warning page showing the
   blocked URL, the score, a **High Risk** badge, and the reasons (`URL contains
   '@'…`, `URL embeds login credentials…`, `The domain does not resolve…`).
2. **Go back.** Click **← Go back to safety** — you return to the page you came
   from; the risky site never loaded.
3. **Proceed anyway.** Revisit `https://good.com@evil/`, click **Proceed
   anyway**. The extension adds `good.com` (the parsed hostname) to the session
   allowlist *first*, then navigates — so the navigation listener sees the
   hostname allowlisted and does **not** re-block it (no redirect loop). The site
   loads.
4. **Allowlist persists for the session.** Visit it again — it loads without a
   warning. Open options → **Clear session allowlist**, then revisit — it prompts
   again. The allowlist also empties on its own when the browser session ends
   (it lives in `chrome.storage.session`).
5. **Trusted / Caution.** Visit a normal site like `https://example.com` — no
   block, and the toolbar badge reflects the band (teal Trusted / amber Caution).
6. **Fail open.** Stop the backend and browse — nothing is blocked; the console
   logs `analyzer unavailable, failing open`.

## Files

- `manifest.json` — MV3 manifest, minimal permissions.
- `background.js` — service worker: nav gate, skip rules, cache, in-flight
  dedup, auth + refresh, fail-open.
- `warning.html` / `warning.js` / `warning.css` — the block page.
- `options.html` / `options.js` — server URL, login, blocking toggle, clear
  allowlist.
