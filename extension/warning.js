// Drishti Web Guard — warning page controller.
// Reads verdict details from query params (set by background.js) and wires the
// two buttons. Proceed-anyway allowlists the hostname BEFORE navigating so the
// nav listener won't re-block it (no redirect loop).

const params = new URLSearchParams(location.search);
const originalUrl = params.get("url") || "";
const score = params.get("score") || "—";
const verdict = params.get("verdict") || "High Risk";

let reasons = [];
try {
  reasons = JSON.parse(params.get("reasons") || "[]");
} catch {
  reasons = [];
}

// Render. textContent everywhere — never innerHTML with attacker-influenced data.
document.getElementById("score").textContent = score;
document.getElementById("verdict").textContent = verdict;

const urlEl = document.getElementById("url");
urlEl.textContent = originalUrl;

const list = document.getElementById("reasons");
if (reasons.length === 0) {
  const li = document.createElement("li");
  li.textContent = "The analyzer returned a High Risk verdict for this destination.";
  list.appendChild(li);
} else {
  for (const r of reasons) {
    const li = document.createElement("li");
    li.textContent = r;
    list.appendChild(li);
  }
}

function hostnameOf(u) {
  try {
    return new URL(u).hostname;
  } catch {
    return "";
  }
}

// Go back: return to wherever the user came from; if there's no history entry
// (e.g. a fresh tab), close the tab instead of stranding them on the warning.
document.getElementById("back").addEventListener("click", () => {
  if (history.length > 1) {
    history.back();
  } else {
    window.close();
  }
});

// Proceed anyway: allowlist the hostname FIRST (awaited), THEN navigate.
document.getElementById("proceed").addEventListener("click", () => {
  const hostname = hostnameOf(originalUrl);
  const go = () => {
    if (originalUrl) location.href = originalUrl;
  };
  if (!hostname) return go();
  chrome.runtime.sendMessage({ type: "allow-host", hostname }, () => {
    // navigate only after the allowlist write is acknowledged
    go();
  });
});
