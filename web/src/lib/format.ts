// Drishti v0.1 — formatters and risk-color mapping | 11-Jul-2026
/** Formatters + risk→color mapping (UIUX.md §2, TESTING.md §4). Null-safe. */

export type RiskToken = "safe" | "medium" | "high" | "critical";

/** Map a 0..100 risk score (or severity) to a ramp bucket (UIUX.md §2 thresholds). */
export function riskBucket(score: number | null | undefined): RiskToken {
  if (score == null || Number.isNaN(score)) return "safe";
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "safe";
}

export function severityBucket(severity: string | null | undefined): RiskToken {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    default:
      return "safe";
  }
}

/** Tailwind text/border/bg class fragments per ramp token. */
export const RISK_TEXT: Record<RiskToken, string> = {
  safe: "text-risk-safe",
  medium: "text-risk-medium",
  high: "text-risk-high",
  critical: "text-risk-critical",
};
export const RISK_BG: Record<RiskToken, string> = {
  safe: "bg-risk-safe",
  medium: "bg-risk-medium",
  high: "bg-risk-high",
  critical: "bg-risk-critical",
};
// Must mirror tailwind.config.js `risk.*` tokens exactly — SVG/canvas (React Flow)
// can't use Tailwind classes, so these hexes are the same PostHog/Sanity ramp.
// SOC Command Center severity ramp: matrix green / amber / orange / red.
export const RISK_HEX: Record<RiskToken, string> = {
  safe: "#00ff66", // terminal green / nominal
  medium: "#f59e0b", // amber
  high: "#f97316", // alert orange
  critical: "#ef4444", // threat alert red
};

/** Compact money: 3_500_000 -> "$3.5M". Null-safe → "—". */
export function money(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) return "—";
  const abs = Math.abs(value);
  if (abs >= 1_000_000_000) return `$${(value / 1_000_000_000).toFixed(1)}B`;
  if (abs >= 1_000_000) return `$${(value / 1_000_000).toFixed(1)}M`;
  if (abs >= 1_000) return `$${(value / 1_000).toFixed(0)}K`;
  return `$${value.toFixed(0)}`;
}

/** Full money with separators for tooltips: "$2,400,000". */
export function moneyFull(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) return "—";
  return `$${Math.round(value).toLocaleString("en-US")}`;
}

export function riskScore(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) return "—";
  return value.toFixed(1);
}

export function cvss(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) return "—";
  return value.toFixed(1);
}

export function percent(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) return "—";
  return `${Math.round(value * 100)}%`;
}

export function severityLabel(severity: string): string {
  return severity ? severity.charAt(0).toUpperCase() + severity.slice(1) : "—";
}

/**
 * Format continuous / cumulative presence duration from backend seconds:
 * null/undefined/NaN: "N/A"
 * 0 seconds: "< 1 min (newly observed)"
 * < 60 seconds (e.g. 45 sec): "< 1 min"
 * 1–59 minutes: "${m} min"
 * 1–23 hours: "${h}h ${m}m"
 * 24+ hours: "${d}d ${hh}h"
 */
export function formatPresenceDuration(seconds: number | null | undefined): string {
  if (seconds == null || Number.isNaN(seconds) || seconds < 0) {
    return "N/A";
  }
  const s = Math.floor(seconds);
  if (s === 0) {
    return "< 1 min (newly observed)";
  }
  if (s < 60) {
    return "< 1 min";
  }
  const totalMinutes = Math.floor(s / 60);
  if (totalMinutes < 60) {
    return `${totalMinutes} min`;
  }
  const totalHours = Math.floor(totalMinutes / 60);
  const remainingMinutes = totalMinutes % 60;
  if (totalHours < 24) {
    return `${totalHours}h ${remainingMinutes}m`;
  }
  const days = Math.floor(totalHours / 24);
  const remainingHours = totalHours % 24;
  return `${days}d ${String(remainingHours).padStart(2, "0")}h`;
}

/**
 * Compact presence duration for grid cards:
 * null/undefined/NaN: "N/A"
 * < 60 seconds: "< 1 min"
 * 1–59 minutes: "${m} min"
 * 1–23 hours: "${h}h ${m}m"
 * 24+ hours: "${d}d ${hh}h"
 */
export function formatCompactPresenceDuration(seconds: number | null | undefined): string {
  if (seconds == null || Number.isNaN(seconds) || seconds < 0) {
    return "N/A";
  }
  const s = Math.floor(seconds);
  if (s < 60) {
    return "< 1 min";
  }
  const totalMinutes = Math.floor(s / 60);
  if (totalMinutes < 60) {
    return `${totalMinutes} min`;
  }
  const totalHours = Math.floor(totalMinutes / 60);
  const remainingMinutes = totalMinutes % 60;
  if (totalHours < 24) {
    return `${totalHours}h ${remainingMinutes}m`;
  }
  const days = Math.floor(totalHours / 24);
  const remainingHours = totalHours % 24;
  return `${days}d ${String(remainingHours).padStart(2, "0")}h`;
}

/**
 * Map observational source to standard SOC labels:
 * scapy → SCAPY / L2
 * arp   → ARP / OS CACHE
 * icmp  → ICMP
 * l3    → L3 / ROUTED
 * null  → SOURCE UNAVAILABLE
 */
export function formatObservationSource(source: string | null | undefined): string {
  if (!source) return "SOURCE UNAVAILABLE";
  const s = source.toLowerCase().trim();
  if (s === "scapy") return "SCAPY / L2";
  if (s === "arp") return "ARP / OS CACHE";
  if (s === "icmp") return "ICMP";
  if (s === "l3") return "L3 / ROUTED";
  return source.toUpperCase();
}

/**
 * Detect locally administered (randomized) MACs according to IEEE 802 standard and vendor hint.
 */
export function isLocallyAdministeredMac(mac: string | null | undefined, vendor?: string | null): boolean {
  if ((vendor ?? "").toLowerCase().includes("private")) return true;
  if (!mac) return false;
  try {
    const firstByte = parseInt(mac.split(/[:-]/)[0], 16);
    return !Number.isNaN(firstByte) && (firstByte & 2) !== 0;
  } catch {
    return false;
  }
}

