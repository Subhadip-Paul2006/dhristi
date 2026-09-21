// Drishti v0.1 — live network watch | 11-Jul-2026
/** Real-time view of the domains this host is connecting to, scored live by the
 * URL Trust Analyzer (SSL, WHOIS, Safe Browsing, VirusTotal). Nothing mocked:
 * the edge watch agent reports each new domain, the server scores it, and a
 * suspicious domain lights up here within seconds. Click one → why it's risky
 * + an AI-drafted block command. */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Bug,
  Clock,
  Copy,
  Cpu,
  Crosshair,
  ExternalLink,
  Globe,
  Grid3x3,
  Laptop,
  Maximize2,
  Minimize2,
  Network,
  Power,
  Radio,
  RefreshCw,
  Router,
  ScanLine,
  Smartphone,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Layers,
  Compass,
  Terminal,
  Trash2,
  TrendingUp,
  Waypoints,
  X,
  Zap,
  Battery,
  HardDrive,
  Lock,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Cog,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { createPortal } from "react-dom";
import { motion } from "framer-motion";
import { api, ApiError } from "../../api/client";
import { ForceMap, CoverageStrip } from "./ForceMap";
import { LiveTrafficPanel } from "./LiveTrafficPanel";
import { PairEndpointModal } from "./PairEndpointModal";
import { Panel } from "../../components/ui/console";
import type {
  BlockFix,
  CorrelatedFindingOut,
  DeepScanCve,
  DeepScanRangeResult,
  DeepScanResult,
  LiveThreat,
  NetworkDevice,
  NetworkThreat,
  TrackingSession,
} from "../../api/types";
import { Button } from "../../components/Button";
import { Card, EmptyState, LoadingBlock, Select } from "../../components/primitives";
import {
  RISK_HEX,
  riskBucket,
  type RiskToken,
  formatCompactPresenceDuration,
  formatObservationSource,
  formatPresenceDuration,
  isLocallyAdministeredMac,
} from "../../lib/format";
import { useToast } from "../../store/graphStore";

const BAND_TOKEN: Record<string, RiskToken> = {
  Trusted: "safe",
  Caution: "medium",
  "High Risk": "critical",
};

function hexFor(band: string): string {
  return RISK_HEX[BAND_TOKEN[band] ?? "safe"];
}

const SEV_TOKEN: Record<string, RiskToken> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "safe",
};
function sevHex(sev: string): string {
  return RISK_HEX[SEV_TOKEN[(sev || "").toLowerCase()] ?? "medium"];
}

export function LiveWatchPage() {
  const [selected, setSelected] = useState<LiveThreat | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({
    queryKey: ["live", "threats"],
    queryFn: () => api.liveThreats(),
    refetchInterval: 3000, // 3s live poll
  });
  const clear = useMutation({
    mutationFn: () => api.liveClear(),
    onSuccess: (r) => {
      setSelected(null);
      qc.invalidateQueries({ queryKey: ["live", "threats"] });
      toast.show(`Feed cleared (${r.cleared})`, "success");
    },
    onError: (e) => toast.show(e instanceof ApiError ? e.message : "Couldn't clear the feed", "error"),
  });

  const threats = q.data ?? [];
  // keep the open detail panel in sync with the 3s poll (fresh score/band/reasons)
  const liveSelected = selected ? threats.find((t) => t.id === selected.id) ?? selected : null;
  const counts = {
    trusted: threats.filter((t) => t.band === "Trusted").length,
    caution: threats.filter((t) => t.band === "Caution").length,
    risk: threats.filter((t) => t.band === "High Risk").length,
  };

  return (
    <div className="console-atmos min-h-screen">
      <div className="mx-auto max-w-6xl space-y-6 p-4 sm:p-6 lg:p-8">
      <header className="flex flex-wrap items-end justify-between gap-4 border-b border-hairline/60 pb-6">
        <div>
          <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-accent-400">
            <span className="inline-block h-2 w-2 rounded-full bg-accent-500 shadow-[0_0_8px_#00ff66] animate-pulse" />
            <span>SYS.MONITOR // REALTIME_WIRE_WATCH</span>
            <span className="text-ink-muted">·</span>
            <span className="text-accent-400 font-bold">[POLL: 3.0s]</span>
          </div>
          <h1 className="mt-2 font-display text-display font-semibold tracking-tight text-ink-primary">
            Live Network &amp; Domain Telemetry
          </h1>
          <p className="mt-1.5 max-w-2xl font-mono text-small text-ink-secondary">
            Continuous wire inventory: every device discovered on subnet, every outbound socket scored in real time against reputation feeds.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Legend hex={RISK_HEX.safe} label={`TRUSTED: ${counts.trusted}`} />
          <Legend hex={RISK_HEX.medium} label={`CAUTION: ${counts.caution}`} />
          <Legend hex={RISK_HEX.critical} label={`HIGH RISK: ${counts.risk}`} />
          {threats.length > 0 && (
            <Button variant="ghost" size="sm" loading={clear.isPending} onClick={() => clear.mutate()} className="font-mono text-[11px] uppercase">
              <Trash2 className="h-3.5 w-3.5" /> Clear Feed
            </Button>
          )}
        </div>
      </header>

      <ConfigAlerts />

      <DevicesSection />

      <NetworkThreatsSection />

      <ManualCheck onDone={() => qc.invalidateQueries({ queryKey: ["live", "threats"] })} />

      {q.isLoading && (
        <Card className="p-6">
          <LoadingBlock label="Connecting to the live feed…" />
        </Card>
      )}
      {!q.isLoading && threats.length === 0 && (
        <Card className="p-10">
          <EmptyState
            title="Waiting for traffic…"
            hint="Start the watch agent and open a site — it will appear here within seconds."
          />
        </Card>
      )}

      {threats.length > 0 && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_360px]">
          <RadarGrid threats={threats} onPick={setSelected} selected={liveSelected} />
          <div className="lg:sticky lg:top-6 lg:self-start">
            {liveSelected ? (
              // key by id → switching threats remounts, resetting the block mutation
              // so a previous domain's block command can't render under a new domain
              <ThreatDetail key={liveSelected.id} threat={liveSelected} onClose={() => setSelected(null)} />
            ) : (
              <Card className="p-6 text-small text-ink-muted">
                Click a domain to see why it scored the way it did — and get an AI-drafted block.
              </Card>
            )}
          </div>
        </div>
      )}
      </div>
    </div>
  );
}

function deviceIcon(d: NetworkDevice) {
  if (d.is_gateway) return Router;
  if (d.is_self) return Laptop;
  return Smartphone;
}

function deviceAccent(d: NetworkDevice): string {
  return d.is_gateway ? RISK_HEX.medium : d.is_self ? RISK_HEX.safe : "#6b7a94";
}

function deviceType(d: NetworkDevice): string {
  if (d.is_gateway) return "Router / Gateway";
  if (d.is_self) return "This computer";
  const os = (d.paired_endpoint_os ?? d.os_info ?? "").toLowerCase();
  if (os.includes("android")) return "Android device";
  const v = (d.vendor ?? "").toLowerCase();
  if (v.includes("android")) return "Android device";
  if (v.includes("apple")) return "Apple device (iPhone / Mac)";
  if (v.includes("samsung") || v.includes("xiaomi") || v.includes("pixel")) return "Android phone";
  if (v.includes("raspberry")) return "Raspberry Pi / IoT";
  if (v.includes("private")) return "Phone / privacy-enabled device";
  return "Network client";
}

/**
 * Format exact localized timestamp (e.g. "Sep 16, 04:12 PM").
 * Replaces misleading relative "6h ago" presentation.
 */
function formatExactTimestamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    const dt = new Date(iso);
    if (isNaN(dt.getTime())) return "—";
    return dt.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: true,
    });
  } catch {
    return "—";
  }
}

/**
 * Format compact time string for cards (e.g. "18:42:11").
 */
function formatCompactTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    const dt = new Date(iso);
    if (isNaN(dt.getTime())) return "—";
    return dt.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return "—";
  }
}

function isRandomizedMac(d: NetworkDevice): boolean {
  return isLocallyAdministeredMac(d.mac, d.vendor);
}

function PresenceBadge({ state, online }: { state?: "new" | "continuous" | "offline" | null; online: boolean }) {
  const resolvedState = state ?? (online ? "continuous" : "offline");
  if (resolvedState === "new") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-[10px] font-semibold text-emerald-400">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
        ● NEWLY OBSERVED
      </span>
    );
  }
  if (resolvedState === "continuous") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-[10px] font-semibold text-emerald-400">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
        ● PRESENT ON NETWORK
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-hairline bg-surface-2 px-2.5 py-0.5 text-[10px] font-semibold text-ink-muted">
      <span className="h-1.5 w-1.5 rounded-full bg-ink-muted" />
      ○ OFFLINE
    </span>
  );
}

function CompactPresenceBadge({ state, online }: { state?: "new" | "continuous" | "offline" | null; online: boolean }) {
  const resolvedState = state ?? (online ? "continuous" : "offline");
  if (resolvedState === "new") {
    return (
      <span className="inline-flex items-center gap-1 text-[9px] font-semibold text-emerald-400">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
        NEW
      </span>
    );
  }
  if (resolvedState === "continuous") {
    return (
      <span className="inline-flex items-center gap-1 text-[9px] font-semibold text-emerald-400">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
        PRESENT
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-[9px] font-semibold text-ink-muted">
      <span className="h-1.5 w-1.5 rounded-full bg-ink-muted/50" />
      OFFLINE
    </span>
  );
}

// derive the local /24 CIDR from this host / gateway IP (best-effort default)
function cidrFromDevices(devices: NetworkDevice[]): string | null {
  const anchor = devices.find((d) => d.is_self) ?? devices.find((d) => d.is_gateway);
  const ip = anchor?.ip ?? devices[0]?.ip;
  if (!ip) return null;
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

// Surface only the most severe REAL network-config findings (critical/high) as a
// compact banner; full detail + unknown/passed checks live on /app/report.
function ConfigAlerts() {
  const q = useQuery({ queryKey: ["netconfig", "last"], queryFn: () => api.netconfigLast() });
  const data = q.data;
  if (!data || !data.available) return null;
  const severe = data.findings.filter(
    (f) => f.status === "real" && (f.severity === "critical" || f.severity === "high"),
  );
  if (severe.length === 0) return null;
  return (
    <Card className="border-l-[3px] border-l-risk-critical p-4">
      <div className="flex items-center gap-2">
        <ShieldAlert className="h-4 w-4 text-risk-critical" />
        <h2 className="font-display text-body text-ink">Network configuration risks</h2>
        <span className="rounded-full border border-hairline px-2 py-0.5 text-[10px] text-ink-muted">
          {severe.length} critical/high
        </span>
        <Link to="/app/report" className="ml-auto text-[11px] text-accent-400 hover:text-accent-300">
          Full report →
        </Link>
      </div>
      <div className="mt-2 space-y-1.5">
        {severe.slice(0, 4).map((f) => {
          const color = f.severity === "critical" ? RISK_HEX.critical : RISK_HEX.high;
          return (
            <div key={f.id} className="flex flex-wrap items-center gap-2 text-[11px]">
              <span className="rounded-sm border border-hairline px-1.5 py-0.5 text-[9px] font-semibold text-ink-muted">
                {f.category}
              </span>
              <span
                className="rounded-sm px-1.5 py-0.5 text-[9px] font-semibold uppercase"
                style={{ backgroundColor: `${color}22`, color }}
              >
                {f.severity}
              </span>
              <span className="text-ink">{f.title}</span>
              {f.finding_id && (
                <Link
                  to={`/app/remediate/${f.finding_id}`}
                  className="inline-flex items-center gap-1 text-accent-400 hover:text-accent-300"
                >
                  <Terminal className="h-3 w-3" /> fix
                </Link>
              )}
            </div>
          );
        })}
      </div>
    </Card>
  );
}

const THREAT_KIND: Record<
  NetworkThreat["kind"],
  { icon: typeof ShieldAlert; label: string }
> = {
  arp_spoof: { icon: Waypoints, label: "ARP spoofing / MITM" },
  rogue_device: { icon: Smartphone, label: "Rogue device" },
  risky_service: { icon: Bug, label: "Exposed service" },
  malicious_domain: { icon: Globe, label: "Malicious domain" },
};

function isDemoThreat(t: NetworkThreat): boolean {
  return (
    (t.device_mac ?? "").startsWith("de:ad:be:ef") ||
    t.evidence.some((e) => e.includes("de:ad:be:ef")) ||
    (t.hostname ?? "").includes("drishti-demo") ||
    t.title.includes("drishti-demo")
  );
}

// Active threat detection over the live inventory — ARP spoofing, rogue
// devices, exposed services, malicious-domain contact. Turns passive inventory
// into "we caught an attack", with a one-click safe demo for a live walkthrough.
function NetworkThreatsSection() {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({
    queryKey: ["live", "network-threats"],
    queryFn: () => api.networkThreats(),
    refetchInterval: 4000,
  });
  const threats = q.data ?? [];
  const demoActive = threats.some(isDemoThreat);

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["live", "network-threats"] });
    qc.invalidateQueries({ queryKey: ["live", "devices"] });
    qc.invalidateQueries({ queryKey: ["live", "threats"] });
  };
  const demo = useMutation({
    mutationFn: () => api.demoAttack(),
    onSuccess: () => {
      invalidate();
      toast.show("Demo attack injected — detections are live", "success");
    },
    onError: (e) => toast.show(e instanceof ApiError ? e.message : "Couldn't run the demo", "error"),
  });
  const clearDemo = useMutation({
    mutationFn: () => api.clearDemoAttack(),
    onSuccess: (r) => {
      invalidate();
      toast.show(`Demo cleared (${r.cleared})`, "success");
    },
    onError: (e) => toast.show(e instanceof ApiError ? e.message : "Couldn't clear the demo", "error"),
  });

  const bySev = {
    critical: threats.filter((t) => t.severity === "critical").length,
    high: threats.filter((t) => t.severity === "high").length,
    medium: threats.filter((t) => t.severity === "medium").length,
  };

  const [expandAll, setExpandAll] = useState(false);
  const [threatLimit, setThreatLimit] = useState(5);

  const displayedThreats = useMemo(() => threats.slice(0, threatLimit), [threats, threatLimit]);

  return (
    <Panel
      eyebrow="Detection · live on the wire"
      title="Active threats"
      icon={ShieldAlert}
      bodyClassName="px-5 pb-5 pt-4"
      meta={
        <div className="flex flex-wrap items-center justify-end gap-2">
          {threats.length > 0 && (
            <button
              onClick={() => setExpandAll((v) => !v)}
              className="flex items-center gap-1 rounded-md border border-hairline px-2.5 py-1 text-[11px] text-ink-muted hover:text-ink hover:border-accent-500/40 transition-colors"
            >
              {expandAll ? (
                <>
                  <ChevronUp className="h-3 w-3" /> Collapse all
                </>
              ) : (
                <>
                  <ChevronDown className="h-3 w-3" /> Expand all
                </>
              )}
            </button>
          )}
          {bySev.critical > 0 && (
            <span
              className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
              style={{ backgroundColor: `${RISK_HEX.critical}22`, color: RISK_HEX.critical }}
            >
              {bySev.critical} critical
            </span>
          )}
          {bySev.high > 0 && (
            <span
              className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
              style={{ backgroundColor: `${RISK_HEX.high}22`, color: RISK_HEX.high }}
            >
              {bySev.high} high
            </span>
          )}
          {demoActive ? (
            <Button variant="ghost" size="sm" loading={clearDemo.isPending} onClick={() => clearDemo.mutate()}>
              <Trash2 className="h-3.5 w-3.5" /> Clear demo
            </Button>
          ) : (
            <Button
              variant="ghost"
              size="sm"
              loading={demo.isPending}
              onClick={() => demo.mutate()}
              title="Inject clearly-labelled demo threats for a live walkthrough"
            >
              <Crosshair className="h-3.5 w-3.5" /> Run attack demo
            </Button>
          )}
        </div>
      }
    >
      {threats.length === 0 ? (
        <div className="rounded-node border border-hairline bg-surface-2 p-5 text-center text-small text-ink-muted">
          <ShieldCheck className="mx-auto mb-2 h-5 w-5 text-risk-safe" />
          No active threats on the wire right now. Detection watches for ARP spoofing, rogue
          devices, exposed services, and malicious-domain contact.
          <div className="mt-2 text-[11px]">
            No second device handy? <span className="text-accent-400">Run attack demo</span> to see
            it catch a live intrusion.
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          {demoActive && (
            <div className="flex flex-wrap items-center gap-2 rounded-node border border-dashed border-accent-500/40 bg-accent-500/5 px-3 py-1.5 text-[11px] text-accent-300">
              <Zap className="h-3.5 w-3.5" /> Demo attack active — clearly-labelled test threats.
              <Link to="/app/paths" className="inline-flex items-center gap-1 font-medium text-accent-400 hover:text-accent-300">
                See the full breach path & fix on the Attack Paths <Crosshair className="h-3 w-3" />
              </Link>
              <span className="text-ink-muted">· Click <b>Clear demo</b> when done.</span>
            </div>
          )}
          {displayedThreats.map((t) => (
            <ThreatRow key={t.id} t={t} forceExpand={expandAll} />
          ))}

          {/* Progressive 5-item Load More Button */}
          {threatLimit < threats.length && (
            <div className="flex flex-col items-center justify-center gap-2 pt-2 border-t border-hairline/30">
              <span className="text-[11px] font-mono text-ink-muted">
                Showing {displayedThreats.length} of {threats.length} active threats
              </span>
              <button
                onClick={() => setThreatLimit((l) => Math.min(l + 5, threats.length))}
                className="flex items-center gap-1.5 rounded-lg border border-hairline bg-surface-2 px-4 py-1.5 text-xs font-semibold text-ink-primary hover:bg-surface-3 hover:border-accent-500/40 transition-all shadow-xs"
              >
                <RefreshCw className="h-3 w-3 text-accent-400" />
                Load more threats (+{Math.min(5, threats.length - threatLimit)} remaining)
              </button>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

function ThreatRow({ t, forceExpand }: { t: NetworkThreat; forceExpand?: boolean }) {
  const [open, setOpen] = useState(false);
  const isExpanded = forceExpand ?? open;
  const meta = THREAT_KIND[t.kind] ?? { icon: ShieldAlert, label: t.kind };
  const Icon = meta.icon;
  const color = sevHex(t.severity);
  const demo = isDemoThreat(t);

  return (
    <div
      className="rounded-node border border-hairline bg-surface-2 transition-all hover:border-hairline-soft overflow-hidden"
      style={{ borderLeft: `3px solid ${color}` }}
    >
      {/* Clickable Header Row */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between p-3 text-left hover:bg-surface-3/60 transition-colors"
      >
        <div className="flex flex-wrap items-center gap-2 min-w-0 pr-2">
          <Icon className="h-4 w-4 shrink-0" style={{ color }} />
          <span className="font-medium text-small text-ink truncate">{t.title}</span>
          <span
            className="rounded-sm px-1.5 py-0.5 text-[9px] font-semibold uppercase shrink-0"
            style={{ backgroundColor: `${color}22`, color }}
          >
            {t.severity}
          </span>
          {demo && (
            <span className="rounded-sm border border-dashed border-accent-500/50 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-accent-400 shrink-0">
              demo
            </span>
          )}
          {t.evidence.length > 0 && !isExpanded && (
            <span className="rounded bg-surface-1 px-1.5 py-0.5 font-mono text-[9.5px] text-ink-muted shrink-0 border border-hairline/40">
              {t.evidence.length} signal{t.evidence.length === 1 ? "" : "s"}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0 ml-auto">
          {t.mitre && (
            <span className="hidden sm:inline-block font-mono text-[10px] text-ink-muted" title="MITRE ATT&CK technique">
              {t.mitre}
            </span>
          )}
          <ChevronDown
            className={`h-4 w-4 text-ink-muted transition-transform duration-200 ${
              isExpanded ? "rotate-180 text-accent-400" : ""
            }`}
          />
        </div>
      </button>

      {/* Expandable Body */}
      {isExpanded && (
        <div className="px-3 pb-3 pt-1 border-t border-hairline/40 space-y-2 bg-black/[0.015]">
          <p className="text-[12px] leading-relaxed text-ink-secondary">{t.detail}</p>
          {t.evidence.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-0.5">
              {t.evidence.map((e, i) => (
                <span
                  key={i}
                  className="rounded-sm border border-hairline bg-surface-1 px-2 py-0.5 font-mono text-[10px] text-ink-muted shadow-xs"
                >
                  {e}
                </span>
              ))}
            </div>
          )}
          {t.recommendation && (
            <div className="flex items-start gap-1.5 rounded-md bg-risk-safe/10 border border-risk-safe/20 p-2 text-[11px] text-ink-secondary">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-risk-safe" />
              <span>{t.recommendation}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// A device's real deep-scan status. "not scanned" is visually distinct from a
// real "0 CVEs" clean result — an unscanned device is NEVER shown as 0/safe.
function VulnBadge({ d, compact = false }: { d: NetworkDevice; compact?: boolean }) {
  if (!d.scanned) {
    return (
      <span className="rounded-sm border border-dashed border-hairline-soft px-1.5 py-0.5 text-[9px] font-medium text-ink-muted">
        not scanned
      </span>
    );
  }
  const n = d.vuln_count ?? 0;
  if (n === 0) {
    return (
      <span className="inline-flex items-center gap-1 rounded-sm bg-risk-safe/15 px-1.5 py-0.5 text-[9px] font-medium text-risk-safe">
        <ShieldCheck className="h-2.5 w-2.5" /> 0 CVEs
      </span>
    );
  }
  const color = sevHex(d.worst_severity ?? "medium");
  return (
    <span
      className="rounded-sm px-1.5 py-0.5 text-[9px] font-semibold"
      style={{ backgroundColor: `${color}22`, color }}
      title={`${n} matched CVE(s), worst: ${d.worst_severity}`}
    >
      {n} {compact ? "CVE" : `CVE${n === 1 ? "" : "s"}`}
    </span>
  );
}

function AutoScanControls({ devices }: { devices: NetworkDevice[] }) {
  const qc = useQueryClient();
  const toast = useToast();
  const cfgQ = useQuery({ queryKey: ["live", "autoscan"], queryFn: () => api.autoscanGet(), refetchInterval: 8000 });
  const set = useMutation({
    mutationFn: (body: { enabled?: boolean; interval_seconds?: number; scan_subnet?: boolean }) =>
      api.autoscanSet(body),
    onSuccess: (c) => {
      qc.setQueryData(["live", "autoscan"], c);
      qc.invalidateQueries({ queryKey: ["live", "devices"] });
    },
    onError: (e) => toast.show(e instanceof ApiError ? e.message : "Couldn't update autoscan", "error"),
  });
  const cfg = cfgQ.data;
  if (!cfg) return null;

  const scannedCount = devices.filter((d) => d.scanned).length;
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-xl border border-hairline-soft bg-surface-1/40 backdrop-blur-xl p-3 shadow-lg">
      <button
        onClick={() => set.mutate({ enabled: !cfg.enabled })}
        disabled={set.isPending}
        className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[12px] font-medium transition-colors ${
          cfg.enabled
            ? "bg-risk-safe/20 text-risk-safe shadow-[0_0_15px_rgba(46,194,126,0.3)] border border-risk-safe/30"
            : "bg-surface-2 text-ink-muted hover:text-ink hover:bg-surface-2/80 border border-hairline"
        }`}
      >
        <Power className="h-3.5 w-3.5" /> Auto-scan {cfg.enabled ? "ON" : "OFF"}
      </button>
      {cfg.enabled && (
        <span className="flex items-center gap-1 text-[10px] text-ink-muted">
          <RefreshCw className={`h-3 w-3 ${cfg.running ? "animate-spin text-risk-safe" : ""}`} />
          {cfg.running ? "running" : "idle"} · every
        </span>
      )}
      <Select
        uiSize="sm"
        value={String(cfg.interval_seconds)}
        onChange={(e) => set.mutate({ interval_seconds: Number(e.target.value) })}
      >
        <option value="300">5 min</option>
        <option value="420">7 min</option>
        <option value="600">10 min</option>
        <option value="900">15 min</option>
      </Select>
      <label className="flex cursor-pointer items-center gap-1.5 text-[11px] text-ink-muted">
        <input
          type="checkbox"
          className="accent-accent-500"
          checked={cfg.scan_subnet}
          onChange={(e) => set.mutate({ scan_subnet: e.target.checked })}
        />
        I'm authorized to scan this whole network
      </label>
      <span className="ml-auto text-[10px] text-ink-muted">
        scope: <b className="text-ink-muted">{cfg.scan_subnet ? "whole subnet" : "this host only"}</b> ·{" "}
        {scannedCount}/{devices.length} scanned
      </span>
    </div>
  );
}

function DevicesSection() {
  const [picked, setPicked] = useState<NetworkDevice | null>(null);
  const [view, setView] = useState<"map" | "grid">("map");
  const [subnetOpen, setSubnetOpen] = useState(false);
  const [pairModalOpen, setPairModalOpen] = useState(false);
  const [visibleCount, setVisibleCount] = useState(12);
  // engine risk_score per device once deep-scanned → recolors its node/tile
  const [scanRisk, setScanRisk] = useState<Record<string, number>>({});
  const q = useQuery({
    queryKey: ["live", "devices"],
    queryFn: () => api.liveDevices(),
    refetchInterval: 5000,
  });
  const endpointAgentsQ = useQuery({
    queryKey: ["endpoint", "agents"],
    queryFn: () => api.listEndpointAgents(),
    refetchInterval: 5000,
  });
  const coverageQ = useQuery({
    queryKey: ["live", "coverage"],
    queryFn: () => api.liveCoverage(),
    refetchInterval: 5000,
  });
  const threatsQ = useQuery({
    queryKey: ["live", "threats"],
    queryFn: () => api.liveThreats(),
    refetchInterval: 3000,
  });
  const endpointAgents = endpointAgentsQ.data ?? [];
  const onlineAgentsCount = endpointAgents.filter((a) => a.status === "ONLINE").length;

  // Live data only — no fake/asset fallback. Empty list = nothing currently
  // on the wire (agent stopped or network changed), and we say so.
  const devices = q.data ?? [];
  const coverage = coverageQ.data ?? [];
  const threats = threatsQ.data ?? [];
  const online = devices.filter((d) => d.online).length;

  // Progressive slicing for optimal DOM load performance
  const displayedDevices = useMemo(() => devices.slice(0, visibleCount), [devices, visibleCount]);

  // rollup of REAL data only: sum matched CVEs across scanned devices, and how
  // many devices remain unscanned (never counted as 0).
  const totalVulns = devices.reduce((s, d) => s + (d.scanned ? d.vuln_count ?? 0 : 0), 0);
  const unscanned = devices.filter((d) => !d.scanned).length;

  // keep the open detail card in sync with fresh poll data
  const live = picked ? devices.find((d) => d.id === picked.id) ?? picked : null;

  return (
    <Panel
      eyebrow="Inventory · live on the wire"
      title="Devices on your network"
      icon={Router}
      bodyClassName="px-5 pb-5 pt-4"
      meta={
        <div className="flex flex-wrap items-center justify-end gap-2">
          <span className="rounded-full border border-hairline px-2 py-0.5 font-mono text-[11px] tabular-nums text-ink-muted">
            {online} online · {devices.length} total
          </span>
          {totalVulns > 0 && (
            <span className="rounded-full border border-risk-critical/40 bg-risk-critical/10 px-2 py-0.5 font-mono text-[11px] text-risk-critical">
              {totalVulns} CVEs
            </span>
          )}
          {unscanned > 0 && (
            <span className="rounded-full border border-dashed border-hairline-soft px-2 py-0.5 font-mono text-[11px] text-ink-muted">
              {unscanned} unscanned
            </span>
          )}
          {cidrFromDevices(devices) && (
            <button
              onClick={() => setSubnetOpen(true)}
              className="flex items-center gap-1.5 rounded-md border border-hairline px-2.5 py-1.5 text-[11px] text-ink-muted hover:border-accent-500/50 hover:text-ink"
            >
              <Waypoints className="h-3.5 w-3.5 text-accent-400" /> Scan subnet
            </button>
          )}
          <button
            onClick={() => setPairModalOpen(true)}
            className="flex items-center gap-1.5 rounded-md border border-accent-500/30 bg-accent-500/10 px-2.5 py-1.5 text-[11px] font-mono text-accent-400 hover:border-accent-500/50 hover:bg-accent-500/20"
            title="Pair Drishti Endpoint Agent running on Windows or macOS"
          >
            <Laptop className="h-3.5 w-3.5 text-accent-400" />
            <span>Pair Endpoint Agent</span>
            {endpointAgents.length > 0 && (
              <span className="rounded-full bg-accent-500/20 px-1.5 py-0.2 text-[10px] text-accent-400">
                {onlineAgentsCount > 0 ? `${onlineAgentsCount} online` : `${endpointAgents.length} paired`}
              </span>
            )}
          </button>
          <div className="flex items-center gap-1 rounded-md border border-hairline p-0.5">
            <button
              onClick={() => setView("map")}
              className={`flex items-center gap-1 rounded-sm px-2 py-1 text-[11px] ${
                view === "map" ? "bg-accent-500/15 text-accent-400" : "text-ink-muted hover:text-ink"
              }`}
            >
              <Network className="h-3.5 w-3.5" /> Map
            </button>
            <button
              onClick={() => setView("grid")}
              className={`flex items-center gap-1 rounded-sm px-2 py-1 text-[11px] ${
                view === "grid" ? "bg-accent-500/15 text-accent-400" : "text-ink-muted hover:text-ink"
              }`}
            >
              <Grid3x3 className="h-3.5 w-3.5" /> Grid
            </button>
          </div>
        </div>
      }
    >
      <AutoScanControls devices={devices} />

      {devices.length === 0 && !q.isLoading && (
        <div className="rounded-node border border-hairline bg-surface-2 p-6 text-center text-small text-ink-muted">
          No devices currently on the wire. Start the agent in devices mode
          (<span className="font-mono">drishti_watch.py --mode devices</span>) on the
          network you want to inventory — devices appear here only while an agent
          is actively seeing them.
        </div>
      )}

      {view === "map" && (
        <>
          <CoverageStrip coverage={coverage} />
          <MapFrame>
            <ForceMap
              devices={devices}
              coverage={coverage}
              onPick={setPicked}
              scanRisk={scanRisk}
            />
          </MapFrame>
        </>
      )}

      {view === "grid" && (
        <div className="space-y-4">
          <motion.div key={visibleCount} 
            initial="hidden" 
            animate="show" 
            variants={{
              hidden: { opacity: 0 },
              show: {
                opacity: 1,
                transition: { staggerChildren: 0.04 }
              }
            }}
            className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4"
          >
            {displayedDevices.map((d) => {
              const Icon = deviceIcon(d);
              const accent =
                scanRisk[d.id] != null ? RISK_HEX[riskBucket(scanRisk[d.id])] : deviceAccent(d);
              const activeAppCount = d.active_apps?.length ?? 0;
              const activeDomCount = d.active_domains?.length ?? 0;
              return (
                <motion.button
                  variants={{
                    hidden: { opacity: 0, y: 12 },
                    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
                  }}
                  key={d.id}
                  onClick={() => setPicked(d)}
                  className={`group rounded-node border bg-surface-2 p-3 text-left transition-all hover:-translate-y-0.5 hover:border-hairline-soft ${
                    d.online ? "border-hairline" : "border-hairline/40 opacity-50"
                  }`}
                  style={{ borderLeft: `3px solid ${accent}` }}
                >
                  <div className="flex items-center gap-2">
                    <Icon className="h-4 w-4 shrink-0" style={{ color: accent }} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-small font-semibold text-ink">
                        {d.hostname || d.ip}
                      </div>
                      {d.hostname && (
                        <div className="truncate font-mono text-[10px] text-ink-muted">
                          {d.ip}
                        </div>
                      )}
                    </div>
                    <div className="ml-auto shrink-0">
                      <CompactPresenceBadge state={d.presence_state} online={d.online} />
                    </div>
                  </div>

                  <div className="mt-1.5 flex items-center justify-between gap-1">
                    <div className="flex items-center gap-1">
                      <VulnBadge d={d} />
                      {(d.device_security_score ?? d.deviceSecurityScore) != null && (
                        <span
                          className="rounded-sm px-1.5 py-0.5 text-[9px] font-bold font-mono"
                          style={{
                            backgroundColor: (d.device_security_score ?? d.deviceSecurityScore)! >= 0.7 ? "#ef444422" : (d.device_security_score ?? d.deviceSecurityScore)! >= 0.4 ? "#f59e0b22" : "#10b98122",
                            color: (d.device_security_score ?? d.deviceSecurityScore)! >= 0.7 ? "#ef4444" : (d.device_security_score ?? d.deviceSecurityScore)! >= 0.4 ? "#f59e0b" : "#10b981",
                          }}
                          title={`Unified Deterministic Score: ${Math.round((d.device_security_score ?? d.deviceSecurityScore)! * 100)}% (Risk Signal Composite)`}
                        >
                          SCORE: {Math.round((d.device_security_score ?? d.deviceSecurityScore)! * 100)}%
                        </span>
                      )}
                    </div>
                    <span className="font-mono text-[9px] text-ink-muted uppercase">
                      {formatObservationSource(d.observation_source)}
                    </span>
                  </div>
                  {(d.ai_tracking_active ?? d.aiTrackingActive) && (
                    <div className="mt-1 flex items-center gap-1 font-mono text-[8.5px]">
                      <span className="inline-flex items-center gap-1 rounded bg-cyan-500/10 border border-cyan-500/30 px-1.5 py-0.5 font-bold text-cyan-400 animate-pulse">
                        <Radio className="h-2 w-2" /> AI LIVE: {d.ai_detection?.verdict ?? d.aiDetection?.verdict ?? "ACTIVE"}
                      </span>
                    </div>
                  )}
                  {d.paired_endpoint_agent_id && (
                    <div className="mt-1 flex items-center gap-1 font-mono text-[8.5px]">
                      <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-bold ${
                        d.paired_endpoint_status === "ONLINE"
                          ? "border-sky-500/40 bg-sky-500/10 text-sky-400"
                          : d.paired_endpoint_status === "STALE"
                          ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
                          : "border-rose-500/40 bg-rose-500/10 text-rose-400"
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${
                          d.paired_endpoint_status === "ONLINE" ? "bg-sky-400 animate-pulse" : d.paired_endpoint_status === "STALE" ? "bg-amber-400" : "bg-rose-400"
                        }`} />
                        AGENT: {d.paired_endpoint_status || "ONLINE"} ({d.paired_endpoint_os ? d.paired_endpoint_os.toUpperCase() : "PAIRED"})
                      </span>
                    </div>
                  )}

                  {/* ── Compact Presence & Last Observed (Section 10) ──────── */}
                  <div className="mt-2 grid grid-cols-2 gap-1.5 rounded border border-hairline/60 bg-surface-1/60 px-2 py-1.5 font-mono text-[10px]">
                    <div>
                      <span className="block text-[8px] uppercase tracking-wider text-ink-muted">Presence</span>
                      <span className="font-medium text-emerald-400">
                        {formatCompactPresenceDuration(d.current_session_duration_seconds)}
                      </span>
                    </div>
                    <div className="text-right">
                      <span className="block text-[8px] uppercase tracking-wider text-ink-muted">Last Observed</span>
                      <span className="text-ink-secondary">
                        {formatCompactTime(d.last_seen)}
                      </span>
                    </div>
                  </div>

                  <div className="mt-1.5 truncate font-mono text-[10px] text-ink-muted">{d.mac ?? "—"}</div>
                  <div className="mt-1 flex items-center gap-1">
                    {d.is_gateway && (
                      <span className="rounded-sm bg-risk-medium/15 px-1.5 py-0.5 text-[9px] font-medium text-risk-medium">
                        GATEWAY
                      </span>
                    )}
                    {d.is_self && (
                      <span className="rounded-sm bg-risk-safe/15 px-1.5 py-0.5 text-[9px] font-medium text-risk-safe">
                        THIS DEVICE
                      </span>
                    )}
                    <span className="truncate text-[10px] text-ink-muted">
                      {d.vendor ?? "unknown vendor"}
                    </span>
                  </div>

                  {/* ── Active Telemetry Badges (Compact & Sleek) ────────── */}
                  {(activeAppCount > 0 || activeDomCount > 0) && (
                    <div className="mt-2.5 flex flex-wrap items-center gap-1 border-t border-hairline/50 pt-2">
                      {d.active_apps?.slice(0, 2).map((app) => (
                        <span
                          key={app}
                          className="inline-flex items-center gap-1 rounded border border-accent-500/30 bg-accent-500/10 px-1.5 py-0.5 text-[9px] font-medium text-accent-300"
                        >
                          <Laptop className="h-2.5 w-2.5" />
                          {app}
                        </span>
                      ))}
                      {d.active_domains?.slice(0, 2).map((dom) => (
                        <span
                          key={dom}
                          className="inline-flex max-w-[100px] items-center gap-1 truncate rounded border border-hairline bg-canvas/80 px-1.5 py-0.5 font-mono text-[9px] text-ink-secondary"
                          title={dom}
                        >
                          <Globe className="h-2.5 w-2.5 text-accent-400" />
                          <span className="truncate">{dom}</span>
                        </span>
                      ))}
                      {(activeAppCount + activeDomCount > 4) && (
                        <span className="rounded bg-surface-1 px-1 py-0.5 font-mono text-[9px] text-ink-muted">
                          +{activeAppCount + activeDomCount - 4}
                        </span>
                      )}
                    </div>
                  )}
                </motion.button>
              );
            })}
          </motion.div>

          {/* Progressive Infinite Load Indicator / Expand Button */}
          {visibleCount < devices.length && (
            <div className="flex flex-col items-center justify-center gap-2 pt-2 border-t border-hairline/30">
              <span className="text-[11px] font-mono text-ink-muted">
                Showing {displayedDevices.length} of {devices.length} devices (load-optimized)
              </span>
              <button
                onClick={() => setVisibleCount((c) => Math.min(c + 12, devices.length))}
                className="flex items-center gap-1.5 rounded-lg border border-hairline bg-surface-2 px-4 py-1.5 text-xs font-semibold text-ink-primary hover:bg-surface-3 hover:border-accent-500/40 transition-all shadow-xs"
              >
                <RefreshCw className="h-3 w-3 text-accent-400" />
                Load more nodes (+{Math.min(12, devices.length - visibleCount)} remaining)
              </button>
            </div>
          )}
        </div>
      )}
        {live &&
          createPortal(
            <DeviceDetail
              device={live}
              threats={threats}
              onClose={() => setPicked(null)}
              onScanned={(id, score) => setScanRisk((m) => ({ ...m, [id]: score }))}
            />,
            document.body
          )}
        {subnetOpen &&
          createPortal(
            <SubnetScan
              devices={devices}
              defaultCidr={cidrFromDevices(devices) ?? ""}
              onClose={() => setSubnetOpen(false)}
              onScanned={(risks) => setScanRisk((m) => ({ ...m, ...risks }))}
            />,
            document.body
          )}
        {pairModalOpen &&
          createPortal(
            <PairEndpointModal onClose={() => setPairModalOpen(false)} />,
            document.body
          )}
    </Panel>
  );
}

function SubnetScan({
  devices,
  defaultCidr,
  onClose,
  onScanned,
}: {
  devices: NetworkDevice[];
  defaultCidr: string;
  onClose: () => void;
  onScanned: (risks: Record<string, number>) => void;
}) {
  const toast = useToast();
  const [cidr, setCidr] = useState(defaultCidr);
  const [consented, setConsented] = useState(false);
  const [phase, setPhase] = useState<"consent" | "scanning" | "result">("consent");
  const [result, setResult] = useState<DeepScanRangeResult | null>(null);
  const ipToId = useMemo(() => {
    const m: Record<string, string> = {};
    for (const d of devices) m[d.ip] = d.id;
    return m;
  }, [devices]);

  const qc = useQueryClient();
  const scan = useMutation({
    mutationFn: () => api.deepScanRange(cidr, true),
    onSuccess: (r) => {
      setResult(r);
      setPhase("result");
      const risks: Record<string, number> = {};
      for (const h of r.hosts) {
        const id = ipToId[h.target];
        if (id && h.available && h.risk_score != null) risks[id] = h.risk_score;
      }
      if (Object.keys(risks).length) onScanned(risks);
      qc.invalidateQueries({ queryKey: ["live", "devices"] });
      qc.invalidateQueries({ queryKey: ["live", "network-threats"] });
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["paths"] });
      toast.show(`Subnet scan completed for ${r.cidr} (${r.hosts.length} hosts analyzed)`, "success");
    },
    onError: (e) => {
      setPhase("consent");
      toast.show(e instanceof ApiError ? e.message : "Subnet scan failed", "error");
    },
  });

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div
        className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-lg border border-hairline-soft bg-surface-1 p-5 shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2">
            <Waypoints className="h-5 w-5 text-accent-400" />
            <h3 className="font-display text-h3 text-ink">Scan this subnet</h3>
          </div>
          <button onClick={onClose} className="text-ink-muted hover:text-ink" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>

        {phase === "consent" && (
          <div className="mt-4">
            <label className="text-[11px] text-ink-muted">Subnet (CIDR)</label>
            <input
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              className="mt-1 w-full rounded-md border border-hairline bg-canvas px-3 py-2 font-mono text-small text-ink outline-none focus:border-accent-500"
              placeholder="192.168.1.0/24"
            />
            <div className="mt-3 rounded-md border border-risk-medium/40 bg-risk-medium/[0.06] p-3">
              <div className="flex items-center gap-2 text-small font-medium text-risk-medium">
                <ShieldQuestion className="h-4 w-4" /> Confirm authorization
              </div>
              <p className="mt-1.5 text-[11px] leading-relaxed text-ink-muted">
                This discovers live hosts on <span className="font-mono">{cidr || "your subnet"}</span>{" "}
                and version-scans them directly over the LAN (no NAT, routing, or traffic
                interception). Only scan networks you <b>own</b> or are <b>authorized to test</b>.
              </p>
              <label className="mt-2.5 flex cursor-pointer items-start gap-2 text-[11px] text-ink-muted">
                <input
                  type="checkbox"
                  className="mt-0.5 accent-accent-500"
                  checked={consented}
                  onChange={(e) => setConsented(e.target.checked)}
                />
                <span>I own this network or am authorized to test it.</span>
              </label>
            </div>
            <Button
              variant="primary"
              className="mt-3 w-full"
              disabled={!consented || !cidr.trim()}
              onClick={() => {
                setPhase("scanning");
                scan.mutate();
              }}
            >
              <Waypoints className="mr-1.5 h-4 w-4" /> Start subnet scan
            </Button>
          </div>
        )}

        {phase === "scanning" && (
          <div className="mt-4">
            <LoadingBlock label={`Discovering + scanning hosts on ${cidr} — this can take a few minutes…`} />
          </div>
        )}

        {phase === "result" && result && (
          <div className="mt-4">
            {!result.available ? (
              <div className="rounded-md border border-status-open/50 bg-status-open/[0.07] p-3">
                <div className="flex items-center gap-2 text-small font-medium text-status-open">
                  <AlertTriangle className="h-4 w-4" /> Subnet scan unavailable
                </div>
                <p className="mt-1.5 text-[11px] text-ink-muted">
                  {result.unavailable_reason ?? "The scan could not be completed."}
                </p>
                <p className="mt-1 text-[11px] text-ink-muted">
                  No hosts were scanned — this is <b>not</b> a clean bill of health.
                </p>
              </div>
            ) : (
              <>
                <div className="mb-3 flex flex-wrap items-center gap-2 text-[11px] text-ink-muted">
                  <span className="rounded-full border border-hairline px-2 py-0.5 font-mono">
                    {result.hosts_scanned} scanned · {result.hosts_discovered} discovered
                  </span>
                  {result.capped && (
                    <span className="rounded-full border border-risk-medium/40 bg-risk-medium/10 px-2 py-0.5 text-risk-medium">
                      capped at {result.host_cap} hosts
                    </span>
                  )}
                </div>
                {result.hosts.length === 0 ? (
                  <p className="rounded-md border border-hairline bg-canvas p-2.5 text-[11px] text-ink-muted">
                    No responsive hosts found on this subnet.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {[...result.hosts]
                      .sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))
                      .map((h) => (
                        <SubnetHostRow key={h.target} host={h} onClose={onClose} />
                      ))}
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function SubnetHostRow({ host: h, onClose }: { host: DeepScanResult; onClose: () => void }) {
  const [open, setOpen] = useState(false);
  const bucket = h.risk_score != null ? riskBucket(h.risk_score) : "safe";
  const color = h.available && h.risk_score != null ? RISK_HEX[bucket] : "#6b7a94";
  return (
    <div className="rounded-md border border-hairline" style={{ borderLeft: `3px solid ${color}` }}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left"
      >
        <span className="font-mono text-small text-ink">{h.target}</span>
        {h.available ? (
          <>
            <span className="font-mono text-[10px] text-ink-muted">{h.ports.length} ports</span>
            <span className="font-mono text-[10px] text-ink-muted">{h.cves.length} CVEs</span>
            <span className="ml-auto font-mono text-small font-semibold" style={{ color }}>
              {h.risk_score != null ? Math.round(h.risk_score) : "—"}
            </span>
          </>
        ) : (
          <span className="ml-auto text-[10px] text-status-open">unavailable</span>
        )}
      </button>
      {open && (
        <div className="border-t border-hairline p-3">
          <DeepScanResultView result={h} onClose={onClose} />
        </div>
      )}
    </div>
  );
}

// Live topology frame — the force-directed map (ForceMap) lives inside; this
// only adds the fullscreen toggle that the old ring map had.
function MapFrame({ children }: { children: React.ReactNode }) {
  const [full, setFull] = useState(false);
  return (
    <div
      className={
        full
          ? "fixed inset-0 z-50 bg-canvas"
          : "relative h-[calc(100vh-260px)] min-h-[440px] w-full overflow-hidden rounded-md border border-hairline bg-canvas"
      }
      style={{
        backgroundImage:
          "radial-gradient(120% 90% at 50% 42%, rgba(255,94,36,0.06) 0%, transparent 55%)",
      }}
    >
      <button
        onClick={() => setFull((v) => !v)}
        className="absolute right-3 top-3 z-10 flex items-center gap-1.5 rounded-md border border-hairline bg-surface-1/90 px-2.5 py-1.5 text-[11px] text-ink-muted backdrop-blur hover:text-ink"
      >
        {full ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
        {full ? "Exit fullscreen" : "Fullscreen"}
      </button>
      {children}
    </div>
  );
}

export function CapabilityBadge({ state, device: d }: { state?: string; device?: NetworkDevice }) {
  const hasAgent = Boolean(
    d?.is_self ||
    (d?.endpoint_processes && d.endpoint_processes.length > 0) ||
    (d?.installed_software && d.installed_software.length > 0) ||
    (d?.listening_ports && d.listening_ports.length > 0) ||
    (d?.installed_browsers && d.installed_browsers.length > 0) ||
    (d?.active_browser_tabs && d.active_browser_tabs.length > 0)
  );
  const cap = state ?? d?.capability_state ?? (hasAgent ? "AGENT CONNECTED" : "NETWORK ONLY");
  let color = "border-neutral-500/40 bg-neutral-500/10 text-neutral-400";
  if (cap === "FULL ENDPOINT TELEMETRY") {
    color = "border-emerald-500/40 bg-emerald-500/10 text-emerald-400";
  } else if (cap === "BROWSER EXTENSION CONNECTED") {
    color = "border-cyan-500/40 bg-cyan-500/10 text-cyan-400";
  } else if (cap === "AGENT CONNECTED" || cap === "WINDOWS ENDPOINT" || cap === "MACOS ENDPOINT" || cap === "ANDROID ENDPOINT") {
    color = "border-sky-500/40 bg-sky-500/10 text-sky-400";
  }
  return (
    <span className={`rounded-sm border px-2 py-0.5 font-mono text-[10px] font-bold ${color}`}>
      [{cap}]
    </span>
  );
}

export function FindingStateBadge({ state, inKev }: { state: string; inKev?: boolean }) {
  if (inKev || state === "KNOWN_EXPLOITED") {
    return (
      <span
        className="rounded border border-rose-500 bg-rose-500/20 px-1.5 py-0.5 text-[8.5px] font-bold text-rose-300 flex items-center gap-1"
        title="Known Exploited Vulnerability (CISA KEV). Note: CISA KEV indicates active in-the-wild exploitation, NOT proof this device was compromised."
      >
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse" />
        [KNOWN EXPLOITED]
      </span>
    );
  }
  if (state === "VULNERABLE") {
    return (
      <span
        className="rounded border border-rose-500/40 bg-rose-500/10 px-1.5 py-0.5 text-[8.5px] font-bold text-rose-400"
        title="Confirmed version match against vulnerability database."
      >
        [VULNERABLE]
      </span>
    );
  }
  if (state === "POTENTIAL_MATCH") {
    return (
      <span
        className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[8.5px] font-bold text-amber-400"
        title="Potential match — product match confirmed but version unverified or partially matched."
      >
        [POTENTIAL MATCH]
      </span>
    );
  }
  if (state === "EXPOSED") {
    return (
      <span
        className="rounded border border-purple-500/40 bg-purple-500/10 px-1.5 py-0.5 text-[8.5px] font-bold text-purple-300"
        title="High-risk network service exposed on open port."
      >
        [EXPOSED]
      </span>
    );
  }
  if (state === "OPEN") {
    return (
      <span
        className="rounded border border-sky-500/40 bg-sky-500/10 px-1.5 py-0.5 text-[8.5px] font-bold text-sky-400"
        title="Port or service observed open."
      >
        [OPEN]
      </span>
    );
  }
  return (
    <span
      className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 text-[8.5px] font-bold text-emerald-400"
      title="Tested against vulnerability intelligence — no confirmed vulnerability."
    >
      [CLEAN]
    </span>
  );
}

export function DeviceSecurityProfileSection({ device: d }: { device: NetworkDevice }) {
  const score = d.device_security_score ?? d.deviceSecurityScore;
  if (score == null) return null;

  const pct = Math.round(score * 100);
  const isHigh = score >= 0.7;
  const isMed = score >= 0.4 && score < 0.7;
  const levelLabel = isHigh ? "HIGH RISK" : isMed ? "ELEVATED RISK" : "NORMAL / LOW RISK";
  const badgeColor = isHigh
    ? "border-rose-500/50 bg-rose-500/10 text-rose-400"
    : isMed
    ? "border-amber-500/50 bg-amber-500/10 text-amber-400"
    : "border-emerald-500/50 bg-emerald-500/10 text-emerald-400";
  const meterColor = isHigh ? "bg-rose-500" : isMed ? "bg-amber-500" : "bg-emerald-500";

  return (
    <div className="mt-4 rounded-lg border border-accent-500/25 bg-surface-2/90 p-3.5 backdrop-blur-xs space-y-3">
      <div className="flex items-center justify-between border-b border-hairline/50 pb-2">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-accent-400 font-mono flex items-center gap-1.5">
          <ShieldAlert className="h-3.5 w-3.5 text-accent-400" />
          Unified Device Security Profile
        </span>
        <span className={`rounded border px-2 py-0.5 font-mono text-[9px] font-bold ${badgeColor}`}>
          [{levelLabel}]
        </span>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex flex-col items-center justify-center rounded-lg border border-hairline bg-surface-1 p-3 text-center min-w-[90px]">
          <span className="font-mono text-2xl font-black text-ink">{pct}%</span>
          <span className="text-[9px] font-mono text-ink-muted uppercase">Risk Score</span>
        </div>

        <div className="flex-1 space-y-1.5">
          <div className="flex items-center justify-between text-[10px] font-mono">
            <span className="text-ink-secondary font-medium">Composite Risk Signal</span>
            <span className="text-ink-muted">{score.toFixed(3)} / 1.000</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-surface-3">
            <div className={`h-full ${meterColor} transition-all duration-500`} style={{ width: `${Math.min(100, pct)}%` }} />
          </div>
          <div className="text-[9.5px] text-ink-muted leading-tight">
            Deterministic formula weighting: Max CVE CVSS (35%), Finding States (20%), CISA KEV (15%), Network Exposure (15%), AI Traffic Signal (15%).
          </div>
        </div>
      </div>

      <div className="rounded border border-dashed border-hairline/70 bg-surface-1/50 px-2.5 py-1.5 text-[9.5px] text-ink-muted leading-relaxed">
        <span className="font-semibold text-ink-secondary">Defensive Verification Notice:</span> This score reflects evaluated risk signals. AI confidence and CISA KEV catalog presence are risk-weight factors and do not constitute evidence of device breach.
      </div>
    </div>
  );
}

export function AiSecurityStateSection({ device: d }: { device: NetworkDevice }) {
  const isTracking = d.ai_tracking_active ?? d.aiTrackingActive;
  const det = d.ai_detection ?? d.aiDetection;
  const fc = d.ai_forecast ?? d.aiForecast;
  const sessionId = d.ai_tracking_session_id;

  if (!isTracking && !det && !fc) return null;

  const verdict = det?.verdict ?? "INSUFFICIENT_DATA";
  const isAnom = verdict === "ANOMALOUS";
  const isSusp = verdict === "SUSPICIOUS";
  const isNorm = verdict === "NORMAL";

  const verdictBadgeColor = isAnom
    ? "border-rose-500/50 bg-rose-500/20 text-rose-300"
    : isSusp
    ? "border-amber-500/50 bg-amber-500/20 text-amber-300"
    : isNorm
    ? "border-emerald-500/50 bg-emerald-500/20 text-emerald-300"
    : "border-neutral-500/50 bg-neutral-500/20 text-neutral-400";

  return (
    <div className="mt-4 rounded-lg border border-cyan-500/30 bg-surface-2/90 p-3.5 backdrop-blur-xs space-y-3">
      <div className="flex items-center justify-between border-b border-hairline/50 pb-2">
        <div className="flex items-center gap-1.5">
          <Radio className="h-3.5 w-3.5 text-cyan-400 animate-pulse" />
          <span className="text-[10px] font-semibold uppercase tracking-wider text-cyan-400 font-mono">
            AI Security State — Real-Time Inference &amp; Progression
          </span>
        </div>
        <span className="rounded border border-cyan-500/40 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-cyan-400">
          [TRACKING ACTIVE]
        </span>
      </div>

      {sessionId && (
        <div className="text-[9.5px] font-mono text-ink-muted">
          Session: <span className="text-ink-secondary">{sessionId}</span>
        </div>
      )}

      {/* ── CURRENT DETECTION ── */}
      {det && (
        <div className="rounded border border-hairline bg-surface-1 p-2.5 space-y-1.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-secondary font-mono">
                Current Behaviour
              </span>
              <span className={`rounded border px-1.5 py-0.2 font-mono text-[9px] font-bold ${verdictBadgeColor}`}>
                [{verdict}]
              </span>
            </div>
            <span className="font-mono text-[9.5px] text-ink-muted">
              Confidence: {Math.round((det.confidence ?? 0) * 100)}%
            </span>
          </div>

          <div className="text-[10px] text-ink-muted flex items-center gap-2 font-mono">
            <span>Category: <strong className="text-ink">{det.attack_category || "None"}</strong></span>
            <span className="text-ink-muted">|</span>
            <span className="text-[9px] italic text-ink-muted">
              Current Detection (Heuristic / ML signal — not confirmed breach)
            </span>
          </div>

          {det.signals && det.signals.length > 0 && (
            <div className="flex flex-wrap gap-1 pt-1">
              {det.signals.map((sig, i) => (
                <span key={i} className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[8.5px] text-accent-300 border border-hairline/60">
                  {sig}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── FUTURE PROGRESSION FORECAST ── */}
      {fc && (
        <div className="rounded border border-hairline bg-surface-1 p-2.5 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-purple-400 font-mono flex items-center gap-1">
              <TrendingUp className="h-3 w-3 text-purple-400" />
              Progression Forecast (Probabilistic Horizon)
            </span>
            <span className={`rounded border px-1.5 py-0.2 font-mono text-[8.5px] font-bold ${
              fc.composite_risk_level === "CRITICAL"
                ? "border-rose-500/40 bg-rose-500/10 text-rose-400"
                : fc.composite_risk_level === "HIGH"
                ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
                : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
            }`}>
              [{fc.composite_risk_level || "LOW"}]
            </span>
          </div>

          {fc.is_available && fc.horizon_steps && fc.horizon_steps.length > 0 ? (
            <div className="space-y-1.5">
              <div className="grid grid-cols-3 gap-1.5 font-mono text-[9px]">
                {fc.horizon_steps.map((step, idx) => (
                  <div key={idx} className="rounded border border-hairline bg-surface-2 p-1.5 space-y-0.5">
                    <div className="flex items-center justify-between text-ink-muted">
                      <span className="font-bold text-accent-400">{step.step}</span>
                      <span>{Math.round((step.probability ?? 0) * 100)}%</span>
                    </div>
                    <div className="truncate font-medium text-ink" title={step.state}>
                      {step.state.replace(/_/g, " ")}
                    </div>
                    <div className="text-[8px] text-ink-muted">
                      [{step.status_label || "PREDICTED"}]
                    </div>
                  </div>
                ))}
              </div>

              {fc.mitre_attack && (
                <div className="rounded border border-hairline/60 bg-surface-2/60 px-2 py-1 text-[9.5px] font-mono flex items-center justify-between">
                  <span className="text-ink-secondary truncate">
                    MITRE: <strong>{fc.mitre_attack.tactic}</strong> ({fc.mitre_attack.tactic_id}) → {fc.mitre_attack.technique}
                  </span>
                  <span className="text-ink-muted shrink-0 ml-1">
                    {Math.round((fc.mitre_attack.confidence ?? 0) * 100)}% conf
                  </span>
                </div>
              )}
            </div>
          ) : (
            <div className="text-[9.5px] font-mono text-ink-muted italic">
              {fc.status || "Forecast unavailable — accumulating traffic context"}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function LiveActivitySection({
  device: d,
  threatMap = {},
}: {
  device: NetworkDevice;
  threatMap?: Record<string, LiveThreat>;
}) {
  const hasEndpointAgent = Boolean(
    d.is_self ||
    d.paired_endpoint_agent_id ||
    (d.endpoint_processes && d.endpoint_processes.length > 0) ||
    (d.installed_software && d.installed_software.length > 0) ||
    (d.listening_ports && d.listening_ports.length > 0) ||
    (d.installed_browsers && d.installed_browsers.length > 0) ||
    (d.active_browser_tabs && d.active_browser_tabs.length > 0) ||
    d.capability_state === "WINDOWS ENDPOINT" ||
    d.capability_state === "MACOS ENDPOINT" ||
    d.capability_state === "ANDROID ENDPOINT" ||
    d.capability_state === "AGENT CONNECTED" ||
    d.capability_state === "FULL ENDPOINT TELEMETRY"
  );

  const capState = d.capability_state ?? (
    hasEndpointAgent
      ? (d.active_browser_tabs && d.active_browser_tabs.length > 0 ? "FULL ENDPOINT TELEMETRY" : "AGENT CONNECTED")
      : "NETWORK ONLY"
  );

  let capBadgeColor = "border-neutral-500/40 bg-neutral-500/10 text-neutral-400";
  if (capState === "FULL ENDPOINT TELEMETRY") {
    capBadgeColor = "border-emerald-500/40 bg-emerald-500/10 text-emerald-400";
  } else if (capState === "BROWSER EXTENSION CONNECTED") {
    capBadgeColor = "border-cyan-500/40 bg-cyan-500/10 text-cyan-400";
  } else if (
    capState === "AGENT CONNECTED" ||
    capState === "WINDOWS ENDPOINT" ||
    capState === "MACOS ENDPOINT" ||
    capState === "ANDROID ENDPOINT"
  ) {
    capBadgeColor = "border-sky-500/40 bg-sky-500/10 text-sky-400";
  }

  const firstProcSource = (d.endpoint_processes?.[0]?.source ?? "").toLowerCase();
  const isAndroid = Boolean(
    d.os_info?.toLowerCase().includes("android") ||
    d.paired_endpoint_os?.toLowerCase().includes("android") ||
    capState === "ANDROID ENDPOINT" ||
    firstProcSource.includes("android")
  );
  const isMac = Boolean(
    d.os_info?.toLowerCase().includes("mac") ||
    capState === "MACOS ENDPOINT" ||
    firstProcSource.includes("macos")
  );
  const isLinux = Boolean(
    d.os_info?.toLowerCase().includes("linux") ||
    capState === "LINUX ENDPOINT" ||
    firstProcSource.includes("linux")
  );
  const platformBadge = isAndroid
    ? "[ANDROID ENDPOINT]"
    : isMac
    ? "[MACOS ENDPOINT]"
    : isLinux
    ? "[LINUX ENDPOINT]"
    : "[WINDOWS ENDPOINT]";

  // Separate user apps from background processes
  const userApps = (d.endpoint_processes ?? []).filter(
    (p) => p.category === "USER_APPLICATION" || !p.category
  );
  const bgProcs = (d.endpoint_processes ?? []).filter(
    (p) => p.category === "BACKGROUND_PROCESS" || p.category === "SYSTEM_PROCESS"
  );
  const effectiveUserApps = userApps.length > 0
    ? userApps
    : (d.active_apps ?? []).map((app) => ({ name: app, observed_at: d.last_seen, details: null, category: "USER_APPLICATION" }));


  return (
    <div className="mt-4 border-t border-hairline pt-4 space-y-3" data-testid="live-activity-section">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-small text-ink">
          <Activity className="h-4 w-4 text-accent-400" />
          <span className="font-semibold uppercase tracking-wider text-xs">Live Activity</span>
          {d.is_telemetry_stale && (
            <span className="rounded border border-amber-500/50 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-amber-400" title="Telemetry data is older than 60s">
              [STALE TELEMETRY]
            </span>
          )}
        </div>
        <span className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold ${capBadgeColor}`}>
          [{capState}]
        </span>
      </div>

      {!hasEndpointAgent ? (
        /* Remote LAN Node Fallback */
        <div className="rounded-lg border border-hairline/60 bg-surface-2/60 p-3.5 text-[11px] space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-ink-muted">TELEMETRY UNAVAILABLE</span>
            <span className="rounded bg-surface-1 px-1.5 py-0.5 font-mono text-[9px] text-ink-muted border border-hairline">
              ENDPOINT AGENT NOT INSTALLED
            </span>
          </div>
          <p className="text-ink-secondary text-[11px] leading-relaxed">
            No authorized Drishti endpoint agent installed on this remote host. Endpoint processes, background services, and active browser tabs are only captured from nodes running an authorized agent.
          </p>

          {/* Recent Network Destinations for remote host (if any observed) */}
          {((d.recent_destinations && d.recent_destinations.length > 0) || (d.active_domains && d.active_domains.length > 0)) && (
            <div className="pt-2 border-t border-hairline/40">
              <div className="mb-2 font-medium text-ink-secondary flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <Network className="h-3.5 w-3.5 text-purple-400" /> Recent Network Destinations:
                </span>
                <span className="rounded border border-purple-500/40 bg-purple-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-purple-400">
                  [NETWORK]
                </span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {(d.recent_destinations ?? (d.active_domains ?? []).map((dom) => ({ name: dom, observed_at: d.last_seen, evidence_type: "NETWORK_TRAFFIC", source: "network" }))).map((dest) => {
                  const tr = threatMap[dest.name.toLowerCase()];
                  const band = tr?.band ?? "Trusted";
                  const color = hexFor(band);
                  return (
                    <span key={dest.name} className="inline-flex items-center gap-1.5 rounded border border-hairline bg-surface-1 px-2 py-1 font-mono text-[11px] text-ink">
                      <span>{dest.name}</span>
                      <span className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase" style={{ backgroundColor: `${color}22`, color }}>
                        {band}
                      </span>
                      <span className="text-[9px] text-ink-muted">{formatCompactTime(dest.observed_at)}</span>
                    </span>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Authorized Endpoint Telemetry Available */
        <div className="space-y-3">
          {/* ──────────────── A. RUNNING APPLICATIONS ──────────────── */}
          <div className="rounded-md border border-hairline bg-canvas p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-medium text-ink-secondary flex items-center gap-1.5 text-[11px]">
                <Laptop className="h-3.5 w-3.5 text-accent-400" /> Running Applications ({effectiveUserApps.length}):
              </span>
              <div className="flex items-center gap-1.5">
                <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-400">
                  [USER APPLICATION]
                </span>
                <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-400">
                  {platformBadge}
                </span>
              </div>
            </div>

            {effectiveUserApps.length > 0 ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1">
                {effectiveUserApps.map((proc, i) => (
                  <div
                    key={`${proc.name}-${i}`}
                    className="flex items-center justify-between rounded border border-hairline/60 bg-surface-2/60 px-2.5 py-1.5 text-[11px]"
                  >
                    <div className="flex items-center gap-1.5 min-w-0">
                      <Laptop className="h-3 w-3 text-accent-400 shrink-0" />
                      <span className="font-mono font-medium text-ink truncate" title={proc.name}>
                        {proc.name}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0 ml-2 font-mono text-[10px] text-ink-muted">
                      {proc.details && proc.details.includes("PID:") ? (
                        <span className="text-accent-300/90">{proc.details.split("|")[0].trim()}</span>
                      ) : null}
                      <span>{formatCompactTime(proc.observed_at)}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[11px] text-ink-muted py-1">
                No user applications currently observed on this endpoint.
              </div>
            )}
          </div>

          {/* ──────────────── B. BACKGROUND PROCESSES ──────────────── */}
          <div className="rounded-md border border-hairline bg-canvas p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-medium text-ink-secondary flex items-center gap-1.5 text-[11px]">
                <Cpu className="h-3.5 w-3.5 text-sky-400" /> Background Processes ({bgProcs.length}):
              </span>
              <div className="flex items-center gap-1.5">
                <span className="rounded border border-sky-500/40 bg-sky-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-sky-400">
                  [BACKGROUND PROCESS]
                </span>
                <span className="rounded border border-sky-500/40 bg-sky-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-sky-400">
                  {platformBadge}
                </span>
              </div>
            </div>

            {bgProcs.length > 0 ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1 max-h-48 overflow-y-auto pr-1">
                {bgProcs.map((proc, i) => (
                  <div
                    key={`${proc.name}-${i}`}
                    className="flex items-center justify-between rounded border border-hairline/60 bg-surface-2/60 px-2.5 py-1.5 text-[11px]"
                  >
                    <div className="flex items-center gap-1.5 min-w-0">
                      <Cpu className="h-3 w-3 text-sky-400 shrink-0" />
                      <span className="font-mono font-medium text-ink truncate" title={proc.name}>
                        {proc.name}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0 ml-2 font-mono text-[10px] text-ink-muted">
                      {proc.details && proc.details.includes("PID:") ? (
                        <span className="text-sky-300/90">{proc.details.split("|")[0].trim()}</span>
                      ) : null}
                      <span>{formatCompactTime(proc.observed_at)}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[11px] text-ink-muted py-1">
                No background services or daemons reported yet.
              </div>
            )}
          </div>

          {/* ──────────────── LISTENING PORTS ──────────────── */}
          {d.listening_ports && d.listening_ports.length > 0 && (
            <div className="rounded-md border border-hairline bg-canvas p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-medium text-ink-secondary flex items-center gap-1.5 text-[11px]">
                  <Shield className="h-3.5 w-3.5 text-teal-400" /> Listening Ports ({d.listening_ports.length}):
                </span>
                <div className="flex items-center gap-1.5">
                  <span className="rounded border border-teal-500/40 bg-teal-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-teal-400">
                    [LISTENING PORT]
                  </span>
                  <span className="rounded border border-teal-500/40 bg-teal-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-teal-400">
                    {platformBadge}
                  </span>
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1 max-h-40 overflow-y-auto pr-1">
                {d.listening_ports.map((lp, i) => (
                  <div
                    key={`${lp.name}-${i}`}
                    className="flex items-center justify-between rounded border border-hairline/60 bg-surface-2/60 px-2.5 py-1 text-[10.5px] font-mono"
                  >
                    <span className="font-semibold text-teal-300 truncate" title={lp.name}>
                      {lp.name}
                    </span>
                    {lp.details ? (
                      <span className="text-teal-400/80 text-[10px] shrink-0 ml-1">{lp.details}</span>
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ──────────────── INSTALLED SOFTWARE ──────────────── */}
          {d.installed_software && d.installed_software.length > 0 && (
            <div className="rounded-md border border-hairline bg-canvas p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-medium text-ink-secondary flex items-center gap-1.5 text-[11px]">
                  <Layers className="h-3.5 w-3.5 text-emerald-400" /> Installed Software ({d.installed_software.length}):
                </span>
                <div className="flex items-center gap-1.5">
                  <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-400">
                    [SOFTWARE INVENTORY]
                  </span>
                  <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-400">
                    {platformBadge}
                  </span>
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1 max-h-48 overflow-y-auto pr-1">
                {d.installed_software.map((sw, i) => (
                  <div
                    key={`${sw.name}-${i}`}
                    className="flex items-center justify-between rounded border border-hairline/60 bg-surface-2/60 px-2.5 py-1 text-[10.5px] font-mono"
                  >
                    <span className="font-medium text-ink truncate max-w-[160px]" title={sw.name}>
                      {sw.name}
                    </span>
                    {sw.details ? (
                      <span className="text-ink-muted text-[10px] shrink-0 ml-1.5 truncate max-w-[100px]">{sw.details}</span>
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ──────────────── OS SERVICES & DAEMONS ──────────────── */}
          {d.endpoint_services && d.endpoint_services.length > 0 && (
            <div className="rounded-md border border-hairline bg-canvas p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-medium text-ink-secondary flex items-center gap-1.5 text-[11px]">
                  <Cog className="h-3.5 w-3.5 text-blue-400" /> OS Services & Daemons ({d.endpoint_services.length}):
                </span>
                <div className="flex items-center gap-1.5">
                  <span className="rounded border border-blue-500/40 bg-blue-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-blue-400">
                    [SERVICE]
                  </span>
                  <span className="rounded border border-blue-500/40 bg-blue-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-blue-400">
                    {platformBadge}
                  </span>
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1 max-h-40 overflow-y-auto pr-1">
                {d.endpoint_services.map((svc, i) => (
                  <div
                    key={`${svc.name}-${i}`}
                    className="flex items-center justify-between rounded border border-hairline/60 bg-surface-2/60 px-2.5 py-1 text-[10.5px] font-mono"
                  >
                    <span className="font-medium text-blue-300 truncate max-w-[140px]" title={svc.name}>
                      {svc.name}
                    </span>
                    {svc.details ? (
                      <span className="text-ink-muted text-[9.5px] truncate max-w-[120px] ml-1">{svc.details}</span>
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ──────────────── RUNNING BROWSER BINARIES ──────────────── */}
          {d.browser_processes && d.browser_processes.length > 0 && (
            <div className="rounded-md border border-hairline bg-canvas p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-medium text-ink-secondary flex items-center gap-1.5 text-[11px]">
                  <Compass className="h-3.5 w-3.5 text-amber-400" /> Running Browser Binaries ({d.browser_processes.length}):
                </span>
                <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-amber-400">
                  [BROWSER PROCESS]
                </span>
              </div>
              <div className="flex flex-wrap gap-1.5 pt-1">
                {d.browser_processes.map((bp, i) => (
                  <span
                    key={`${bp.name}-${i}`}
                    className="inline-flex items-center gap-1.5 rounded border border-hairline/60 bg-surface-2/60 px-2.5 py-1 font-mono text-[10.5px] text-amber-300"
                  >
                    <span>{bp.name}</span>
                    {bp.details ? <span className="text-ink-muted text-[9px]">{bp.details}</span> : null}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* ──────────────── C. ACTIVE BROWSER TABS ──────────────── */}
          <div className="rounded-md border border-hairline bg-canvas p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-medium text-ink-secondary flex items-center gap-1.5 text-[11px]">
                <Globe className="h-3.5 w-3.5 text-cyan-400" /> Active Browser Tabs ({(d.active_browser_tabs?.length ?? 0)}):
              </span>
              <span className="rounded border border-cyan-500/40 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-cyan-400">
                [ACTIVE TAB]
              </span>
            </div>

            {d.active_browser_tabs && d.active_browser_tabs.length > 0 ? (
              <div className="space-y-1.5 pt-1">
                {d.active_browser_tabs.map((tab, i) => (
                  <div
                    key={`${tab.url ?? tab.name}-${i}`}
                    className="rounded border border-hairline/70 bg-surface-2/70 p-2 text-[11px] space-y-1"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-cyan-300 truncate" title={tab.title ?? tab.name}>
                        {tab.browser ? `[${tab.browser}] ` : ""}{tab.title ?? tab.name}
                      </span>
                      <span className="font-mono text-[10px] text-ink-muted shrink-0">
                        {formatCompactTime(tab.observed_at)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-[10px] text-accent-400">
                        {tab.domain ?? (tab.name.includes(":") ? tab.name.split(":")[1].trim() : tab.name)}
                      </span>
                      {tab.url ? (
                        <a
                          href={tab.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-[10px] text-sky-400 hover:text-sky-300 truncate max-w-[200px]"
                          title={tab.url}
                        >
                          <span className="truncate">{tab.url}</span>
                          <ExternalLink className="h-2.5 w-2.5 shrink-0" />
                        </a>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              /* Extension Required Fallback */
              <div className="rounded border border-dashed border-hairline bg-surface-2/40 p-2.5 text-[11px] space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-ink-muted">BROWSER TELEMETRY UNAVAILABLE</span>
                  <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-amber-400">
                    EXTENSION REQUIRED
                  </span>
                </div>
                <p className="text-[10.5px] text-ink-secondary leading-relaxed">
                  Endpoint agent is active, but no browser extension is connected. Load the Drishti Extension in Chrome, Edge, or Brave to stream real-time active tabs.
                </p>
              </div>
            )}
          </div>

          {/* ──────────────── D. PROCESS SOCKET CONNECTIONS ──────────────── */}
          {d.process_connections && d.process_connections.length > 0 && (
            <div className="rounded-md border border-hairline bg-canvas p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-medium text-ink-secondary flex items-center gap-1.5 text-[11px]">
                  <Waypoints className="h-3.5 w-3.5 text-indigo-400" /> Process Socket Connections ({d.process_connections.length}):
                </span>
                <span className="rounded border border-indigo-500/40 bg-indigo-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-indigo-400">
                  [PROCESS SOCKET]
                </span>
              </div>
              <div className="space-y-1 max-h-40 overflow-y-auto pr-1">
                {d.process_connections.map((conn, idx) => (
                  <div
                    key={`${conn.name}-${idx}`}
                    className="flex items-center justify-between rounded border border-hairline/60 bg-surface-2/60 px-2.5 py-1 text-[10.5px] font-mono"
                  >
                    <span className="font-semibold text-indigo-300 truncate max-w-[140px]" title={conn.name}>
                      {conn.name}
                    </span>
                    <span className="text-ink-muted truncate text-[10px]" title={conn.details ?? ""}>
                      {conn.details ?? ""}
                    </span>
                    <span className="text-ink-muted shrink-0 text-[9px] ml-2">
                      {formatCompactTime(conn.observed_at)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ──────────────── E. RECENT NETWORK DESTINATIONS ──────────────── */}
          <div className="rounded-md border border-hairline bg-canvas p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-medium text-ink-secondary flex items-center gap-1.5 text-[11px]">
                <Network className="h-3.5 w-3.5 text-purple-400" /> Recent Network Destinations ({(d.recent_destinations?.length ?? d.active_domains?.length ?? 0)}):
              </span>
              <span className="rounded border border-purple-500/40 bg-purple-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-purple-400">
                [NETWORK]
              </span>
            </div>

            {((d.recent_destinations && d.recent_destinations.length > 0) || (d.active_domains && d.active_domains.length > 0)) ? (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {(d.recent_destinations ?? (d.active_domains ?? []).map((dom) => ({ name: dom, observed_at: d.last_seen, evidence_type: "NETWORK_TRAFFIC", source: "network" }))).map((dest) => {
                  const tr = threatMap[dest.name.toLowerCase()];
                  const band = tr?.band ?? "Trusted";
                  const color = hexFor(band);
                  return (
                    <span key={dest.name} className="inline-flex items-center gap-1.5 rounded border border-hairline bg-surface-2 px-2 py-1 font-mono text-[11px] text-ink">
                      <span>{dest.name}</span>
                      <span className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase" style={{ backgroundColor: `${color}22`, color }}>
                        {band}
                      </span>
                      <span className="text-[9px] text-ink-muted">{formatCompactTime(dest.observed_at)}</span>
                    </span>
                  );
                })}
              </div>
            ) : (
              <div className="text-[11px] text-ink-muted py-1">
                No recent outbound network traffic observed.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function EndpointAgentSection({ device: d }: { device: NetworkDevice }) {
  const isPaired = Boolean(d.paired_endpoint_agent_id);
  const [isOpen, setIsOpen] = useState(isPaired);
  const status = d.paired_endpoint_status || (isPaired ? "ONLINE" : "UNPAIRED");

  const isOnline = status === "ONLINE";
  const isStale = status === "STALE";
  const isOffline = status === "OFFLINE";

  const telemQuery = useQuery({
    queryKey: ["endpoint-telemetry", d.paired_endpoint_device_id || d.id],
    queryFn: () => api.getEndpointTelemetry(d.paired_endpoint_device_id || d.id),
    enabled: Boolean(d.paired_endpoint_device_id || d.id) && isPaired,
    staleTime: 5000,
    refetchInterval: 10000,
  });
  const telem = telemQuery.data;

  const statusBadge = isOnline ? (
    <span className="inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-400">
      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
      ONLINE
    </span>
  ) : isStale ? (
    <span className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-amber-400">
      <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
      STALE
    </span>
  ) : isOffline ? (
    <span className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-rose-400">
      <span className="h-1.5 w-1.5 rounded-full bg-rose-400" />
      OFFLINE
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded border border-neutral-500/40 bg-neutral-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-neutral-400">
      UNPAIRED
    </span>
  );

  const formatBytes = (b?: number) => {
    if (b == null || isNaN(b) || b <= 0) return "—";
    const gb = b / (1024 * 1024 * 1024);
    if (gb >= 1) return `${gb.toFixed(1)} GB`;
    const mb = b / (1024 * 1024);
    return `${mb.toFixed(0)} MB`;
  };

  return (
    <div className="mt-4 rounded-lg border border-sky-500/30 bg-surface-2/90 p-3.5 backdrop-blur-xs space-y-3">
      <div
        className="flex items-center justify-between cursor-pointer select-none"
        onClick={() => setIsOpen((prev) => !prev)}
      >
        <div className="flex items-center gap-1.5">
          <Terminal className="h-3.5 w-3.5 text-sky-400" />
          <span className="text-[10px] font-semibold uppercase tracking-wider text-sky-400 font-mono">
            Endpoint Agent
          </span>
          {isPaired && (
            <span className="text-[9.5px] font-mono text-ink-muted">
              ({d.paired_endpoint_hostname || d.hostname || "Agent Host"})
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {statusBadge}
          {isOpen ? (
            <ChevronUp className="h-3.5 w-3.5 text-ink-muted" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5 text-ink-muted" />
          )}
        </div>
      </div>

      {isOpen && (
        <div className="space-y-2.5 pt-1 border-t border-hairline/40">
          {isPaired ? (
            <>
              <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
                <div className="rounded border border-hairline bg-surface-1 p-2 space-y-0.5">
                  <div className="text-ink-muted uppercase tracking-wider text-[8.5px]">Agent ID</div>
                  <div className="text-ink font-semibold truncate" title={d.paired_endpoint_agent_id ?? ""}>
                    {d.paired_endpoint_agent_id}
                  </div>
                </div>

                <div className="rounded border border-hairline bg-surface-1 p-2 space-y-0.5">
                  <div className="text-ink-muted uppercase tracking-wider text-[8.5px]">Device ID</div>
                  <div className="text-ink font-semibold truncate" title={d.paired_endpoint_device_id ?? d.id}>
                    {d.paired_endpoint_device_id ?? d.id}
                  </div>
                </div>

                <div className="rounded border border-hairline bg-surface-1 p-2 space-y-0.5">
                  <div className="text-ink-muted uppercase tracking-wider text-[8.5px]">Hostname &amp; OS</div>
                  <div className="text-ink font-semibold truncate">
                    {d.paired_endpoint_hostname || d.hostname || "—"} ({[d.paired_endpoint_os, d.paired_endpoint_os_version].filter(Boolean).join(" ") || "—"})
                  </div>
                </div>

                <div className="rounded border border-hairline bg-surface-1 p-2 space-y-0.5">
                  <div className="text-ink-muted uppercase tracking-wider text-[8.5px]">Agent Version</div>
                  <div className="text-ink font-semibold">
                    v{d.paired_endpoint_agent_version || "0.1.0"}
                  </div>
                </div>

                <div className="rounded border border-hairline bg-surface-1 p-2 space-y-0.5">
                  <div className="text-ink-muted uppercase tracking-wider text-[8.5px]">Last Heartbeat</div>
                  <div className="text-ink font-semibold">
                    {formatExactTimestamp(d.paired_endpoint_last_heartbeat)}
                  </div>
                </div>

                <div className="rounded border border-hairline bg-surface-1 p-2 space-y-0.5">
                  <div className="text-ink-muted uppercase tracking-wider text-[8.5px]">Paired At</div>
                  <div className="text-ink font-semibold">
                    {formatExactTimestamp(d.paired_endpoint_paired_at)}
                  </div>
                </div>
              </div>

              {/* Hardware Telemetry (CPU, Memory, Storage, Battery) */}
              {(telem?.cpu_info || telem?.memory_info || telem?.storage_info || telem?.battery_info) && (
                <div className="rounded border border-sky-500/20 bg-surface-1 p-2.5 space-y-2 text-[10px] font-mono">
                  <div className="text-[9px] font-bold text-sky-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-hairline pb-1">
                    <Cpu className="h-3 w-3 text-sky-400" />
                    System Hardware Telemetry
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    {/* CPU */}
                    {telem.cpu_info && (
                      <div className="space-y-0.5">
                        <div className="text-ink-muted text-[8.5px] uppercase">CPU ({telem.cpu_info.cores ?? "—"} Cores)</div>
                        <div className="text-ink font-semibold">
                          {telem.cpu_info.usage_percent != null ? `${telem.cpu_info.usage_percent.toFixed(1)}%` : "Active"}
                          <span className="text-[8.5px] text-ink-muted ml-1">({telem.cpu_info.architecture || "ARM"})</span>
                        </div>
                        <div className="text-[8px] text-ink-muted">
                          {telem.cpu_info.per_core_supported ? "Per-core load enabled" : "SELinux: per-core restricted"}
                        </div>
                      </div>
                    )}

                    {/* Memory */}
                    {telem.memory_info && (
                      <div className="space-y-0.5">
                        <div className="text-ink-muted text-[8.5px] uppercase">Memory (RAM)</div>
                        <div className="text-ink font-semibold">
                          {formatBytes(telem.memory_info.used_bytes)} / {formatBytes(telem.memory_info.total_bytes)}
                        </div>
                        <div className="text-[8px] text-ink-muted">
                          Avail: {formatBytes(telem.memory_info.available_bytes)} {telem.memory_info.low_memory ? "· Low RAM alert" : ""}
                        </div>
                      </div>
                    )}

                    {/* Storage */}
                    {telem.storage_info && (
                      <div className="space-y-0.5">
                        <div className="text-ink-muted text-[8.5px] uppercase flex items-center gap-1">
                          <HardDrive className="h-2.5 w-2.5" /> Storage
                        </div>
                        <div className="text-ink font-semibold">
                          {formatBytes(telem.storage_info.used_bytes)} / {formatBytes(telem.storage_info.total_bytes)}
                        </div>
                        <div className="text-[8px] text-ink-muted">
                          Free: {formatBytes(telem.storage_info.available_bytes)}
                        </div>
                      </div>
                    )}

                    {/* Battery */}
                    {telem.battery_info && (
                      <div className="space-y-0.5">
                        <div className="text-ink-muted text-[8.5px] uppercase flex items-center gap-1">
                          <Battery className="h-2.5 w-2.5 text-emerald-400" /> Battery
                        </div>
                        <div className="text-ink font-semibold flex items-center gap-1">
                          <span>{telem.battery_info.percentage ?? "—"}%</span>
                          {telem.battery_info.charging && (
                            <span className="text-emerald-400 text-[8.5px] font-bold">[CHARGING]</span>
                          )}
                        </div>
                        <div className="text-[8px] text-ink-muted">
                          Health: {telem.battery_info.health || "Good"} {telem.battery_info.temperature_c != null ? `· ${telem.battery_info.temperature_c}°C` : ""}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Security Posture Telemetry */}
              {telem?.security_posture && (
                <div className="rounded border border-indigo-500/20 bg-surface-1 p-2.5 space-y-2 text-[10px] font-mono">
                  <div className="text-[9px] font-bold text-indigo-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-hairline pb-1">
                    <ShieldCheck className="h-3 w-3 text-indigo-400" />
                    Device Security Posture
                  </div>
                  <div className="grid grid-cols-2 gap-1.5 text-[9px]">
                    <div>
                      <span className="text-ink-muted">Screen Lock: </span>
                      <span className={telem.security_posture.screen_lock ? "text-emerald-400 font-bold" : "text-amber-400 font-bold"}>
                        {telem.security_posture.screen_lock ? "SECURE" : "UNLOCKED"}
                      </span>
                    </div>
                    <div>
                      <span className="text-ink-muted">Storage: </span>
                      <span className="text-emerald-400 font-bold">{telem.security_posture.encryption || "ENCRYPTED"}</span>
                    </div>
                    <div>
                      <span className="text-ink-muted">Dev Options: </span>
                      <span className={telem.security_posture.developer_options ? "text-amber-400 font-bold" : "text-emerald-400 font-bold"}>
                        {telem.security_posture.developer_options ? "ENABLED" : "OFF"}
                      </span>
                    </div>
                    <div>
                      <span className="text-ink-muted">USB Debugging: </span>
                      <span className={telem.security_posture.usb_debugging ? "text-amber-400 font-bold" : "text-emerald-400 font-bold"}>
                        {telem.security_posture.usb_debugging ? "ENABLED" : "OFF"}
                      </span>
                    </div>
                    {telem.security_posture.security_patch && (
                      <div className="col-span-2">
                        <span className="text-ink-muted">Security Patch: </span>
                        <span className="text-ink font-semibold">{telem.security_posture.security_patch}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Installed Android Applications */}
              {telem?.applications && telem.applications.length > 0 && (
                <div className="rounded border border-hairline bg-surface-1 p-2.5 space-y-1.5 text-[10px] font-mono">
                  <div className="text-[9px] font-bold text-emerald-400 uppercase tracking-wider flex items-center justify-between border-b border-hairline pb-1">
                    <span className="flex items-center gap-1">
                      <Layers className="h-3 w-3 text-emerald-400" />
                      Installed Applications ({telem.applications.length})
                    </span>
                    <span className="text-[8px] text-ink-muted">Package Visibility Compliant</span>
                  </div>
                  <div className="max-h-36 overflow-y-auto space-y-1 pr-1">
                    {telem.applications.map((app, idx) => (
                      <div key={`${app.package_name}-${idx}`} className="flex items-center justify-between rounded bg-surface-2 px-2 py-1">
                        <div className="flex items-center gap-1.5 truncate max-w-[200px]">
                          <span className="text-ink font-medium truncate">{app.label || app.package_name}</span>
                          {app.version_name && (
                            <span className="text-[8.5px] text-ink-muted">v{app.version_name}</span>
                          )}
                        </div>
                        <span className="rounded border border-hairline px-1 py-0.2 text-[8px] text-ink-muted shrink-0">
                          {app.classification || "USER_APP"}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="rounded border border-emerald-500/20 bg-emerald-500/5 px-2.5 py-1.5 text-[9.5px] font-mono text-emerald-300 flex items-center gap-1.5">
                <CheckCircle2 className="h-3 w-3 shrink-0 text-emerald-400" />
                <span>Endpoint telemetry and live network tracking are unified for this device.</span>
              </div>
            </>
          ) : (
            <div className="rounded border border-dashed border-hairline bg-surface-1/50 p-3 text-center space-y-1">
              <div className="text-[11px] font-mono text-ink-muted">
                No Endpoint Agent paired with this device.
              </div>
              <div className="text-[9.5px] text-ink-muted leading-tight">
                To link live OS telemetry, start the agent with <code className="text-accent-300">--force-pair</code> and enter the pairing code in SOC settings.
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DeviceDetail({
  device: d,
  threats = [],
  onClose,
  onScanned,
}: {
  device: NetworkDevice;
  threats?: LiveThreat[];
  onClose: () => void;
  onScanned: (id: string, riskScore: number) => void;
}) {
  const Icon = deviceIcon(d);
  const accent = deviceAccent(d);
  const toast = useToast();
  const [phase, setPhase] = useState<"idle" | "consent" | "scanning" | "result">("idle");
  const [consented, setConsented] = useState(false);
  const [result, setResult] = useState<DeepScanResult | null>(null);
  const [trackingSession, setTrackingSession] = useState<TrackingSession | null>(null);

  const startTracking = useMutation({
    mutationFn: () =>
      api.startLiveTracking({
        device_id: d.id,
        ip: d.ip,
        mac: d.mac,
        hostname: d.hostname,
      }),
    onSuccess: (session) => setTrackingSession(session),
    onError: (e) =>
      toast.show(
        e instanceof ApiError ? e.message : "Couldn't start traffic capture",
        "error"
      ),
  });

  const vulnQuery = useQuery({
    queryKey: ["endpoint-vulns", d.id],
    queryFn: () => api.getEndpointVulnerabilities(d.id),
    enabled: Boolean(d.id),
    staleTime: 15000,
  });

  const threatMap = useMemo(() => {

    const m: Record<string, LiveThreat> = {};
    for (const t of threats) m[t.domain.toLowerCase()] = t;
    return m;
  }, [threats]);

  const rows: [string, string][] = [
    ["IP address", d.ip],
    ["MAC address", d.mac ?? "— (off-link / L3, no ARP MAC)"],
    ["Subnet", d.subnet ? `${d.subnet}${d.subnet_inferred ? " (inferred)" : ""}` : "unknown"],
    ["Discovery", d.discovery === "l3" ? "L3 (routed — ping + DNS)" : "ARP (on-link)"],
    ["Vendor", d.vendor ?? "Unknown"],
    ["Device type", deviceType(d)],
    ["MAC type", isRandomizedMac(d) ? "Locally-administered (randomized for privacy)" : "Universal (hardware-assigned)"],
    ["Network status", d.online ? "Online" : "Offline"],
  ];

  const qc = useQueryClient();
  const scan = useMutation({
    mutationFn: () => api.deepScan(d.ip, true),
    onSuccess: (r) => {
      setResult(r);
      setPhase("result");
      if (r.available && r.risk_score != null) onScanned(d.id, r.risk_score);
      qc.invalidateQueries({ queryKey: ["live", "devices"] });
      qc.invalidateQueries({ queryKey: ["live", "network-threats"] });
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["paths"] });
      toast.show(
        r.available
          ? `Deep scan completed for ${d.ip} (Risk Score: ${r.risk_score != null ? Math.round(r.risk_score) : "—"})`
          : `Deep scan unavailable: ${r.unavailable_reason ?? "scan failed"}`,
        r.available ? "success" : "error"
      );
    },
    onError: (e) => {
      setPhase("idle");
      toast.show(e instanceof ApiError ? e.message : "Deep scan failed", "error");
    },
  });

  const wide = phase === "result" || phase === "scanning";
  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 p-4"
      onClick={onClose}
    >
      <div
        className={`max-h-[90vh] w-full overflow-y-auto rounded-lg border border-hairline-soft bg-surface-1 p-5 shadow-lg ${
          wide ? "max-w-2xl" : "max-w-md"
        }`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-lg" style={{ backgroundColor: `${accent}1f`, color: accent }}>
              <Icon className="h-5 w-5" />
            </span>
            <div>
              <div className="font-mono text-body text-ink">{d.hostname ? `${d.hostname} (${d.ip})` : d.ip}</div>
              <div className="text-[11px] text-ink-muted">{deviceType(d)}</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <PresenceBadge state={d.presence_state} online={d.online} />
            <button onClick={onClose} className="text-ink-muted hover:text-ink" aria-label="Close">
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          {d.is_gateway && (
            <span className="rounded-sm bg-risk-medium/15 px-2 py-0.5 text-[10px] font-medium text-risk-medium">
              GATEWAY — routes all your traffic
            </span>
          )}
          {d.is_self && (
            <span className="rounded-sm bg-risk-safe/15 px-2 py-0.5 text-[10px] font-medium text-risk-safe">
              THIS DEVICE
            </span>
          )}
          <CapabilityBadge state={d.capability_state} device={d} />
          <span className="rounded-sm bg-surface-2 border border-hairline px-2 py-0.5 text-[10px] font-mono text-ink-muted">
            {formatObservationSource(d.observation_source)}
          </span>
        </div>

        {/* ── Presence & Observation Telemetry (History Engine) ───────────── */}
        <div className="mt-4 rounded-lg border border-emerald-500/20 bg-surface-2/80 p-3.5 backdrop-blur-xs">
          <div className="flex items-center justify-between border-b border-hairline/50 pb-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-emerald-400 font-mono flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5 text-emerald-400" />
              Presence Telemetry & Continuity
            </span>
            <span className="font-mono text-[9px] text-accent-300 font-medium">
              {formatObservationSource(d.observation_source)}
            </span>
          </div>

          <div className="mt-3 grid grid-cols-2 gap-3 font-mono text-small">
            <div className="space-y-0.5">
              <div className="text-[10px] uppercase tracking-wider text-ink-muted">First Observed</div>
              <div className="font-semibold text-ink">{formatExactTimestamp(d.first_seen)}</div>
            </div>
            <div className="space-y-0.5 text-right">
              <div className="text-[10px] uppercase tracking-wider text-ink-muted">Last Observed</div>
              <div className="font-semibold text-ink">{formatExactTimestamp(d.last_seen)}</div>
            </div>

            <div className="space-y-0.5 border-t border-hairline/30 pt-2">
              <div className="text-[10px] uppercase tracking-wider text-ink-muted">Current Presence</div>
              <div className="font-semibold text-emerald-400">
                {formatPresenceDuration(d.current_session_duration_seconds)}
              </div>
            </div>
            <div className="space-y-0.5 border-t border-hairline/30 pt-2 text-right">
              <div className="text-[10px] uppercase tracking-wider text-ink-muted">Total Observed</div>
              <div className="font-semibold text-ink-primary">
                {formatPresenceDuration(d.total_observed_duration_seconds)}
              </div>
            </div>

            <div className="space-y-0.5 border-t border-hairline/30 pt-2">
              <div className="text-[10px] uppercase tracking-wider text-ink-muted">Sessions</div>
              <div className="text-[12px] text-ink-secondary">
                {d.session_count ?? 1} {(d.session_count ?? 1) === 1 ? "session" : "sessions"} · {d.observation_count ?? 1} {(d.observation_count ?? 1) === 1 ? "observation" : "observations"}
              </div>
            </div>
            <div className="space-y-0.5 border-t border-hairline/30 pt-2 text-right">
              <div className="text-[10px] uppercase tracking-wider text-ink-muted">Observation Source</div>
              <div className="text-[11px] font-semibold text-accent-300">
                {formatObservationSource(d.observation_source)}
              </div>
            </div>
          </div>
        </div>

        {/* ── MAC Randomization Informational Notice ─────────────────────── */}
        {isRandomizedMac(d) && (
          <div className="mt-2.5 rounded border border-emerald-500/20 bg-emerald-500/5 p-2.5 text-[11px] text-ink-muted flex items-start gap-2">
            <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-400 mt-0.5" />
            <div>
              <span className="font-medium text-emerald-300">Locally-administered / randomized MAC.</span>{" "}
              Presence continuity applies to this observed virtual address.
            </div>
          </div>
        )}

        <dl className="mt-4 divide-y divide-edge-subtle/50">
          {rows.map(([k, v]) => (
            <div key={k} className="flex items-center justify-between gap-3 py-2">
              <dt className="text-small text-ink-muted">{k}</dt>
              <dd className="text-right font-mono text-small text-ink-muted">{v}</dd>
            </div>
          ))}
        </dl>

        {/* ── ENDPOINT AGENT SECTION (Phase 01 / End-to-End Grid Integration) ── */}
        <EndpointAgentSection device={d} />

        {/* ── LIVE ACTIVITY (Running Apps, Active Browser Tabs, Network Destinations) ── */}
        <LiveActivitySection device={d} threatMap={threatMap} />

        {/* ── UNIFIED DEVICE SECURITY PROFILE (Phase 04) ── */}
        <DeviceSecurityProfileSection device={d} />

        {/* ── AI SECURITY STATE (Phase 04) ── */}
        <AiSecurityStateSection device={d} />

        {/* ── Network Exposure & Port Intelligence (DeepScan / Nmap Evidence) ── */}
        {((d.services && d.services.length > 0) || (d.open_ports && d.open_ports.length > 0) || (d.security_findings && d.security_findings.length > 0)) && (
          <div className="mt-4 rounded-lg border border-purple-500/20 bg-surface-2/80 p-3.5 backdrop-blur-xs space-y-2.5">
            <div className="flex items-center justify-between border-b border-hairline/50 pb-2">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-purple-400 font-mono flex items-center gap-1.5">
                <Network className="h-3.5 w-3.5 text-purple-400" />
                Network Exposure &amp; Port Intelligence
              </span>
              <span className="font-mono text-[9px] text-purple-300 font-bold border border-purple-500/40 bg-purple-500/10 rounded px-1.5 py-0.5">
                [NMAP EVIDENCE]
              </span>
            </div>

            {d.services && d.services.length > 0 && (
              <div className="space-y-1">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-muted">Open Ports &amp; Services:</div>
                <div className="space-y-1 max-h-36 overflow-y-auto pr-1">
                  {d.services.map((s) => {
                    const isExposed = [3389, 445, 23, 21, 5900, 139].includes(s.port);
                    return (
                      <div key={`${s.port}/${s.protocol}`} className="flex items-center justify-between rounded bg-canvas px-2.5 py-1 text-[11px] font-mono">
                        <div className="flex items-center gap-2">
                          <span className="text-accent-400 font-bold">{s.port}/{s.protocol}</span>
                          <span className="text-ink">{s.service_name}</span>
                          <span className="text-ink-muted truncate max-w-[120px]">
                            {[s.product, s.version].filter(Boolean).join(" ") || "version unknown"}
                          </span>
                        </div>
                        <div className="flex items-center gap-1">
                          <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1 py-0.2 text-[8.5px] font-bold text-emerald-400">
                            [OPEN]
                          </span>
                          {isExposed && (
                            <span className="rounded border border-rose-500/40 bg-rose-500/10 px-1 py-0.2 text-[8.5px] font-bold text-rose-400">
                              [EXPOSED]
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {d.security_findings && d.security_findings.length > 0 && (
              <div className="space-y-1 pt-1 border-t border-hairline/30">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-muted">Security Analysis Findings:</div>
                <ul className="space-y-0.5 text-[10.5px] font-mono text-amber-300">
                  {d.security_findings.map((f, i) => (
                    <li key={i} className="flex items-center gap-1.5">
                      <span className="text-amber-400">•</span>
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* ── Vulnerability Intelligence & Security Finding States (Phase 03) ── */}
        {((d.cves && d.cves.length > 0) || (vulnQuery.data?.findings && vulnQuery.data.findings.length > 0) || d.scanned || d.capability_state?.includes("ENDPOINT")) && (
          <div className="mt-4 rounded-lg border border-rose-500/20 bg-surface-2/80 p-3.5 backdrop-blur-xs space-y-2.5">
            <div className="flex items-center justify-between border-b border-hairline/50 pb-2">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-rose-400 font-mono flex items-center gap-1.5">
                <Bug className="h-3.5 w-3.5 text-rose-400" />
                Vulnerability Intelligence &amp; Finding States
              </span>
              <div className="flex items-center gap-1 font-mono text-[9px]">
                <span className="rounded border border-hairline bg-surface-3 px-1.5 py-0.5 text-ink-muted">NVD</span>
                <span className="rounded border border-hairline bg-surface-3 px-1.5 py-0.5 text-ink-muted">CISA KEV</span>
                <span className="rounded border border-hairline bg-surface-3 px-1.5 py-0.5 text-ink-muted">OSV</span>
                <span className="rounded border border-hairline bg-surface-3 px-1.5 py-0.5 text-ink-muted">GHSA</span>
              </div>
            </div>

            {/* Source Freshness & Availability */}
            {vulnQuery.data?.source_statuses && vulnQuery.data.source_statuses.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 text-[9px] font-mono">
                <span className="text-ink-muted">Source Feeds:</span>
                {vulnQuery.data.source_statuses.map((src) => (
                  <span
                    key={src.source_name}
                    className={`rounded px-1.5 py-0.2 border ${
                      src.available
                        ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                        : "border-rose-500/30 bg-rose-500/10 text-rose-400 font-bold"
                    }`}
                  >
                    {src.source_name.toUpperCase()}: {src.available ? "ONLINE" : "SOURCE UNAVAILABLE / STALE"}
                  </span>
                ))}
              </div>
            )}

            {/* Correlated Findings List */}
            {(() => {
              const findings: CorrelatedFindingOut[] = vulnQuery.data?.findings?.length
                ? vulnQuery.data.findings
                : (d.endpoint_vuln_findings && d.endpoint_vuln_findings.length > 0)
                ? (d.endpoint_vuln_findings as unknown as CorrelatedFindingOut[])
                : (d.cves || []).map((c) => ({
                    finding_id: c.finding_id || c.id,
                    device_id: d.id,
                    org_id: "",
                    finding_state: c.finding_state || (c.in_kev ? "KNOWN_EXPLOITED" : "VULNERABLE"),
                    observed_product: c.affected_service,
                    observed_vendor: null,
                    observed_version: null,
                    evidence_source: c.source || "network_service",
                    evidence_type: c.evidence_type || "CVE_CORRELATION",
                    cve_id: c.id,
                    cvss: c.cvss,
                    severity: c.severity,
                    in_kev: Boolean(c.in_kev),
                    ghsa_ids: c.ghsa_ids || [],
                    affected_range_text: c.affected_range_text,
                    fixed_version_text: c.fixed_version_text,
                    summary: c.summary,
                    intel_sources: c.intel_sources || ["nvd"],
                    source_freshness: c.source_freshness || "live",
                    source_status_reason: c.source_status_reason,
                    source_details: {},
                  }));

              const verifiedVulns = findings.filter((f) =>
                ["VULNERABLE", "KNOWN_EXPLOITED", "POTENTIAL_MATCH", "EXPOSED"].includes(f.finding_state)
              );

              if (verifiedVulns.length === 0) {
                return (
                  <div className="rounded bg-emerald-500/10 border border-emerald-500/20 p-2.5 text-[11px] font-mono text-emerald-400 flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 shrink-0" />
                    <div>
                      <span className="font-bold">[NO CONFIRMED VULNERABILITIES]</span>
                      <p className="text-[10px] text-ink-muted mt-0.5">
                        Installed software and network services verified against NVD, OSV, and CISA KEV. Zero active vulnerability matches found.
                      </p>
                    </div>
                  </div>
                );
              }

              return (
                <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                  {verifiedVulns.map((f) => {
                    const isKev = f.in_kev || f.finding_state === "KNOWN_EXPLOITED";
                    const isVuln = f.finding_state === "VULNERABLE";
                    const isExposed = f.finding_state === "EXPOSED";
                    return (
                      <div
                        key={f.finding_id || f.cve_id}
                        className={`rounded border p-2 text-[11px] font-mono space-y-1 ${
                          isKev
                            ? "border-rose-500/50 bg-rose-500/10"
                            : isVuln
                            ? "border-amber-500/40 bg-surface-3"
                            : isExposed
                            ? "border-purple-500/40 bg-purple-500/10"
                            : "border-hairline/60 bg-surface-3"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-bold text-ink">{f.cve_id || f.observed_product}</span>
                            <span
                              className="rounded px-1.5 py-0.2 text-[8.5px] font-bold uppercase"
                              style={{ backgroundColor: `${sevHex(f.severity)}22`, color: sevHex(f.severity) }}
                            >
                              {f.severity} (CVSS {f.cvss.toFixed(1)})
                            </span>
                            <span className="rounded border border-cyan-500/40 bg-cyan-500/10 px-1 py-0.2 text-[8px] font-bold text-cyan-400">
                              {f.evidence_source === "endpoint_software" ? "[ENDPOINT SOFTWARE]" : "[NETWORK SERVICE]"}
                            </span>
                          </div>

                          <div className="flex items-center gap-1 shrink-0">
                            <FindingStateBadge state={f.finding_state} inKev={f.in_kev} />
                          </div>
                        </div>

                        <div className="text-[10px] text-ink-muted truncate">
                          <span className="text-ink-secondary font-medium">{f.observed_product}</span>
                          {f.observed_version && <span className="text-ink-muted"> {f.observed_version}</span>}
                          {f.affected_range_text && <span className="text-ink-muted"> | Range: {f.affected_range_text}</span>}
                          {f.fixed_version_text && <span className="text-emerald-400"> | Fixed in: {f.fixed_version_text}</span>}
                        </div>

                        {f.summary && (
                          <p className="text-[9.5px] text-ink-muted line-clamp-2 leading-relaxed">
                            {f.summary}
                          </p>
                        )}

                        <div className="flex items-center gap-2 pt-0.5 text-[8.5px] text-ink-muted">
                          <span>Intel: {f.intel_sources?.join(", ").toUpperCase() || "NVD"}</span>
                          {f.ghsa_ids && f.ghsa_ids.length > 0 && (
                            <span className="text-purple-300">GHSA: {f.ghsa_ids.join(", ")}</span>
                          )}
                          {f.source_freshness && f.source_freshness !== "live" && (
                            <span className="text-amber-400 uppercase">[{f.source_freshness}]</span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              );
            })()}
          </div>
        )}


        {/* ── Deep scan ──────────────────────────────────────────────── */}
        <div className="mt-4 border-t border-hairline pt-4">
          {phase === "idle" && (
            <div>
              <div className="flex items-center gap-2 text-small text-ink">
                <ScanLine className="h-4 w-4 text-accent-400" />
                <span className="font-medium">Deep vulnerability scan</span>
              </div>
              <p className="mt-1 text-[11px] text-ink-muted">
                Runs a real service/version scan (nmap) of this device, matches detected software
                against real CVEs, and scores it with the same risk engine — right on the map.
              </p>
              <Button
                variant="primary"
                className="mt-3 w-full"
                onClick={() => {
                  setConsented(false);
                  setPhase("consent");
                }}
              >
                <ScanLine className="mr-1.5 h-4 w-4" /> Deep scan for vulnerabilities
              </Button>
            </div>
          )}

          {phase === "consent" && (
            <div className="rounded-md border border-risk-medium/40 bg-risk-medium/[0.06] p-3">
              <div className="flex items-center gap-2 text-small font-medium text-risk-medium">
                <ShieldQuestion className="h-4 w-4" /> Confirm authorization
              </div>
              <p className="mt-1.5 text-[11px] leading-relaxed text-ink-muted">
                A deep scan actively probes <span className="font-mono">{d.ip}</span>. Only scan
                devices you <b>own</b> or are <b>explicitly authorized to test</b>. Drishti is a
                defensive tool — this helps you secure the device, never attack it.
              </p>
              <label className="mt-2.5 flex cursor-pointer items-start gap-2 text-[11px] text-ink-muted">
                <input
                  type="checkbox"
                  className="mt-0.5 accent-accent-500"
                  checked={consented}
                  onChange={(e) => setConsented(e.target.checked)}
                />
                <span>I own this device or am authorized to test it.</span>
              </label>
              <div className="mt-3 flex gap-2">
                <Button
                  variant="primary"
                  className="flex-1"
                  disabled={!consented}
                  onClick={() => {
                    setPhase("scanning");
                    scan.mutate();
                  }}
                >
                  Start deep scan
                </Button>
                <Button variant="ghost" onClick={() => setPhase("idle")}>
                  Cancel
                </Button>
              </div>
            </div>
          )}

          {phase === "scanning" && (
            <LoadingBlock label={`Scanning ${d.ip} — service detection + CVE lookup, this can take up to a minute…`} />
          )}

          {phase === "result" && result && (
            <DeepScanResultView
              result={result}
              onRescan={() => {
                setResult(null);
                setConsented(false);
                setPhase("consent");
              }}
              onClose={onClose}
            />
          )}
        </div>

        {/* ── Live Network Traffic Scanner ──────────────────────────── */}
        <div className="mt-4 border-t border-hairline pt-4">
          <div className="flex items-center gap-2 text-small text-ink">
            <Radio className="h-4 w-4 text-accent-400" />
            <span className="font-medium">Live Network Traffic Scanner</span>
          </div>
          <p className="mt-1 text-[11px] text-ink-muted">
            Start a real-time packet capture on this device's traffic — AI analyses protocol
            distribution, top destinations, behavioural anomalies, and forecasts threats.
          </p>
          <Button
            variant="primary"
            className="mt-3 w-full"
            loading={startTracking.isPending}
            onClick={() => startTracking.mutate()}
          >
            <Radio className="mr-1.5 h-4 w-4" /> Start live traffic scan
          </Button>
        </div>

        <div className="mt-3 rounded-md border border-hairline bg-canvas p-2.5 text-[11px] text-ink-muted">
          Devices are discovered by an ARP/ping sweep of your subnet (presence + identity only). A
          deep scan only runs on the device you explicitly consent to. Drishti never inspects
          another device's traffic.
        </div>
      </div>

      {/* Live Traffic Panel overlay */}
      {trackingSession &&
        createPortal(
          <LiveTrafficPanel
            initialSession={trackingSession}
            onClose={() => setTrackingSession(null)}
          />,
          document.body
        )}
    </div>
  );
}

function DeepScanResultView({
  result: r,
  onRescan,
  onClose,
}: {
  result: DeepScanResult;
  onRescan?: () => void;
  onClose: () => void;
}) {
  // Scan itself couldn't run — clearly distinct from a clean/empty result.
  if (!r.available) {
    return (
      <div className="rounded-md border border-status-open/50 bg-status-open/[0.07] p-3">
        <div className="flex items-center gap-2 text-small font-medium text-status-open">
          <AlertTriangle className="h-4 w-4" /> Scan unavailable
        </div>
        <p className="mt-1.5 text-[11px] text-ink-muted">
          {r.unavailable_reason ?? "The scan could not be completed."}
        </p>
        <p className="mt-1 text-[11px] text-ink-muted">
          No results were produced — this is <b>not</b> a clean bill of health. Fix the cause above
          and rescan.
        </p>
        {onRescan && (
          <Button variant="ghost" className="mt-2" onClick={onRescan}>
            Try again
          </Button>
        )}
      </div>
    );
  }

  const cves = [...r.cves].sort((a, b) => b.cvss - a.cvss);
  const bucket = r.risk_score != null ? riskBucket(r.risk_score) : "safe";
  const riskColor = r.risk_score != null ? RISK_HEX[bucket] : "#6b7a94";

  return (
    <div className="space-y-3">
      {/* engine risk score + path */}
      <div className="flex items-center gap-3 rounded-md border border-hairline bg-canvas p-3">
        <div
          className="flex h-14 w-14 shrink-0 flex-col items-center justify-center rounded-lg font-mono"
          style={{ backgroundColor: `${riskColor}1f`, color: riskColor }}
        >
          <span className="text-h3 font-semibold leading-none">
            {r.risk_score != null ? Math.round(r.risk_score) : "—"}
          </span>
          <span className="mt-0.5 text-[8px] uppercase tracking-wide">risk</span>
        </div>
        <div className="min-w-0 text-[11px]">
          <div className="text-small text-ink">
            Engine risk score for <span className="font-mono">{r.target}</span>
          </div>
          <div className="mt-0.5 text-ink-muted">
            {r.os ? <>OS: {r.os} · </> : null}
            {r.top_path_formed
              ? `On an attack path (path risk ${r.top_path_risk != null ? Math.round(r.top_path_risk) : "—"})`
              : "No attack path from the internet formed for this device."}
          </div>
        </div>
      </div>

      {/* open ports / services */}
      <div>
        <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-medium text-ink-muted">
          <Network className="h-3.5 w-3.5" /> Open ports &amp; services ({r.services.length})
        </div>
        {r.services.length === 0 ? (
          <p className="text-[11px] text-ink-muted">No open ports detected on the top 1000.</p>
        ) : (
          <div className="space-y-1">
            {r.services.map((s) => (
              <div
                key={`${s.port}/${s.protocol}`}
                className="flex items-center gap-2 rounded-sm bg-canvas px-2 py-1 font-mono text-[11px]"
              >
                <span className="text-accent-400">
                  {s.port}/{s.protocol}
                </span>
                <span className="text-ink">{s.service_name}</span>
                <span className="ml-auto truncate text-ink-muted">
                  {[s.product, s.version].filter(Boolean).join(" ") || "version unknown"}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* CVEs */}
      <div>
        <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-medium text-ink-muted">
          <Bug className="h-3.5 w-3.5" /> Matched CVEs ({cves.length})
        </div>
        {r.cve_lookup_unavailable ? (
          <div className="rounded-md border border-status-open/50 bg-status-open/[0.07] p-2.5 text-[11px]">
            <span className="font-medium text-status-open">CVE lookup unavailable</span>
            <span className="text-ink-muted">
              {" "}
              — {r.cve_lookup_reason ?? "the CVE source could not be reached"}. This is not “no
              vulnerabilities” — the check could not run.
            </span>
          </div>
        ) : cves.length === 0 ? (
          <p className="rounded-md border border-hairline bg-canvas p-2.5 text-[11px] text-ink-muted">
            No known CVEs matched the detected service versions. (Absence of a match isn’t proof of
            safety — only that the source had nothing for these versions.)
          </p>
        ) : (
          <div className="space-y-1.5">
            {cves.map((c) => (
              <CveItem key={c.id} cve={c} onNavigate={onClose} />
            ))}
          </div>
        )}
      </div>

      {onRescan && (
        <Button variant="ghost" className="w-full" onClick={onRescan}>
          <ScanLine className="mr-1.5 h-4 w-4" /> Rescan
        </Button>
      )}
    </div>
  );
}

function CveItem({ cve: c, onNavigate }: { cve: DeepScanCve; onNavigate: () => void }) {
  const color = sevHex(c.severity);
  return (
    <div className="rounded-md border border-hairline bg-canvas p-2.5" style={{ borderLeft: `3px solid ${color}` }}>
      <div className="flex items-center gap-2">
        <span
          className="rounded-sm px-1.5 py-0.5 text-[9px] font-semibold uppercase"
          style={{ backgroundColor: `${color}22`, color }}
        >
          {c.severity}
        </span>
        <span className="font-mono text-[11px] text-ink">{c.id}</span>
        <span className="font-mono text-[10px] text-ink-muted">CVSS {c.cvss.toFixed(1)}</span>
        <span className="ml-auto truncate font-mono text-[10px] text-ink-muted" title={c.affected_service}>
          {c.affected_service}
        </span>
      </div>
      {c.summary && <p className="mt-1 line-clamp-2 text-[11px] text-ink-muted">{c.summary}</p>}
      {c.finding_id && (
        <Link
          to={`/app/remediate/${c.finding_id}`}
          onClick={onNavigate}
          className="mt-1.5 inline-flex items-center gap-1 text-[11px] text-accent-400 hover:text-accent-300"
        >
          <Terminal className="h-3 w-3" /> Generate fix <ExternalLink className="h-3 w-3" />
        </Link>
      )}
    </div>
  );
}

function ManualCheck({ onDone }: { onDone: () => void }) {
  const [url, setUrl] = useState("");
  const toast = useToast();
  const check = useMutation({
    mutationFn: (u: string) => api.liveCheck(u),
    onSuccess: (r) => {
      toast.show(
        r.is_threat ? `⚠ ${r.domain} — ${r.band}` : `${r.domain} — ${r.band}`,
        r.is_threat ? "error" : "success",
      );
      setUrl("");
      onDone();
    },
    onError: () => toast.show("Couldn't analyze that URL", "error"),
  });
  return (
    <Card className="flex flex-wrap items-center gap-3 p-4">
      <div className="flex items-center gap-2 text-small text-ink-muted">
        <Globe className="h-4 w-4 text-accent-400" /> Check any URL instantly
      </div>
      <form
        className="flex flex-1 items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (url.trim()) check.mutate(url.trim());
        }}
      >
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="e.g. eicar.org"
          className="min-w-0 flex-1 rounded-md border border-hairline bg-canvas px-3 py-1.5 font-mono text-small text-ink outline-none focus:border-accent-500"
        />
        <Button type="submit" loading={check.isPending}>
          Analyze
        </Button>
      </form>
    </Card>
  );
}

function Legend({ hex, label }: { hex: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-2 rounded border border-hairline/70 bg-surface-1/90 px-2.5 py-1 font-mono text-[10px] uppercase font-bold tracking-wider text-ink-secondary shadow-sm">
      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: hex, boxShadow: `0 0 6px ${hex}` }} />
      {label}
    </span>
  );
}

function RadarGrid({
  threats,
  onPick,
  selected,
}: {
  threats: LiveThreat[];
  onPick: (t: LiveThreat) => void;
  selected: LiveThreat | null;
}) {
  const [filter, setFilter] = useState<"realtime" | "threats" | "all">("all");
  const [search, setSearch] = useState("");

  const now = Date.now();
  const fiveMinAgo = now - 5 * 60 * 1000;

  const filtered = useMemo(() => {
    return threats.filter((t) => {
      if (search.trim() && !t.domain.toLowerCase().includes(search.toLowerCase().trim())) {
        return false;
      }
      if (filter === "threats") {
        return t.band !== "Trusted";
      }
      if (filter === "realtime") {
        const lastSeenMs = new Date(t.last_seen).getTime();
        return lastSeenMs >= fiveMinAgo;
      }
      return true;
    });
  }, [threats, filter, search]);

  const realTimeCount = threats.filter((t) => new Date(t.last_seen).getTime() >= fiveMinAgo).length;
  const threatCount = threats.filter((t) => t.band !== "Trusted").length;

  // risky first, so the dangerous ones sit at the top of the grid
  const ordered = useMemo(() => [...filtered].sort((a, b) => a.score - b.score), [filtered]);

  const [visibleThreatCount, setVisibleThreatCount] = useState(12);

  // Progressive slicing for optimal load performance
  const displayedThreats = useMemo(() => ordered.slice(0, visibleThreatCount), [ordered, visibleThreatCount]);

  return (
    <div className="space-y-3">
      {/* ── Filter Bar ────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-hairline bg-surface-1/50 p-2">
        <div className="flex items-center gap-1">
          <button
            onClick={() => { setFilter("all"); setVisibleThreatCount(12); }}
            className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
              filter === "all"
                ? "bg-accent-500/15 text-accent-400 font-semibold"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            All Activity ({threats.length})
          </button>
          <button
            onClick={() => { setFilter("realtime"); setVisibleThreatCount(12); }}
            className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
              filter === "realtime"
                ? "bg-accent-500/15 text-accent-400 font-semibold"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-risk-safe animate-pulse" />
            Real-Time 5m ({realTimeCount})
          </button>
          <button
            onClick={() => { setFilter("threats"); setVisibleThreatCount(12); }}
            className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
              filter === "threats"
                ? "bg-risk-critical/15 text-risk-critical font-semibold"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            <ShieldAlert className="h-3 w-3" />
            Threats Only ({threatCount})
          </button>
        </div>

        <div className="flex items-center">
          <input
            type="text"
            placeholder="Search domain..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setVisibleThreatCount(12); }}
            className="rounded border border-hairline bg-surface-2 px-2 py-0.5 font-mono text-[11px] text-ink placeholder-ink-muted/60 outline-none focus:border-accent-500"
          />
        </div>
      </div>

      {ordered.length === 0 ? (
        <div className="rounded-node border border-hairline bg-surface-2 p-8 text-center text-small text-ink-muted">
          No domains matched the selected filter ({filter}).
        </div>
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {displayedThreats.map((t) => {
              const hex = hexFor(t.band);
              const risky = t.band !== "Trusted";
              const isLive = new Date(t.last_seen).getTime() >= fiveMinAgo;
              const active = selected?.id === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => onPick(t)}
                  className={`group relative flex flex-col items-start gap-2 rounded-node border bg-surface-2 p-3 text-left transition-all hover:-translate-y-0.5 ${
                    active ? "border-accent-500" : "border-hairline hover:border-hairline-soft"
                  }`}
                  style={{ borderLeft: `3px solid ${hex}` }}
                >
                  {risky && (
                    <span
                      aria-hidden
                      className="absolute right-2 top-2 h-2 w-2 rounded-full"
                      style={{ backgroundColor: hex, boxShadow: `0 0 0 4px ${hex}22` }}
                    />
                  )}
                  <div className="flex w-full items-center justify-between">
                    <span
                      className="flex h-7 w-7 items-center justify-center rounded-md"
                      style={{ backgroundColor: `${hex}1f`, color: hex }}
                    >
                      {risky ? <ShieldAlert className="h-3.5 w-3.5" /> : <Globe className="h-3.5 w-3.5" />}
                    </span>
                    {isLive && (
                      <span className="flex items-center gap-1 rounded bg-risk-safe/10 px-1.5 py-0.5 text-[8px] font-semibold text-risk-safe">
                        <span className="h-1.5 w-1.5 rounded-full bg-risk-safe animate-pulse" />
                        LIVE
                      </span>
                    )}
                  </div>
                  <span className="w-full truncate font-mono text-small text-ink font-medium" title={t.domain}>
                    {t.domain}
                  </span>
                  <span className="flex w-full items-center justify-between font-mono text-[10px] text-ink-muted">
                    <span style={{ color: hex }} className="font-semibold">{t.band}</span>
                    <span>×{t.hit_count} hits</span>
                  </span>

                  {/* ── Source Device IP / Host Badge ─────────────── */}
                  {t.source_host && (
                    <div className="flex w-full items-center gap-1.5 font-mono text-[10px] text-ink-secondary border-t border-hairline/40 pt-1.5 mt-0.5 truncate bg-black/5 rounded px-1.5 py-0.5">
                      <Laptop className="h-3 w-3 shrink-0 text-accent-400" />
                      <span className="truncate" title={`Client device: ${t.source_host}`}>
                        {t.source_host}
                      </span>
                    </div>
                  )}
                </button>
              );
            })}
          </div>

          {/* Progressive Load More Trigger */}
          {visibleThreatCount < ordered.length && (
            <div className="flex flex-col items-center justify-center gap-2 pt-2 border-t border-hairline/30">
              <span className="text-[11px] font-mono text-ink-muted">
                Showing {displayedThreats.length} of {ordered.length} live requests
              </span>
              <button
                onClick={() => setVisibleThreatCount((c) => Math.min(c + 12, ordered.length))}
                className="flex items-center gap-1.5 rounded-lg border border-hairline bg-surface-2 px-4 py-1.5 text-xs font-semibold text-ink-primary hover:bg-surface-3 hover:border-accent-500/40 transition-all shadow-xs"
              >
                <RefreshCw className="h-3 w-3 text-accent-400" />
                Load more requests (+{Math.min(12, ordered.length - visibleThreatCount)} remaining)
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ThreatDetail({ threat: t, onClose }: { threat: LiveThreat; onClose: () => void }) {
  const hex = hexFor(t.band);
  const toast = useToast();
  const qc = useQueryClient();
  const [tab, setTab] = useState<"summary" | "technical" | "remediation">("summary");
  const block = useMutation({
    mutationFn: () => api.liveBlock(encodeURIComponent(t.domain || t.id)),
    onError: (e) => toast.show(e instanceof ApiError ? e.message : "Couldn't generate a block command", "error"),
  });

  const resolveThreat = useMutation({
    mutationFn: () => api.resolveLiveThreat(encodeURIComponent(t.domain || t.id)),
    onSuccess: () => {
      toast.show(`Threat for ${t.domain} marked as Solved & Resolved`, "success");
      qc.invalidateQueries({ queryKey: ["live", "threats"] });
      qc.invalidateQueries({ queryKey: ["live", "devices"] });
      qc.invalidateQueries({ queryKey: ["live", "network-threats"] });
      onClose();
    },
    onError: () => toast.show("Couldn't resolve threat", "error"),
  });

  const vj = t.verdict_json || {};
  const website = vj.website || {};
  const providers = vj.providers || {};
  const signals = (vj.signals || []) as Array<{ label: string; status: string; detail: string; key: string }>;
  const aiSummary = vj.ai_summary;
  const tls = website.tls || {};
  const sb = providers.safe_browsing || {};
  const vt = providers.virustotal || {};

  return (
    <Card className="p-5 space-y-4">
      <div className="flex items-start justify-between gap-2 border-b border-hairline pb-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-3 w-3 rounded-full" style={{ backgroundColor: hex }} />
            <span className="font-mono text-h3 text-ink font-semibold">{t.domain}</span>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-ink-muted">
            <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase" style={{ backgroundColor: `${hex}22`, color: hex }}>
              {t.band}
            </span>
            <span>Score: <b className="font-mono text-ink">{t.score}</b>/100</span>
            <span>· Hits: <b className="font-mono text-ink">×{t.hit_count}</b></span>
            {t.source_host && <span>· Host: <b className="font-mono text-ink-secondary">{t.source_host}</b></span>}
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => resolveThreat.mutate()}
            disabled={resolveThreat.isPending}
            className="flex items-center gap-1 rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-1 text-[11px] font-semibold text-emerald-400 hover:bg-emerald-500/20 transition-colors"
            title="Mark this threat as resolved / solved"
          >
            <CheckCircle2 className="h-3.5 w-3.5" />
            <span>{resolveThreat.isPending ? "Solving..." : "Solved"}</span>
          </button>
          <button onClick={onClose} className="text-ink-muted hover:text-ink p-1" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-1 border-b border-hairline pb-2">
        <button
          onClick={() => setTab("summary")}
          className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
            tab === "summary" ? "bg-accent-500/15 text-accent-400 font-semibold" : "text-ink-muted hover:text-ink"
          }`}
        >
          Overview &amp; AI
        </button>
        <button
          onClick={() => setTab("technical")}
          className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
            tab === "technical" ? "bg-accent-500/15 text-accent-400 font-semibold" : "text-ink-muted hover:text-ink"
          }`}
        >
          Technical Signals ({signals.length})
        </button>
        <button
          onClick={() => setTab("remediation")}
          className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
            tab === "remediation" ? "bg-accent-500/15 text-accent-400 font-semibold" : "text-ink-muted hover:text-ink"
          }`}
        >
          Remediation &amp; Block
        </button>
      </div>

      {/* Tab 1: Summary & AI Analysis */}
      {tab === "summary" && (
        <div className="space-y-3">
          {aiSummary && (
            <div className="rounded-md border border-accent-500/30 bg-accent-500/10 p-3 text-[12px] leading-relaxed text-ink">
              <div className="mb-1 flex items-center gap-1.5 font-medium text-accent-400">
                <Zap className="h-3.5 w-3.5" /> AI Threat Assessment
              </div>
              <p>{aiSummary}</p>
            </div>
          )}

          {t.reasons.length > 0 ? (
            <div>
              <div className="mb-1.5 flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-ink-muted font-medium">
                <ShieldAlert className="h-3.5 w-3.5" /> Core Risk Signals
              </div>
              <ul className="space-y-1">
                {t.reasons.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-small text-ink-secondary">
                    <span className="mt-1 h-1.5 w-1.5 rounded-full shrink-0" style={{ backgroundColor: hex }} />
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="flex items-center gap-2 rounded-md border border-risk-safe/25 bg-risk-safe/5 p-3 text-small text-ink-muted">
              <ShieldCheck className="h-4 w-4 text-risk-safe shrink-0" /> Clean reputation checks — no risk signals detected.
            </div>
          )}

          {/* Quick Rep Stats */}
          <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
            <div className="rounded-md border border-hairline bg-canvas p-2.5">
              <div className="text-ink-muted font-medium">Safe Browsing</div>
              <div className="mt-1 font-semibold text-ink">
                {sb.configured ? (sb.verdict === "flagged" ? "⚠️ FLAGGED" : "Clean") : "Not configured"}
              </div>
            </div>
            <div className="rounded-md border border-hairline bg-canvas p-2.5">
              <div className="text-ink-muted font-medium">VirusTotal</div>
              <div className="mt-1 font-semibold text-ink">
                {vt.configured ? (vt.malicious > 0 ? `⚠️ ${vt.malicious} detections` : "Clean (0/90)") : "Not configured"}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Deep Technical Breakdown */}
      {tab === "technical" && (
        <div className="space-y-3 text-[11px]">
          {/* Domain & Certificate Facts */}
          <div className="rounded-md border border-hairline bg-canvas p-3 space-y-2">
            <div className="font-semibold text-ink flex items-center gap-1.5">
              <Globe className="h-3.5 w-3.5 text-accent-400" /> Infrastructure Facts
            </div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-ink-secondary">
              <div>Host: <span className="font-mono text-ink">{website.host || t.domain}</span></div>
              <div>HTTPS: <span className="font-mono text-ink">{website.https ? "Yes" : "No"}</span></div>
              <div>Domain Age: <span className="font-mono text-ink">{website.domain_age_days ? `${website.domain_age_days} days` : "Unknown"}</span></div>
              <div>Registrar: <span className="font-mono text-ink">{website.registrar || "Unknown"}</span></div>
              <div>TLS Issuer: <span className="font-mono text-ink">{tls.issuer || "None"}</span></div>
              <div>TLS Status: <span className="font-mono text-ink">{tls.valid ? "Valid" : "Invalid/None"}</span></div>
            </div>
          </div>

          {/* Evaluated Signals List */}
          {signals.length > 0 && (
            <div>
              <div className="mb-1.5 font-semibold text-ink text-[11px]">Evaluated Signal Audit ({signals.length})</div>
              <div className="space-y-1 max-h-56 overflow-y-auto pr-1">
                {signals.map((s, idx) => {
                  const statusColor = s.status === "pass" ? RISK_HEX.safe : s.status === "warn" ? RISK_HEX.medium : s.status === "fail" ? RISK_HEX.critical : "#6b7a94";
                  return (
                    <div key={idx} className="flex items-start justify-between gap-2 rounded border border-hairline bg-surface-2 p-2">
                      <div>
                        <div className="font-medium text-ink flex items-center gap-1.5">
                          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: statusColor }} />
                          {s.label}
                        </div>
                        <div className="text-ink-muted text-[10px] mt-0.5">{s.detail}</div>
                      </div>
                      <span className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase" style={{ backgroundColor: `${statusColor}22`, color: statusColor }}>
                        {s.status}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Remediation & Executable Block */}
      {tab === "remediation" && (
        <div className="space-y-3">
          <p className="text-small text-ink-muted">
            Generate concrete, OS-specific terminal block commands to neutralize traffic to <b className="font-mono text-ink">{t.domain}</b>.
          </p>
          <Button loading={block.isPending} onClick={() => block.mutate()} className="w-full">
            <Terminal className="h-4 w-4" /> {block.data ? "Regenerate AI Block Commands" : "Generate Live AI Block Commands"}
          </Button>
          {block.data && !block.data.refused && (
            <BlockView
              fix={block.data}
              onResolve={() => resolveThreat.mutate()}
              resolving={resolveThreat.isPending}
            />
          )}
        </div>
      )}

      {/* Bottom CTA if on overview tab */}
      {tab === "summary" && (
        <div className="pt-2 border-t border-hairline flex flex-col gap-2">
          {t.band !== "Trusted" && (
            <Button loading={block.isPending} onClick={() => { setTab("remediation"); block.mutate(); }} className="w-full">
              <Terminal className="h-4 w-4" /> Generate AI Block Command
            </Button>
          )}
          <Button
            variant="ghost"
            loading={resolveThreat.isPending}
            onClick={() => resolveThreat.mutate()}
            className="w-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20 font-semibold"
          >
            <CheckCircle2 className="h-4 w-4 mr-1.5" /> Mark Threat Resolved &amp; Solved
          </Button>
        </div>
      )}
    </Card>
  );
}


function BlockView({
  fix,
  onResolve,
  resolving,
}: {
  fix: BlockFix;
  onResolve?: () => void;
  resolving?: boolean;
}) {
  const toast = useToast();
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [copied, setCopied] = useState(false);

  const activeCmd = fix.commands[selectedIdx] || fix.commands[0];

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast.show("Command copied to clipboard", "success");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.show("Couldn't copy to clipboard", "error");
    }
  };

  const platformLabels: Record<string, string> = {
    hosts: "Hosts File",
    linux: "Linux (UFW / iptables)",
    macos: "macOS (Packet Filter)",
    windows: "Windows PowerShell",
    pihole: "DNS / Pi-hole",
    router: "Router (MikroTik / VyOS)",
  };

  return (
    <div className="mt-4 space-y-3.5">
      {/* AI Summary Banner */}
      <div className="rounded-lg border border-accent-500/25 bg-accent-500/10 p-3 text-[12px] leading-relaxed text-ink">
        <div className="flex items-center gap-1.5 font-semibold text-accent-400 mb-1">
          <Terminal className="h-3.5 w-3.5" /> AI Containment Strategy
        </div>
        <p className="text-ink-secondary">{fix.summary}</p>
        {fix.why_risky && fix.why_risky.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {fix.why_risky.map((r, i) => (
              <span key={i} className="rounded bg-black/40 px-2 py-0.5 font-mono text-[10px] text-ink-muted border border-white/5">
                • {r}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Platform Selector Tabs */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-hairline pb-2">
        {fix.commands.map((c, i) => (
          <button
            key={i}
            onClick={() => { setSelectedIdx(i); setCopied(false); }}
            className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-all ${
              selectedIdx === i
                ? "bg-accent-500 text-white font-semibold shadow-sm"
                : "bg-surface-2 text-ink-muted hover:text-ink hover:bg-surface-3"
            }`}
          >
            {platformLabels[c.platform] || c.platform.toUpperCase()}
          </button>
        ))}
      </div>

      {/* Terminal View for Active Command */}
      {activeCmd && (
        <div className="rounded-lg border border-white/10 bg-[#0d100d] overflow-hidden shadow-lg">
          {/* Terminal Bar */}
          <div className="flex items-center justify-between border-b border-white/10 bg-[#161a16] px-3 py-1.5">
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5">
                <div className="h-2 w-2 rounded-full bg-[#ff5f56]" />
                <div className="h-2 w-2 rounded-full bg-[#ffbd2e]" />
                <div className="h-2 w-2 rounded-full bg-[#27c93f]" />
              </div>
              <span className="font-mono text-[10px] uppercase font-semibold text-accent-400">
                {activeCmd.platform}
              </span>
            </div>
            <button
              onClick={() => copy(activeCmd.command)}
              className="flex items-center gap-1.5 rounded bg-white/10 px-2.5 py-1 text-[11px] font-mono text-ink-primary hover:bg-white/20 transition-colors"
            >
              {copied ? (
                <>
                  <Check className="h-3 w-3 text-emerald-400" />
                  <span className="text-emerald-400">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="h-3 w-3" />
                  <span>Copy</span>
                </>
              )}
            </button>
          </div>

          {/* Terminal Body */}
          <pre className="overflow-x-auto p-3 font-mono text-[12px] leading-relaxed text-[#f2efe7] selection:bg-accent-500 selection:text-white">
            {activeCmd.command}
          </pre>
        </div>
      )}

      {/* Resolution & Status Actions Box */}
      {onResolve && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3.5 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-emerald-400 flex items-center gap-1.5">
              <CheckCircle2 className="h-4 w-4" /> Containment Verification
            </span>
            <span className="text-[10px] font-mono text-ink-muted">Action Ready</span>
          </div>
          <p className="text-[11px] text-ink-secondary">
            After running the block rule on your firewall or hosts file, mark this threat as solved to dismiss it from active risk feeds.
          </p>
          <Button
            loading={resolving}
            onClick={onResolve}
            className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-2 shadow-sm justify-center"
          >
            <CheckCircle2 className="h-4 w-4 mr-1.5" /> Mark Threat Resolved &amp; Solved
          </Button>
        </div>
      )}

      {/* Safety Guardrail Footer */}
      <div className="flex items-start gap-2 rounded-md border border-emerald-500/20 bg-emerald-500/5 p-2.5 text-[11px] text-ink-muted">
        <Activity className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
        <div>
          <span className="font-medium text-emerald-400">Defensive Containment Verified: </span>
          {fix.disclaimer || "Blocks outbound traffic to this specific domain only without affecting normal subnet routing."}
        </div>
      </div>
    </div>
  );
}
