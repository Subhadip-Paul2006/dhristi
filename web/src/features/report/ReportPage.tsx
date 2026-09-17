// Drishti v0.1 — network intelligence report | 11-Jul-2026
/** Whole-network intelligence: AI executive summary, risk-band distribution,
 * high-severity CVE table, and unsupervised ML (IsolationForest anomalies +
 * KMeans segments). All data is real engine output — nothing invented. */
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowRight,
  Boxes,
  BrainCircuit,
  Lock,
  Network,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Wrench,
} from "lucide-react";
import { api } from "../../api/client";
import type { CveRow, NodeHardening, RiskBand, SecuritySegment } from "../../api/types";
import { NetworkConfigSection } from "./NetworkConfigSection";
import { Button } from "../../components/Button";
import { SeverityBadge } from "../../components/SeverityBadge";
import { EmptyState, ErrorState, LoadingBlock, Skeleton } from "../../components/primitives";
import { Panel, StatReadout } from "../../components/ui/console";
import { RISK_HEX, riskBucket, type RiskToken } from "../../lib/format";

const BAND_TOKEN: Record<string, RiskToken> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  safe: "safe",
};
const BAND_LABEL: Record<string, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  safe: "SAFE",
};
const SEG_HEX: Record<string, string> = {
  HIGH: RISK_HEX.high,
  MEDIUM: RISK_HEX.medium,
  LOW: RISK_HEX.safe,
};

export function ReportPage() {
  return (
    <div className="console-atmos min-h-screen">
      <div className="mx-auto max-w-5xl space-y-6 p-4 sm:p-6 lg:p-8">
        <header className="border-b border-hairline/60 pb-6 mb-2">
          <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-accent-400">
            <span className="inline-block h-2 w-2 rounded-full bg-accent-500 shadow-[0_0_8px_#00ff66] animate-pulse" />
            <span>SYS.REPORT // NETWORK_ASSESSMENT_TELEMETRY</span>
          </div>
          <h1 className="mt-2 font-display text-display font-semibold tracking-tight text-ink-primary">
            Defensive Network Intelligence Report
          </h1>
          <p className="mt-1.5 max-w-2xl font-mono text-small text-ink-secondary">
            Deterministic risk audit, IsolationForest anomalies, KMeans topological clusters, and automated CVSS hardening playbooks.
          </p>
        </header>

          <AssessmentHeader />
        <ExecutiveSummary />
        <NetworkConfigSection />
        <HardeningSection />
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <DistributionCard />
          <MlSegments />
        </div>
        <CveTable />
        <MlAnomalies />
      </div>
    </div>
  );
}

// ── Assessment header — at-a-glance stats over real engine output ────────────
function AssessmentHeader() {
  const dist = useQuery({ queryKey: ["report", "dist"], queryFn: () => api.reportDistribution() });
  const cves = useQuery({ queryKey: ["report", "cves"], queryFn: () => api.reportCves() });
  const hard = useQuery({ queryKey: ["report", "hardening"], queryFn: () => api.reportHardening() });

  const critHigh =
    dist.data?.bands
      .filter((b) => b.band === "critical" || b.band === "high")
      .reduce((s, b) => s + b.count, 0) ?? null;
  const top = hard.data?.[0];

  const tiles: { label: string; value: string; hint?: string }[] = [
    { label: "Devices scanned", value: dist.data ? String(dist.data.total_assets) : "…" },
    {
      label: "Avg vulnerability",
      value: dist.data ? `${dist.data.average_risk}/100` : "…",
    },
    { label: "Unique CVEs", value: cves.data ? String(cves.data.length) : "…" },
    { label: "Critical + high", value: critHigh != null ? String(critHigh) : "…" },
    {
      label: "Highest-risk device",
      value: top ? (top.hostname ?? top.ip) : "…",
      hint: top ? `score ${top.current_score.toFixed(1)}` : undefined,
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      {tiles.map((t) => (
        <StatReadout key={t.label} label={t.label} className="!py-3.5">
          <span className="block truncate text-[1.35rem]">{t.value}</span>
          {t.hint && (
            <span className="mt-1 block font-mono text-[10px] font-normal uppercase tracking-[0.1em] text-ink-muted">
              {t.hint}
            </span>
          )}
        </StatReadout>
      ))}
    </div>
  );
}

// ── C2: engine-grounded node hardening (real quantified deltas) ──────────────
const ACTION_ICON: Record<string, typeof Lock> = {
  CLOSE_PORT: Lock,
  PATCH: Wrench,
  VLAN_SEGMENT: Network,
  ISOLATE_CONNECTION: Network,
};

function HardeningSection() {
  const q = useQuery({ queryKey: ["report", "hardening"], queryFn: () => api.reportHardening() });
  return (
    <Panel
      index="02"
      eyebrow="Remediation · measured deltas"
      title="Node hardening plan"
      icon={ShieldCheck}
      tone="safe"
    >
      <p className="-mt-1 mb-4 max-w-2xl text-[11px] text-ink-muted">
        Every reduction is <span className="text-ink-secondary">measured, not estimated</span> — the
        engine is re-run with each change applied and reports the actual drop in risk score.
      </p>
      {q.isLoading && <Skeleton className="h-40" />}
      {q.isError && <ErrorState message="Couldn't load hardening plan." onRetry={() => q.refetch()} />}
      {q.data && q.data.length === 0 && <EmptyState title="No high-risk nodes to harden." />}
      {q.data && q.data.length > 0 && (
        <div className="space-y-4">
          {q.data.map((n) => (
            <HardeningNode key={n.ip} node={n} />
          ))}
        </div>
      )}
    </Panel>
  );
}

function HardeningNode({ node: n }: { node: NodeHardening }) {
  const beforeHex = RISK_HEX[riskBucket(n.current_score)];
  const afterHex = RISK_HEX[riskBucket(n.projected_score)];
  return (
    <div className="rounded-md border border-edge-subtle p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-body text-ink-primary">{n.hostname ?? n.ip}</span>
          <span className="font-mono text-[11px] text-ink-muted">{n.ip}</span>
        </div>
        <div className="flex items-center gap-2 text-small">
          <span className="font-mono" style={{ color: beforeHex }}>
            {n.current_score.toFixed(1)}
          </span>
          <ArrowRight className="h-3.5 w-3.5 text-ink-muted" />
          <span className="font-mono" style={{ color: afterHex }}>
            {n.projected_score.toFixed(1)}
          </span>
          <span className="rounded-sm bg-risk-safe/15 px-1.5 py-0.5 text-[11px] font-medium text-risk-safe">
            ↓ {n.reduction_pct}%
          </span>
          <span className="text-[11px] text-ink-muted">
            {n.band_before} → {n.band_after}
          </span>
        </div>
      </div>
      <ul className="mt-3 space-y-1.5">
        {n.actions.map((a, i) => {
          const Icon = ACTION_ICON[a.kind] ?? Wrench;
          return (
            <li key={i} className="flex items-center gap-2 text-small text-ink-secondary">
              <Icon className="h-3.5 w-3.5 shrink-0 text-accent-400" />
              <span className="rounded-sm border border-edge-subtle px-1.5 py-0.5 font-mono text-[10px] text-ink-muted">
                {a.kind}
              </span>
              <span className="flex-1">{a.label}</span>
              <span className="shrink-0 font-mono text-[11px] text-risk-safe">
                ~{a.risk_reduction_pct}%
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// ── A3: AI executive summary ─────────────────────────────────────────────────
function ExecutiveSummary() {
  const gen = useMutation({ mutationFn: () => api.reportSummary() });
  const s = gen.data;
  return (
    <Panel
      index="01"
      eyebrow="Narrative · AI-drafted"
      title="Executive threat narrative"
      icon={BrainCircuit}
      meta={
        <Button loading={gen.isPending} onClick={() => gen.mutate()}>
          <Sparkles className="h-4 w-4" /> {s ? "Regenerate" : "Generate summary"}
        </Button>
      }
    >
      {gen.isPending && (
        <div className="mt-4">
          <LoadingBlock label="Analyzing the whole network…" />
        </div>
      )}
      {!s && !gen.isPending && (
        <p className="mt-4 text-small text-ink-muted">
          Generate a board-ready summary of the network's systemic risks and priority actions.
        </p>
      )}
      {s && !s.refused && (
        <div className="mt-4 space-y-4">
          <div className="text-body text-ink-primary">{s.headline}</div>
          <p className="text-small leading-relaxed text-ink-secondary">{s.narrative}</p>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <ListBlock title="Top systemic risks" icon={ShieldAlert} items={s.top_risks} />
            <ListBlock title="Priority actions" icon={AlertTriangle} items={s.priority_actions} />
          </div>
        </div>
      )}
      {s?.refused && (
        <p className="mt-4 text-small text-ink-muted">{s.reason ?? "Could not summarize."}</p>
      )}
    </Panel>
  );
}

function ListBlock({
  title,
  items,
  icon: Icon,
}: {
  title: string;
  items: string[];
  icon: typeof ShieldAlert;
}) {
  return (
    <div className="rounded-md border border-edge-subtle p-3">
      <div className="mb-2 flex items-center gap-1.5 text-[11px] uppercase tracking-[0.02em] text-ink-muted">
        <Icon className="h-3.5 w-3.5" /> {title}
      </div>
      <ul className="space-y-1.5">
        {items.map((it, i) => (
          <li key={i} className="flex gap-2 text-small text-ink-secondary">
            <span className="text-ink-muted">•</span> {it}
          </li>
        ))}
      </ul>
    </div>
  );
}

// ── A2: risk-band distribution ───────────────────────────────────────────────
function DistributionCard() {
  const q = useQuery({ queryKey: ["report", "dist"], queryFn: () => api.reportDistribution() });
  return (
    <Panel
      index="03"
      eyebrow="Fleet · risk bands"
      title="Risk distribution"
      meta={
        q.data ? (
          <span className="font-mono text-[11px] text-ink-muted">
            avg <span className="text-ink-secondary">{q.data.average_risk}</span>/100 ·{" "}
            {q.data.total_assets} assets
          </span>
        ) : undefined
      }
    >
      {q.isLoading && <Skeleton className="mt-1 h-32" />}
      {q.isError && <ErrorState message="Couldn't load distribution." onRetry={() => q.refetch()} />}
      {q.data && (
        <div className="space-y-3">
          {q.data.bands.map((b) => (
            <BandBar key={b.band} band={b} />
          ))}
        </div>
      )}
    </Panel>
  );
}

function BandBar({ band }: { band: RiskBand }) {
  const hex = RISK_HEX[BAND_TOKEN[band.band] ?? "safe"];
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-small">
        <span className="flex items-center gap-2 text-ink-secondary">
          <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: hex }} />
          {BAND_LABEL[band.band] ?? band.band}
        </span>
        <span className="font-mono text-ink-muted">
          {band.count} · {band.pct}%
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-bg-raised">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${band.pct}%`, backgroundColor: hex }}
        />
      </div>
    </div>
  );
}

// ── A1: high-severity CVE table ──────────────────────────────────────────────
function CveTable() {
  const q = useQuery({ queryKey: ["report", "cves"], queryFn: () => api.reportCves() });
  return (
    <Panel index="05" eyebrow="Findings · aggregated" title="High-severity CVEs detected" icon={ShieldAlert} tone="critical">
      {q.isLoading && <Skeleton className="h-40" />}
      {q.isError && <ErrorState message="Couldn't load CVEs." onRetry={() => q.refetch()} />}
      {q.data && q.data.length === 0 && <EmptyState title="No open findings." />}
      {q.data && q.data.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-small">
            <thead>
              <tr className="border-b border-edge-subtle text-left text-[11px] uppercase tracking-[0.02em] text-ink-muted">
                <th className="py-2 pr-3 font-medium">CVE</th>
                <th className="py-2 pr-3 font-medium">CVSS</th>
                <th className="py-2 pr-3 font-medium">Title</th>
                <th className="py-2 pr-3 font-medium">Affected hosts</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((r) => (
                <CveRowView key={(r.cve_id ?? "") + r.title} row={r} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function CveRowView({ row }: { row: CveRow }) {
  return (
    <tr className="border-b border-edge-subtle/60 align-top">
      <td className="py-2.5 pr-3 font-mono text-ink-secondary">{row.cve_id ?? "—"}</td>
      <td className="py-2.5 pr-3">
        <SeverityBadge severity={row.severity} score={row.cvss} />
      </td>
      <td className="py-2.5 pr-3 text-ink-primary">{row.title}</td>
      <td className="py-2.5 pr-3 text-ink-secondary">
        <span className="font-mono text-ink-muted">×{row.affected_count}</span>{" "}
        {row.affected.map((h) => h.hostname ?? h.ip).join(", ")}
      </td>
    </tr>
  );
}

// ── B2: KMeans security segments ─────────────────────────────────────────────
function MlSegments() {
  const q = useQuery({ queryKey: ["report", "ml"], queryFn: () => api.reportMl() });
  return (
    <Panel index="04" eyebrow="Unsupervised · KMeans" title="Security segments" icon={Boxes}>
      {q.isLoading && <Skeleton className="h-32" />}
      {q.isError && <ErrorState message="Couldn't load ML analysis." onRetry={() => q.refetch()} />}
      {q.data && !q.data.available && (
        <p className="text-small text-ink-muted">{q.data.algorithm_note}</p>
      )}
      {q.data?.available && (
        <div className="space-y-2.5">
          {q.data.segments.map((s) => (
            <SegmentRow key={s.segment} seg={s} />
          ))}
        </div>
      )}
    </Panel>
  );
}

function SegmentRow({ seg }: { seg: SecuritySegment }) {
  const hex = SEG_HEX[seg.label] ?? RISK_HEX.safe;
  return (
    <div className="rounded-md border border-edge-subtle p-3">
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-2 text-small text-ink-primary">
          <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: hex }} />
          Segment {seg.segment}
          <span
            className="rounded-sm px-1.5 py-0.5 text-[10px] font-medium"
            style={{ backgroundColor: `${hex}22`, color: hex }}
          >
            {seg.label}
          </span>
        </span>
        <span className="font-mono text-small text-ink-secondary">risk {seg.risk_pct}%</span>
      </div>
      <div className="mt-1.5 text-[11px] text-ink-muted">{seg.members.join(", ")}</div>
    </div>
  );
}

// ── B1: IsolationForest anomalies ────────────────────────────────────────────
function MlAnomalies() {
  const q = useQuery({ queryKey: ["report", "ml"], queryFn: () => api.reportMl() });
  return (
    <Panel index="06" eyebrow="Unsupervised · IsolationForest" title="Anomalous nodes" icon={BrainCircuit} tone="critical">
      <p className="-mt-1 mb-3 text-[11px] text-ink-muted">
        Outlier assets vs the fleet's risk / exposure profile.
      </p>
      {q.isLoading && <Skeleton className="h-32" />}
      {q.data && !q.data.available && (
        <p className="text-small text-ink-muted">{q.data.algorithm_note}</p>
      )}
      {q.data?.available && q.data.anomalies.length === 0 && (
        <EmptyState title="No anomalous nodes detected." />
      )}
      {q.data?.available && q.data.anomalies.length > 0 && (
        <div className="space-y-2">
          {q.data.anomalies.map((a) => (
            <div
              key={a.ip}
              className="flex items-center justify-between gap-3 rounded-md border border-edge-subtle px-3 py-2"
            >
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 text-risk-high" />
                <div>
                  <div className="text-small text-ink-primary">
                    {a.hostname ?? a.ip}{" "}
                    <span className="font-mono text-[11px] text-ink-muted">{a.ip}</span>
                  </div>
                  <div className="text-[11px] text-ink-muted">{a.reason}</div>
                </div>
              </div>
              <div className="shrink-0 text-right">
                <div className="font-mono text-small text-risk-high">
                  {a.anomaly_score.toFixed(3)}
                </div>
                <div className="text-[10px] uppercase tracking-[0.02em] text-ink-muted">
                  anomaly
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
