// Drishti v0.1 — security overview dashboard | 20-Jul-2026
/** The command surface. Opens on the thesis of the whole product — exposure
 * priced in deterministic dollars — as a live instrument readout, then the
 * ranked routes an attacker can actually walk. Built from the shared console
 * primitives so it reads as one instrument with live watch + report. */
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, ShieldCheck, ShieldOff, Wrench } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import type { PathSummary } from "../../api/types";
import { MoneyValue } from "../../components/MoneyValue";
import { RiskPill } from "../../components/RiskPill";
import { Stagger, StaggerItem } from "../../components/motion";
import { CountUp, Panel, StatReadout } from "../../components/ui/console";
import { ErrorState, Skeleton } from "../../components/primitives";
import { RISK_HEX, moneyFull, riskBucket } from "../../lib/format";

export function Dashboard() {
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => api.dashboard() });

  return (
    <div className="console-atmos min-h-screen">
      <div className="mx-auto w-full max-w-[1600px] p-4 sm:p-6 lg:p-8 xl:px-12">
        <header className="mb-8 flex flex-col gap-4 border-b border-hairline/60 pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="flex items-center gap-2.5 font-mono text-[11px] uppercase tracking-[0.2em] text-accent-400">
              <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-accent-500 shadow-[0_0_8px_#00ff66]" />
              <span>SYS.DEFENSE // SITUATION_READOUT</span>
              <span className="text-ink-muted">·</span>
              <span className="text-ink-muted">DEFENSIVE ATTACK-PATH INTELLIGENCE</span>
            </div>
            <h1 className="mt-2 font-display text-display font-semibold tracking-tight text-ink-primary">
              The routes an attacker can walk, priced.
            </h1>
            <p className="mt-1.5 max-w-xl font-mono text-small text-ink-secondary">
              Ranked by reachability, not severity — and every figure is computed by the engine on screen, never hardcoded.
            </p>
          </div>
          <div className="flex items-center gap-3 font-mono text-[11px] text-ink-muted">
            <div className="flex items-center gap-2 rounded border border-hairline bg-surface-1/80 px-3 py-1.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
              <span className="text-ink-muted">TELEMETRY:</span>
              <span className="font-semibold text-accent-400">LIVE FEED</span>
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-accent-500 animate-ping" />
            </div>
            <div className="hidden rounded border border-hairline bg-surface-1/80 px-3 py-1.5 sm:flex sm:items-center sm:gap-2">
              <span className="text-ink-muted">GRAPH:</span>
              <span className="text-ink-primary">CORRELATED</span>
            </div>
          </div>
        </header>

        {q.isLoading && <DashboardSkeleton />}
        {q.isError && <ErrorState message="Couldn't load the dashboard." onRetry={() => q.refetch()} />}

        {q.data && (
          <Stagger className="space-y-6">
            {q.data.open_findings === 0 && q.data.total_exposure_usd === 0 ? (
              <StaggerItem>
                <ActiveMonitoringState />
              </StaggerItem>
            ) : (
              <>
                {/* Hero: exposure gauge + the single riskiest route */}
                <StaggerItem>
                  <div className="grid grid-cols-1 items-stretch gap-6 lg:grid-cols-[1.15fr_1fr]">
                    <ExposureGauge
                      value={q.data.total_exposure_usd}
                      topPath={q.data.top_paths[0]}
                    />
                    {q.data.top_paths[0] ? (
                      <RiskiestRoute path={q.data.top_paths[0]} />
                    ) : (
                      <Panel eyebrow="Priority queue" title="No ranked routes" index="—">
                        <p className="text-small text-ink-muted">
                          Run a scan to surface the reachable routes to your crown jewels.
                        </p>
                      </Panel>
                    )}
                  </div>
                </StaggerItem>

                {/* Secondary telemetry rail */}
                <StaggerItem>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                    <StatReadout label="OPEN FINDINGS" index="01">{q.data.open_findings}</StatReadout>
                    <StatReadout label="CRITICAL ASSETS" index="02">{q.data.critical_assets}</StatReadout>
                    <StatReadout label="TOP PATH RISK" tone="critical" index="03">
                      <span className="text-risk-critical font-bold">{q.data.top_path_risk.toFixed(1)}</span>
                    </StatReadout>
                  </div>
                </StaggerItem>

                {/* Severity + zones */}
                <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                  <StaggerItem>
                    <Panel index="02" eyebrow="FINDINGS // SEVERITY DENSITY" title="Open findings breakdown">
                      <SeverityChart breakdown={q.data.severity_breakdown} />
                    </Panel>
                  </StaggerItem>
                  <StaggerItem>
                    <Panel index="03" eyebrow="TERRAIN // ZONE GEOMETRY" title="Risk zones & assets">
                      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-2 xl:grid-cols-4">
                        {q.data.zone_summary.map((z) => {
                          const hex = RISK_HEX[riskBucket(z.worst_risk)];
                          return (
                            <div
                              key={z.name}
                              className="reg-frame group relative flex flex-col justify-between rounded border border-hairline bg-surface-1/60 p-3.5 transition-all hover:border-accent-500/50 hover:bg-surface-2/70"
                            >
                              <span aria-hidden className="reg-tick reg-br" />
                              <div className="flex items-center justify-between">
                                <span className="truncate font-mono text-[11px] uppercase tracking-wider text-ink-secondary">{z.name}</span>
                                <span
                                  className="h-2 w-2 shrink-0 rounded-full"
                                  style={{ background: hex, boxShadow: `0 0 8px ${hex}` }}
                                />
                              </div>
                              <div className="mt-3 font-mono text-h1 font-bold text-ink-primary tabular-nums">
                                {z.asset_count}
                              </div>
                              <div className="mt-1 flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.14em] text-ink-muted border-t border-hairline/50 pt-1.5">
                                <span>WORST</span>
                                <span className="font-semibold text-ink-primary">{z.worst_risk.toFixed(0)}</span>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </Panel>
                  </StaggerItem>
                </div>

                {/* Ranked routes — a real priority sequence, so the index numbers mean something */}
                <StaggerItem>
                  <Panel
                    index="04"
                    eyebrow="PRIORITY QUEUE // REACHABILITY × VALUE"
                    title="Ranked attack routes"
                    bodyClassName=""
                  >
                    {q.data.top_paths.length === 0 ? (
                      <div className="p-5 font-mono text-small text-ink-muted">No ranked paths detected in terrain.</div>
                    ) : (
                      <ol className="divide-y divide-hairline">
                        {q.data.top_paths.map((p, i) => (
                          <RouteRow key={p.id} path={p} rank={i + 1} />
                        ))}
                      </ol>
                    )}
                  </Panel>
                </StaggerItem>
              </>
            )}
          </Stagger>
        )}
      </div>
    </div>
  );
}

/** The thesis, as an instrument: exposure counted up in precise dollars, with a
 * faint scanline sweep. This is the most characteristic thing Drishti shows. */
function ExposureGauge({ value, topPath }: { value: number; topPath?: PathSummary }) {
  return (
    <Panel
      index="01"
      eyebrow="TOTAL EXPOSURE · DETERMINISTIC PRICE"
      tone="critical"
      glow
      bodyClassName="p-6 relative overflow-hidden"
      className="scanline border-risk-critical/40 flex flex-col justify-between"
    >
      <div>
        <div className="flex items-center justify-between border-b border-risk-critical/20 pb-3">
          <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-risk-critical font-semibold">
            TOTAL EXPOSURE AT RISK
          </span>
          <span className="font-mono text-[10px] text-ink-muted tracking-wider">
            [ METRIC // RISK_USD ]
          </span>
        </div>
        <div className="mt-4 font-mono text-[clamp(2.75rem,6vw,4.25rem)] font-bold leading-[0.95] tracking-tight text-risk-critical tabular-nums drop-shadow-[0_0_24px_rgba(239,68,68,0.35)]">
          <CountUp value={value} format={moneyFull} durationMs={1200} />
        </div>
        <div className="mt-2 font-mono text-[11px] uppercase tracking-[0.16em] text-ink-muted">
          ATTACK SURFACE POTENTIAL LOSS
        </div>
        <p className="mt-3 max-w-md text-small text-ink-secondary">
          Summed from reachable graph path exploits, deduped by crown jewel target. Deterministic financial impact.
        </p>
      </div>
      {topPath && (
        <div className="mt-5 inline-flex items-center gap-2 rounded border border-risk-critical/30 bg-risk-critical/[0.08] px-3 py-2 font-mono text-[11px] text-ink-secondary">
          <span className="text-risk-critical font-bold">▲ HIGH PRIORITY:</span>
          <span>
            <MoneyValue value={topPath.impact_usd} className="font-bold text-risk-critical" /> on the single riskiest route
          </span>
        </div>
      )}
    </Panel>
  );
}

/** The riskiest route right now — the one-click path to its $ impact + fix. */
function RiskiestRoute({ path }: { path: PathSummary }) {
  return (
    <Link to={`/app/paths/${path.id}`} className="block h-full focus-visible:outline-none group">
      <Panel
        index="CRIT"
        eyebrow="PRIMARY VECTOR · HIGHEST IMPACT"
        tone="accent"
        className="h-full transition-all duration-300 hover:border-accent-500/70 hover:shadow-[0_0_25px_rgba(0,255,102,0.15)] hover:-translate-y-0.5"
        bodyClassName="flex flex-col justify-between gap-5 p-6 h-full"
      >
        <div>
          <div className="flex items-center justify-between font-mono text-[11px] text-ink-muted border-b border-hairline/60 pb-2.5">
            <span>TARGET VECTOR</span>
            <span className="text-accent-400 font-semibold">[{path.hop_count} HOPS TO COMPROMISE]</span>
          </div>
          
          <div className="mt-4 flex flex-wrap items-center gap-2.5 font-mono text-small">
            <span className="rounded border border-accent-500/40 bg-accent-500/10 px-2.5 py-1 font-semibold text-accent-400 shadow-[0_0_8px_rgba(0,255,102,0.1)]">
              {path.entry_label}
            </span>
            <ArrowRight className="h-4 w-4 shrink-0 text-accent-500/60" />
            <span className="rounded border border-hairline bg-surface-2 px-2.5 py-1 font-semibold text-ink-primary">
              {path.target_hostname || "crown jewel"}
            </span>
          </div>
        </div>

        <div className="flex items-end justify-between gap-4 border-t border-hairline/60 pt-4">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-ink-muted">
              VECTOR EXPOSURE VALUE
            </div>
            <MoneyValue value={path.impact_usd} size="lg" tint className="mt-1 block font-mono font-bold" />
          </div>
          <span className="inline-flex shrink-0 items-center gap-2 rounded border border-accent-500 bg-accent-500/20 px-4 py-2 font-mono text-[12px] font-bold uppercase tracking-[0.06em] text-accent-400 transition-all group-hover:bg-accent-500 group-hover:text-black group-hover:shadow-[0_0_15px_#00ff66]">
            <Wrench className="h-3.5 w-3.5" /> INTERCEPT &amp; FIX
          </span>
        </div>
      </Panel>
    </Link>
  );
}

function RouteRow({ path, rank }: { path: PathSummary; rank: number }) {
  return (
    <li>
      <Link
        to={`/app/paths/${path.id}`}
        className="group flex flex-col gap-3 px-5 py-4 transition-colors hover:bg-surface-2/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-500/50 sm:flex-row sm:items-center sm:gap-4"
      >
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded border border-hairline bg-surface-1 font-mono text-[12px] font-bold tabular-nums text-accent-400 group-hover:border-accent-500/40 group-hover:shadow-[0_0_8px_rgba(0,255,102,0.2)]">
          {String(rank).padStart(2, "0")}
        </span>
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1 font-mono text-small">
          <span className="rounded bg-accent-500/10 px-2 py-0.5 text-accent-400 border border-accent-500/20 font-semibold">
            {path.entry_label}
          </span>
          <ArrowRight className="h-3.5 w-3.5 shrink-0 text-ink-muted group-hover:text-accent-400 transition-colors" />
          <span className="text-ink-primary font-medium">{path.target_hostname}</span>
          <span className="shrink-0 text-ink-muted text-[12px]">[{path.hop_count} HOPS]</span>
        </div>
        <div className="flex shrink-0 items-center gap-4">
          <RiskPill score={path.path_risk} />
          <MoneyValue value={path.impact_usd} tint className="w-24 text-right font-mono font-semibold" />
        </div>
      </Link>
    </li>
  );
}

function SeverityChart({
  breakdown,
}: {
  breakdown: { critical: number; high: number; medium: number; low: number };
}) {
  const rows = [
    { name: "Critical", value: breakdown.critical, hex: RISK_HEX.critical },
    { name: "High", value: breakdown.high, hex: RISK_HEX.high },
    { name: "Medium", value: breakdown.medium, hex: RISK_HEX.medium },
    { name: "Low", value: breakdown.low, hex: RISK_HEX.safe },
  ];
  const total = rows.reduce((s, r) => s + r.value, 0);
  const max = Math.max(...rows.map((r) => r.value), 1);
  if (total === 0)
    return (
      <div className="flex items-center gap-2 py-6 font-mono text-small text-ink-muted">
        <ShieldOff className="h-4 w-4 text-risk-safe" /> No open findings.
      </div>
    );
  return (
    <div>
      <div className="flex h-2.5 gap-1 overflow-hidden rounded bg-surface-3 p-0.5 border border-hairline">
        {rows
          .filter((r) => r.value > 0)
          .map((r) => (
            <span
              key={r.name}
              className="h-full rounded-sm"
              style={{ width: `${(r.value / total) * 100}%`, background: r.hex, boxShadow: `0 0 6px ${r.hex}88` }}
              title={`${r.name}: ${r.value}`}
            />
          ))}
      </div>
      <div className="mt-4 space-y-3">
        {rows.map((r) => (
          <div key={r.name} className="flex items-center gap-3 font-mono">
            <span
              className="h-2 w-2 shrink-0 rounded-full"
              style={{ background: r.hex, boxShadow: `0 0 8px ${r.hex}` }}
            />
            <span className="w-20 shrink-0 text-[12px] uppercase tracking-wider text-ink-secondary">{r.name}</span>
            <div className="h-2 flex-1 overflow-hidden rounded bg-surface-3 border border-hairline/50">
              <span
                className="block h-full rounded transition-[width] duration-1000 ease-out"
                style={{
                  width: `${(r.value / max) * 100}%`,
                  background: `linear-gradient(90deg, transparent, ${r.hex})`,
                  boxShadow: `0 0 8px ${r.hex}88`,
                }}
              />
            </div>
            <span className="w-10 shrink-0 text-right font-mono text-small tabular-nums font-bold text-ink-primary">
              {r.value}
            </span>
          </div>
        ))}
      </div>
      <div className="mt-4 flex items-center justify-between border-t border-hairline pt-3 font-mono text-[11px] text-ink-muted">
        <span className="uppercase tracking-[0.14em]">TOTAL DETECTIONS</span>
        <span className="tabular-nums font-bold text-accent-400">{total} OPEN</span>
      </div>
    </div>
  );
}

function ActiveMonitoringState() {
  return (
    <Panel eyebrow="STATUS // NOMINAL" title="System secure & actively monitoring" tone="safe" glow>
      <div className="flex flex-col items-start gap-6 sm:flex-row sm:items-center">
        <div className="relative flex h-20 w-20 shrink-0 items-center justify-center">
          <div className="absolute h-full w-full animate-ping rounded-full bg-risk-safe/10" style={{ animationDuration: "3s" }} />
          <div className="relative z-10 flex h-14 w-14 items-center justify-center rounded border border-risk-safe/50 bg-canvas/80 shadow-[0_0_20px_rgba(0,255,102,0.35)]">
            <ShieldCheck className="h-7 w-7 text-risk-safe" />
          </div>
        </div>
        <p className="max-w-2xl font-mono text-small text-ink-secondary">
          No vulnerabilities or critical exposures detected in your network. The Drishti engine is
          continuously scanning for new assets and emerging threats — priced exposure will appear
          here the moment a reachable route forms.
        </p>
      </div>
    </Panel>
  );
}

function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1.15fr_1fr]">
        <Skeleton className="h-48" />
        <Skeleton className="h-48" />
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {[0, 1, 2].map((i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-64" />
    </div>
  );
}
