// Drishti v0.1 — ranked attack paths listing | 11-Jul-2026
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Crosshair } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { MoneyValue } from "../../components/MoneyValue";
import { RiskPill } from "../../components/RiskPill";
import { StatReadout } from "../../components/ui/console";
import { EmptyState, ErrorState, Skeleton } from "../../components/primitives";
import { money, percent } from "../../lib/format";

export function PathsPage() {
  const q = useQuery({ queryKey: ["paths"], queryFn: () => api.paths(25) });
  const topRisk = Math.max(0, ...(q.data ?? []).map((p) => p.path_risk));
  const highestImpact = Math.max(0, ...(q.data ?? []).map((p) => p.impact_usd));
  const distinctTargets = new Set((q.data ?? []).map((p) => p.target_asset_id)).size;

  return (
    <div className="console-atmos min-h-screen">
      <div className="mx-auto max-w-6xl space-y-6 p-4 sm:p-6 lg:p-8">
        <header className="flex flex-col gap-3 border-b border-hairline/60 pb-6 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-accent-400">
              <span className="inline-block h-2 w-2 rounded-full bg-accent-500 shadow-[0_0_8px_#00ff66] animate-pulse" />
              <span>SYS.BREACH // ATTACK_SURFACE_VECTORS</span>
            </div>
            <h1 className="mt-2 font-display text-display font-semibold tracking-tight text-ink-primary">
              Ranked Breach Vectors
            </h1>
            <p className="mt-1.5 max-w-2xl font-mono text-small text-ink-secondary">
              Deterministic reachability sequence calculated across active terrain. Prioritized by exploitability and financial exposure.
            </p>
          </div>
          <div className="flex items-center gap-2 rounded border border-hairline bg-surface-1/90 px-3 py-1.5 font-mono text-[11px] text-ink-muted">
            <Crosshair className="h-3.5 w-3.5 text-accent-400" />
            <span>ALGORITHM: <span className="text-accent-400">GRAPH TRAVERSAL</span></span>
          </div>
        </header>

        {q.data && q.data.length > 0 && (
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <StatReadout label="RANKED PATHS" index="01">{q.data.length}</StatReadout>
            <StatReadout label="TARGETS AT RISK" index="02">{distinctTargets}</StatReadout>
            <StatReadout label="MAX PATH RISK" tone="critical" index="03">
              <span className="text-risk-critical font-bold">{topRisk.toFixed(1)}</span>
            </StatReadout>
            <StatReadout label="PEAK IMPACT" tone="accent" index="04">
              <span className="text-accent-400 font-bold">{money(highestImpact)}</span>
            </StatReadout>
          </div>
        )}

        {q.isLoading && <Skeleton className="h-72" />}
        {q.isError && <ErrorState message="Couldn't load paths." onRetry={() => q.refetch()} />}
        {q.data?.length === 0 && (
          <EmptyState
            title="NO REVEALED BREACH PATHS"
            hint="Active scanning indicates no reachable vectors formed to internal crown jewels."
          />
        )}

        {q.data && q.data.length > 0 && (
          <div className="reg-frame relative overflow-hidden rounded border border-hairline bg-surface-1/60 shadow-[0_0_20px_rgba(0,0,0,0.4)] backdrop-blur">
            <span aria-hidden className="reg-tick reg-tr" />
            <div className="border-b border-hairline/60 bg-surface-2/40 px-5 py-3 font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted flex items-center justify-between">
              <span>PRIORITY QUEUE // TRAVERSAL CANDIDATES</span>
              <span className="text-accent-400">{q.data.length} LIVE VECTORS</span>
            </div>
            <ol className="divide-y divide-hairline">
              {q.data.map((p, i) => (
                <li key={p.id}>
                  <Link
                    to={`/app/paths/${p.id}`}
                    className="group flex flex-col gap-3 px-5 py-4 transition-all hover:bg-surface-2/70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-500/50 sm:flex-row sm:items-center sm:gap-4"
                  >
                    <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded border border-hairline bg-surface-1 font-mono text-[12px] font-bold tabular-nums text-accent-400 group-hover:border-accent-500/40 group-hover:shadow-[0_0_8px_rgba(0,255,102,0.2)]">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1 font-mono text-small">
                      <span className="rounded border border-accent-500/30 bg-accent-500/10 px-2 py-0.5 text-[11px] font-semibold text-accent-400">
                        {p.entry_label}
                      </span>
                      <ArrowRight className="h-3.5 w-3.5 shrink-0 text-ink-muted group-hover:text-accent-400 transition-colors" />
                      <span className="font-semibold text-ink-primary group-hover:text-accent-400 transition-colors">
                        {p.target_hostname}
                      </span>
                      <span className="shrink-0 text-ink-muted text-[11px]">
                        · [{p.hop_count} HOPS] · {percent(p.likelihood)} PROB
                      </span>
                    </div>
                    <div className="flex shrink-0 items-center gap-4 pl-6 sm:pl-0">
                      <RiskPill score={p.path_risk} />
                      <MoneyValue value={p.impact_usd} tint className="w-24 text-right font-mono font-bold" />
                    </div>
                  </Link>
                </li>
              ))}
            </ol>
          </div>
        )}
      </div>
    </div>
  );
}
