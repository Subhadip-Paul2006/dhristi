// Drishti v0.1 — asset inventory listing page | 11-Jul-2026
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { MoneyValue } from "../../components/MoneyValue";
import { RiskPill } from "../../components/RiskPill";
import { StatReadout } from "../../components/ui/console";
import { EmptyState, ErrorState, Skeleton } from "../../components/primitives";
import { money } from "../../lib/format";

export function AssetsPage() {
  const q = useQuery({ queryKey: ["assets"], queryFn: () => api.assets() });
  const totalValue = (q.data ?? []).reduce((s, a) => s + a.business_value, 0);
  const exposed = (q.data ?? []).filter((a) => a.internet_facing).length;
  const critical = (q.data ?? []).filter((a) => a.criticality === "critical").length;

  return (
    <div className="console-atmos min-h-screen">
      <div className="mx-auto max-w-6xl space-y-6 p-4 sm:p-6 lg:p-8">
        <header className="flex flex-col gap-3 border-b border-hairline/60 pb-6 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-accent-400">
              <span className="inline-block h-2 w-2 rounded-full bg-accent-500 shadow-[0_0_8px_#00ff66] animate-pulse" />
              <span>SYS.INVENTORY // DISCOVERED_HOST_NODES</span>
            </div>
            <h1 className="mt-2 font-display text-display font-semibold tracking-tight text-ink-primary">
              Hardware &amp; Cloud Asset Registry
            </h1>
            <p className="mt-1.5 max-w-2xl font-mono text-small text-ink-secondary">
              Discovered endpoints, gateways, and cloud servers. Real asset valuations with computed blast radiuses.
            </p>
          </div>
        </header>

        {q.data && q.data.length > 0 && (
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <StatReadout label="TOTAL ASSETS" index="01">{q.data.length}</StatReadout>
            <StatReadout label="WAN EXPOSED" tone="accent" index="02">
              <span className="text-accent-400 font-bold">{exposed}</span>
            </StatReadout>
            <StatReadout label="CROWN JEWELS" tone="critical" index="03">
              <span className="text-risk-critical font-bold">{critical}</span>
            </StatReadout>
            <StatReadout label="AGGREGATE VALUE" index="04">{money(totalValue)}</StatReadout>
          </div>
        )}

        {q.isLoading && <Skeleton className="h-72" />}
        {q.isError && <ErrorState message="Couldn't load assets." onRetry={() => q.refetch()} />}
        {q.data?.length === 0 && (
          <EmptyState
            title="NO NETWORK ASSETS FOUND"
            hint="Run a network scan or inventory agent to discover assets on the network."
          />
        )}

        {q.data && q.data.length > 0 && (
          <div className="reg-frame relative overflow-hidden rounded border border-hairline bg-surface-1/60 shadow-[0_0_20px_rgba(0,0,0,0.4)] backdrop-blur">
            <span aria-hidden className="reg-tick reg-tr" />
            <table className="w-full text-small">
              <thead className="border-b border-hairline bg-surface-2/70 text-left font-mono text-[10px] uppercase tracking-[0.14em] text-ink-muted">
                <tr>
                  <th className="px-5 py-3 font-semibold">HOST / IP</th>
                  <th className="px-5 py-3 font-semibold">SECURITY ZONE</th>
                  <th className="px-5 py-3 font-semibold">NODE TYPE</th>
                  <th className="px-5 py-3 font-semibold">ASSET VALUE</th>
                  <th className="px-5 py-3 font-semibold">BLAST RADIUS</th>
                  <th className="px-5 py-3 font-semibold">RISK SCORE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline font-mono">
                {q.data.map((a) => (
                  <tr key={a.id} className="transition-colors hover:bg-surface-2/60">
                    <td className="px-5 py-3">
                      <Link to={`/app/assets/${a.id}`} className="font-bold text-ink-primary hover:text-accent-400 transition-colors">
                        {a.hostname ?? a.ip}
                      </Link>
                      <div className="text-[10px] text-ink-muted">{a.ip}</div>
                    </td>
                    <td className="px-5 py-3 text-ink-secondary">
                      <span className="rounded border border-hairline bg-surface-2 px-1.5 py-0.5 text-[10px] uppercase">
                        {a.zone ?? "UNCLASSIFIED"}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-[11px] uppercase text-accent-400/80 font-bold">
                      {a.asset_type}
                    </td>
                    <td className="px-5 py-3 font-mono font-semibold">
                      <MoneyValue value={a.business_value} className="text-small" />
                    </td>
                    <td className="px-5 py-3">
                      <span className="rounded border border-hairline/60 bg-surface-1 px-2 py-0.5 text-[11px] font-bold text-ink-primary">
                        {a.blast_radius_count ?? 0} NODES
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <RiskPill score={a.risk_score} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
