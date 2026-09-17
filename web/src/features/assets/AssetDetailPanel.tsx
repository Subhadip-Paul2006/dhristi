// Drishti v0.1 — asset detail side panel | 11-Jul-2026
import { useQuery } from "@tanstack/react-query";
import { MapPin, Wrench } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { Button } from "../../components/Button";
import { MoneyValue } from "../../components/MoneyValue";
import { RiskPill } from "../../components/RiskPill";
import { SeverityBadge } from "../../components/SeverityBadge";
import { ErrorState, LoadingBlock } from "../../components/primitives";

/** Reused in the graph drawer and the full asset page. */
export function AssetDetailPanel({
  assetId,
  showViewOnMap = false,
}: {
  assetId: string;
  showViewOnMap?: boolean;
}) {
  const q = useQuery({ queryKey: ["asset", assetId], queryFn: () => api.asset(assetId) });

  if (q.isLoading) return <LoadingBlock label="Loading asset…" />;
  if (q.isError || !q.data)
    return <ErrorState message="Couldn't load this asset." onRetry={() => q.refetch()} />;
  const a = q.data;

  return (
    <div className="space-y-6 font-mono">
      <div className="rounded border border-hairline/70 bg-surface-1/60 p-4">
        <div className="flex items-center justify-between gap-2">
          <div className="font-mono text-h3 font-bold text-ink-primary">{a.hostname ?? a.ip}</div>
          <RiskPill score={a.risk_score} />
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-ink-muted">
          <span className="text-accent-400 font-bold">{a.ip}</span>
          <span>· TYPE: {a.asset_type.toUpperCase()}</span>
          {a.zone && <span>· ZONE: {a.zone.toUpperCase()}</span>}
          <span>· TIER: {a.criticality.toUpperCase()}</span>
          {a.os && <span>· OS: {a.os}</span>}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <MiniStat label="BUSINESS VALUE">
          <MoneyValue value={a.business_value} className="font-bold text-ink-primary" />
        </MiniStat>
        <MiniStat label="REACHES (BLAST)">
          <span className="font-mono text-body font-bold text-accent-400">
            {a.blast_radius_count ?? 0} NODES
          </span>
        </MiniStat>
      </div>

      <div className="rounded border border-risk-critical/30 bg-risk-critical/[0.08] p-3 text-[11px] text-ink-secondary">
        <span className="font-bold text-risk-critical">▲ BLAST HAZARD:</span> If compromised, this node reaches{" "}
        <strong className="text-ink-primary">{a.blast_radius_count ?? 0}</strong> assets worth{" "}
        <MoneyValue value={a.downstream_value} tint className="text-small font-bold" />.
      </div>

      {showViewOnMap && (
        <Link to={`/app/graph?focus=${a.id}`}>
          <Button variant="ghost" size="sm" className="font-mono text-[11px] uppercase">
            <MapPin className="h-3.5 w-3.5 text-accent-400" /> View on Map
          </Button>
        </Link>
      )}

      {a.services.length > 0 && (
        <section>
          <SectionLabel>LISTENING SERVICES // NETWORK PORTS</SectionLabel>
          <div className="overflow-hidden rounded border border-hairline bg-surface-1/60">
            <table className="w-full text-small">
              <tbody className="divide-y divide-hairline font-mono text-[11px]">
                {a.services.map((s) => (
                  <tr key={s.id} className="transition-colors hover:bg-surface-2/60">
                    <td className="px-3 py-2 font-bold text-accent-400">
                      {s.port}/{s.protocol}
                    </td>
                    <td className="px-3 py-2 text-ink-primary">{s.name}</td>
                    <td className="px-3 py-2 text-ink-muted">{s.version ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {a.findings.length > 0 && (
        <section>
          <SectionLabel>ACTIVE FINDINGS // VULNERABILITY DETECTIONS</SectionLabel>
          <div className="space-y-2">
            {a.findings.map((f) => (
              <div
                key={f.id}
                className="flex items-center justify-between gap-3 rounded border border-hairline bg-surface-1/80 p-3 shadow-sm transition-colors hover:border-accent-500/40"
              >
                <div className="min-w-0 font-mono">
                  <div className="truncate text-small font-sans font-medium text-ink-primary">{f.title}</div>
                  <div className="text-[10px] text-accent-400 font-bold">{f.cve_id ?? "NVD-UNASSIGNED"}</div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <SeverityBadge severity={f.severity} score={f.cvss} />
                  {f.status === "open" && (
                    <Link to={`/app/remediate/${f.id}`}>
                      <Button variant="ghost" size="sm" className="font-mono text-[10px] uppercase">
                        <Wrench className="h-3 w-3" /> FIX
                      </Button>
                    </Link>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function MiniStat({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rounded border border-hairline bg-surface-1/80 p-3 shadow-sm">
      <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-ink-muted font-semibold">{label}</div>
      <div className="mt-1">{children}</div>
    </div>
  );
}
function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-2 font-mono text-[10px] uppercase tracking-[0.16em] text-ink-muted font-semibold">{children}</div>
  );
}
