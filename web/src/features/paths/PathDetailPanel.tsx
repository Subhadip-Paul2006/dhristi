// Drishti v0.1 — attack path detail panel with AI remediation | 11-Jul-2026
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowDown, Crosshair, Crown, Scissors } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import type { PathDetail } from "../../api/types";
import { Button } from "../../components/Button";
import { BreachSimulation } from "./BreachSimulation";
import { MoneyValue } from "../../components/MoneyValue";
import { RiskPill } from "../../components/RiskPill";
import { SeverityBadge } from "../../components/SeverityBadge";
import { ErrorState, LoadingBlock } from "../../components/primitives";
import { percent } from "../../lib/format";

/** Reused in the graph drawer and the full path page. Streams the AI narrative
 * while showing the deterministic $ number instantly (APP_FLOW.md §7 beat 3). */
export function PathDetailPanel({ pathId }: { pathId: string }) {
  const navigate = useNavigate();
  const q = useQuery({ queryKey: ["path", pathId], queryFn: () => api.path(pathId) });

  const impact = useMutation({ mutationFn: () => api.impact(pathId) });
  const [breakMsg, setBreakMsg] = useState<string | null>(null);
  const [showSim, setShowSim] = useState(false);
  useEffect(() => {
    impact.mutate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathId]);

  if (q.isLoading) return <LoadingBlock label="Loading path…" />;
  if (q.isError || !q.data)
    return <ErrorState message="Couldn't load this attack path." onRetry={() => q.refetch()} />;
  const p: PathDetail = q.data;

  // the highest-leverage finding = the target hop's via-vuln step; break-this-path
  // routes to remediation for the final step's asset finding when resolvable.
  const finalStep = p.steps[p.steps.length - 1];

  const breakPath = async () => {
    setBreakMsg(null);
    if (!finalStep) {
      setBreakMsg("This path has no steps to remediate.");
      return;
    }
    try {
      // 1) prefer an open finding on the final hop matching its via_cve
      const asset = await api.asset(finalStep.asset_id);
      const match =
        asset.findings.find(
          (f) => f.status === "open" && finalStep.via_cve && f.cve_id === finalStep.via_cve,
        ) ?? asset.findings.find((f) => f.status === "open");
      if (match) {
        navigate(`/app/remediate/${match.id}`);
        return;
      }
      // 2) fall back to the highest-risk open finding anywhere along the path
      const pathAssetIds = new Set(p.steps.map((s) => s.asset_id));
      const open = await api.findings("?status=open");
      const onPath = open
        .filter((f) => pathAssetIds.has(f.asset_id))
        .sort((a, b) => b.cvss - a.cvss);
      if (onPath[0]) {
        navigate(`/app/remediate/${onPath[0].id}`);
        return;
      }
      // 3) nothing open on this path — say so, offer the findings list
      setBreakMsg("No open findings remain on this path — it may already be broken.");
    } catch {
      setBreakMsg("Couldn't look up findings for this path right now.");
    }
  };

  return (
    <div className="space-y-6">
      <div className="rounded border border-hairline/70 bg-surface-1/60 p-4">
        <div className="flex items-center gap-2 font-mono text-small text-ink-muted">
          <span className="rounded border border-accent-500/30 bg-accent-500/10 px-2 py-0.5 text-accent-400 font-bold">
            {p.entry_label}
          </span>
          <span className="text-accent-500">→</span>
          <span className="font-bold text-ink-primary">{p.target_hostname}</span>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <MoneyValue value={p.impact_usd} size="lg" tint className="font-mono font-bold" />
          <RiskPill score={p.path_risk} />
          <span className="font-mono text-[11px] uppercase tracking-wider text-ink-muted">
            PROBABILITY {percent(p.likelihood)}
          </span>
        </div>
      </div>

      <section>
        <div className="mb-2.5 font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-ink-muted">
          ATTACK SEQUENCE // {p.hop_count} HOPS TO COMPROMISE
        </div>
        <ol className="relative space-y-2 border-l border-hairline pl-4">
          {p.steps.map((s, i) => (
            <li key={s.step_index} className="relative">
              <span
                className={`absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full ${
                  i === p.steps.length - 1 ? "bg-risk-critical shadow-[0_0_8px_#ef4444]" : "bg-accent-500 shadow-[0_0_8px_#00ff66]"
                }`}
              />
              <div className="rounded border border-hairline bg-surface-1/80 p-3 shadow-md">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 font-mono text-small font-bold text-ink-primary">
                    {i === p.steps.length - 1 && <Crown className="h-3.5 w-3.5 text-risk-critical animate-pulse" />}
                    {s.asset_hostname ?? s.asset_ip}
                  </span>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-ink-muted">ZONE: {s.zone}</span>
                </div>
                {s.via_cve && (
                  <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-hairline/50 pt-2">
                    {s.via_severity && (
                      <SeverityBadge severity={s.via_severity} score={s.via_cvss} />
                    )}
                    <span className="font-mono text-[11px] text-ink-secondary">
                      VIA <strong className="text-accent-400">{s.via_cve}</strong> — {s.via_title}
                    </span>
                  </div>
                )}
              </div>
              {i < p.steps.length - 1 && (
                <ArrowDown className="ml-1.5 my-1 h-3 w-3 text-accent-500/60" />
              )}
            </li>
          ))}
        </ol>
      </section>

      <section>
        <div className="mb-2.5 font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-ink-muted">
          SYNTHETIC FINANCIAL &amp; ASSET IMPACT
        </div>
        <div className="rounded border border-hairline bg-surface-1/60 p-4">
          {impact.isPending && (
            <div className="font-mono text-small text-ink-muted">
              Analyzing financial impact…{" "}
              <MoneyValue value={p.impact_usd} tint className="text-small" /> exposure computed.
            </div>
          )}
          {impact.data && !impact.data.refused && (
            <div className="space-y-3">
              <div className="font-display text-h3 leading-snug text-ink-primary">
                {impact.data.headline}
              </div>
              <p className="text-body text-ink-secondary">{impact.data.narrative}</p>
              {impact.data.drivers.length > 0 && (
                <ul className="space-y-1.5 font-mono text-[12px]">
                  {impact.data.drivers.map((d, i) => (
                    <li key={i} className="flex gap-2 text-ink-secondary">
                      <span className="text-accent-400">▸</span> {d}
                    </li>
                  ))}
                </ul>
              )}
              <div className="rounded border border-accent-500/40 bg-accent-500/10 p-3 font-mono text-small text-ink-primary shadow-[0_0_12px_rgba(0,255,102,0.1)]">
                <span className="font-bold text-accent-400 uppercase tracking-wider">HIGHEST-LEVERAGE ACTION:</span>{" "}
                {impact.data.highest_leverage_action}
              </div>
            </div>
          )}
          {impact.data?.refused && (
            <div className="font-mono text-small text-ink-muted">
              This narrative isn't available — the deterministic figure of{" "}
              <MoneyValue value={p.impact_usd} className="text-small" /> still stands.
            </div>
          )}
          {impact.isError && (
            <div className="space-y-2 font-mono text-small text-ink-muted">
              <div>
                Couldn't generate the AI narrative — the deterministic exposure of{" "}
                <MoneyValue value={p.impact_usd} tint className="text-small" /> still stands.
              </div>
              <Button variant="ghost" size="sm" onClick={() => impact.mutate()}>
                Retry analysis
              </Button>
            </div>
          )}
        </div>
      </section>

      <div className="flex flex-col gap-3 sm:flex-row">
        <Button onClick={() => setShowSim(true)} className="w-full font-mono uppercase tracking-wider">
          <Crosshair className="h-4 w-4" /> SIMULATE BREACH
        </Button>
        <Button variant="ghost" onClick={breakPath} className="w-full font-mono uppercase tracking-wider">
          <Scissors className="h-4 w-4" /> BREAK THIS VECTOR
        </Button>
      </div>
      {breakMsg && (
        <div className="rounded border border-hairline bg-surface-2/70 p-3 font-mono text-small text-ink-secondary">
          {breakMsg}{" "}
          <Link to="/app/findings" className="font-semibold text-accent-400 hover:underline">
            Review all findings →
          </Link>
        </div>
      )}

      {showSim && (
        <BreachSimulation
          path={p}
          onClose={() => setShowSim(false)}
          onBreakPath={() => {
            setShowSim(false);
            breakPath();
          }}
        />
      )}
    </div>
  );
}
