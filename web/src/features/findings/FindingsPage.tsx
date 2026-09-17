// Drishti v0.1 — vulnerability findings table | 11-Jul-2026
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Wrench } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import type { Finding } from "../../api/types";
import { Button } from "../../components/Button";
import { SeverityBadge } from "../../components/SeverityBadge";
import { StatReadout } from "../../components/ui/console";
import { EmptyState, ErrorState, Select, Skeleton } from "../../components/primitives";
import { useToast } from "../../store/graphStore";

const STATUS_TINT: Record<string, string> = {
  open: "text-status-open",
  remediating: "text-status-remediating",
  resolved: "text-status-resolved",
  accepted: "text-ink-muted",
};

export function FindingsPage() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const qc = useQueryClient();
  const toast = useToast();

  const query = new URLSearchParams();
  if (severity) query.set("severity", severity);
  if (status) query.set("status", status);
  const qs = query.toString() ? `?${query}` : "";

  const q = useQuery({
    queryKey: ["findings", severity, status],
    queryFn: () => api.findings(qs),
  });

  const setStatusMut = useMutation({
    mutationFn: ({ id, s }: { id: string; s: string }) => api.patchFinding(id, s),
    onSuccess: (_d, v) => {
      qc.invalidateQueries();
      toast.show(`Finding marked ${v.s}`, v.s === "resolved" ? "success" : "info");
    },
    onError: () => toast.show("Couldn't update status", "error"),
  });

  const counts = (q.data ?? []).reduce(
    (acc, f) => {
      if (f.severity === "critical") acc.critical++;
      if (f.status === "open") acc.open++;
      if (f.status === "resolved") acc.resolved++;
      return acc;
    },
    { critical: 0, open: 0, resolved: 0 },
  );

  return (
    <div className="console-atmos min-h-screen">
      <div className="mx-auto max-w-6xl space-y-6 p-4 sm:p-6 lg:p-8">
        <header className="flex flex-col gap-3 border-b border-hairline/60 pb-6 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-accent-400">
              <span className="inline-block h-2 w-2 rounded-full bg-accent-500 shadow-[0_0_8px_#00ff66] animate-pulse" />
              <span>SYS.VULN // INVENTORY_AND_EXPLOIT_INDEX</span>
            </div>
            <h1 className="mt-2 font-display text-display font-semibold tracking-tight text-ink-primary">
              Correlated Vulnerabilities
            </h1>
            <p className="mt-1.5 max-w-2xl font-mono text-small text-ink-secondary">
              Network-correlated findings with CVSS severity scoring and direct automated AI remediation playbooks.
            </p>
          </div>
        </header>

        {q.data && q.data.length > 0 && (
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <StatReadout label="TOTAL DETECTED" index="01">{q.data.length}</StatReadout>
            <StatReadout label="CRITICAL RISKS" tone="critical" index="02">
              <span className="text-risk-critical font-bold">{counts.critical}</span>
            </StatReadout>
            <StatReadout label="UNRESOLVED OPEN" tone="accent" index="03">
              <span className="text-accent-400 font-bold">{counts.open}</span>
            </StatReadout>
            <StatReadout label="CONTAINED / FIXED" index="04">{counts.resolved}</StatReadout>
          </div>
        )}

        <div className="flex flex-wrap gap-3 font-mono">
          <Select
            uiSize="sm"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            aria-label="Filter by severity"
            className="border-hairline bg-surface-1 font-mono text-[11px] uppercase"
          >
            <option value="">ALL SEVERITIES</option>
            {["critical", "high", "medium", "low"].map((o) => (
              <option key={o} value={o}>
                {o.toUpperCase()}
              </option>
            ))}
          </Select>
          <Select
            uiSize="sm"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            aria-label="Filter by status"
            className="border-hairline bg-surface-1 font-mono text-[11px] uppercase"
          >
            <option value="">ALL STATUSES</option>
            {["open", "remediating", "resolved", "accepted"].map((o) => (
              <option key={o} value={o}>
                {o.toUpperCase()}
              </option>
            ))}
          </Select>
        </div>

        {q.isLoading && <Skeleton className="h-72" />}
        {q.isError && <ErrorState message="Couldn't load findings." onRetry={() => q.refetch()} />}
        {q.data?.length === 0 && (
          <EmptyState
            title="NO VULNERABILITIES FOUND"
            hint="Zero open findings match the specified severity and status criteria."
          />
        )}

        {q.data && q.data.length > 0 && (
          <div className="reg-frame relative overflow-hidden rounded border border-hairline bg-surface-1/60 shadow-[0_0_20px_rgba(0,0,0,0.4)] backdrop-blur">
            <span aria-hidden className="reg-tick reg-tr" />
            <table className="w-full text-small">
              <thead className="border-b border-hairline bg-surface-2/70 text-left font-mono text-[10px] uppercase tracking-[0.14em] text-ink-muted">
                <tr>
                  <th className="px-5 py-3 font-semibold">ASSET HOST</th>
                  <th className="px-5 py-3 font-semibold">VULNERABILITY &amp; CVE</th>
                  <th className="px-5 py-3 font-semibold">SEVERITY</th>
                  <th className="px-5 py-3 font-semibold">STATUS</th>
                  <th className="px-5 py-3 font-semibold text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline font-mono">
                {q.data.map((f: Finding) => (
                  <tr key={f.id} className="transition-colors hover:bg-surface-2/60">
                    <td className="px-5 py-3">
                      <Link to={`/app/assets/${f.asset_id}`} className="font-bold text-ink-primary hover:text-accent-400 transition-colors">
                        {f.asset_hostname ?? f.asset_ip}
                      </Link>
                    </td>
                    <td className="max-w-xs px-5 py-3">
                      <div className="truncate font-sans font-medium text-ink-primary">{f.title}</div>
                      <div className="mt-0.5 text-[11px] text-accent-400 font-bold">{f.cve_id ?? "NVD-UNASSIGNED"}</div>
                    </td>
                    <td className="px-5 py-3">
                      <SeverityBadge severity={f.severity} score={f.cvss} />
                    </td>
                    <td className="px-5 py-3">
                      <Select
                        uiSize="sm"
                        value={f.status}
                        onChange={(e) => setStatusMut.mutate({ id: f.id, s: e.target.value })}
                        aria-label={`Status for ${f.asset_hostname ?? f.asset_ip}`}
                        className={`font-mono text-[10px] uppercase font-bold ${STATUS_TINT[f.status]}`}
                      >
                        {["open", "remediating", "resolved", "accepted"].map((s) => (
                          <option key={s} value={s}>
                            {s.toUpperCase()}
                          </option>
                        ))}
                      </Select>
                    </td>
                    <td className="px-5 py-3 text-right">
                      {f.status === "open" && (
                        <Link to={`/app/remediate/${f.id}`}>
                          <Button variant="ghost" size="sm" className="font-mono text-[10px] uppercase hover:text-accent-400">
                            <Wrench className="h-3 w-3" /> FIX PLAYBOOK
                          </Button>
                        </Link>
                      )}
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
