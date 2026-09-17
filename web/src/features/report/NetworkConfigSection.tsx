// Drishti v0.1 — network configuration vulnerability section | 12-Jul-2026
/** NAT / DMZ / DHCP misconfiguration findings on the Network Intelligence
 * Report. Every finding is inferred from REAL observed topology or explicit
 * user-declared config and is fed into the same risk engine. "unknown /
 * insufficient data" and "passed" checks render visually distinct from real
 * findings — an unknown is never shown as a clean pass. */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  HelpCircle,
  Network,
  ShieldQuestion,
  SlidersHorizontal,
  Terminal,
} from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "../../api/client";
import type { NetconfigFinding, NetconfigInput } from "../../api/types";
import { Button } from "../../components/Button";
import { EmptyState, ErrorState, LoadingBlock } from "../../components/primitives";
import { Panel } from "../../components/ui/console";
import { RISK_HEX } from "../../lib/format";
import { useToast } from "../../store/graphStore";

const SEV_HEX: Record<string, string> = {
  critical: RISK_HEX.critical,
  high: RISK_HEX.high,
  medium: RISK_HEX.medium,
  low: RISK_HEX.safe,
  none: "#6b7a94",
};
const CAT_TINT: Record<string, string> = {
  DMZ: "text-accent-400",
  NAT: "text-risk-high",
  DHCP: "text-risk-medium",
};

export function NetworkConfigSection() {
  const qc = useQueryClient();
  const toast = useToast();
  const [showForm, setShowForm] = useState(false);
  const [consented, setConsented] = useState(false);
  const [declare, setDeclare] = useState(false);
  const [form, setForm] = useState({
    dmz_hosts: "",
    dhcp_servers: "",
    gateway_ip: "",
    dhcp_snooping: "unknown",
    port_forwards: "",
  });

  const last = useQuery({ queryKey: ["netconfig", "last"], queryFn: () => api.netconfigLast() });

  const run = useMutation({
    mutationFn: () => api.netconfigAnalyze(true, declare ? buildConfig(form) : undefined),
    onSuccess: (r) => {
      qc.setQueryData(["netconfig", "last"], r);
      setShowForm(false);
      toast.show(`Configuration analyzed — ${r.recomputed_risk.real_findings} real finding(s)`, "success");
    },
    onError: (e) => toast.show(e instanceof ApiError ? e.message : "Analysis failed", "error"),
  });

  const data = last.data;
  const findings = data?.findings ?? [];

  return (
    <Panel index="1a" eyebrow="Topology · inferred config" title="Network configuration" icon={Network}>
      <p className="-mt-1 text-[11px] text-ink-muted">
        NAT / DMZ / DHCP misconfigurations inferred from your real topology (and any config you
        declare), fed into the risk engine. Checks lacking data are marked{" "}
        <span className="text-ink-secondary">unknown</span> — never a fabricated pass.
      </p>

      {last.isLoading && <LoadingBlock label="Loading configuration analysis…" />}
      {last.isError && <ErrorState message="Couldn't load config analysis." onRetry={() => last.refetch()} />}

      {data && (
        <div className="mt-3">
          {!showForm && (
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <Button variant="primary" size="sm" onClick={() => setShowForm(true)}>
                <SlidersHorizontal className="mr-1.5 h-3.5 w-3.5" />
                {data.available ? "Re-analyze configuration" : "Analyze configuration"}
              </Button>
              {data.available && (
                <span className="text-[11px] text-ink-muted">
                  {data.recomputed_risk.real_findings} real · {data.recomputed_risk.unknown_findings} unknown ·{" "}
                  {data.recomputed_risk.passed_checks} passed
                  {data.used_declared_config ? " · used declared config" : " · observed only"}
                </span>
              )}
            </div>
          )}

          {showForm && (
            <ConsentForm
              consented={consented}
              setConsented={setConsented}
              declare={declare}
              setDeclare={setDeclare}
              form={form}
              setForm={setForm}
              pending={run.isPending}
              onCancel={() => setShowForm(false)}
              onRun={() => run.mutate()}
            />
          )}

          {run.isPending && <LoadingBlock label="Analyzing configuration + recomputing risk…" />}

          {!showForm && !data.available && !run.isPending && (
            <EmptyState
              title="No configuration analysis yet."
              hint="Run it to detect NAT/DMZ/DHCP misconfigurations on your network."
            />
          )}

          {data.available && findings.length > 0 && (
            <div className="space-y-2.5">
              {[...findings]
                .sort((a, b) => statusRank(a) - statusRank(b))
                .map((f) => (
                  <FindingRow key={f.id} f={f} />
                ))}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

function FindingRow({ f }: { f: NetconfigFinding }) {
  const real = f.status === "real";
  const passed = f.status === "passed";
  const color = SEV_HEX[f.severity] ?? "#6b7a94";

  // structural distinction: real = severity left-border; unknown = dashed muted;
  // passed = teal check. An unknown never looks like a pass.
  const wrap = real
    ? "rounded-md border border-edge-subtle bg-bg-inset"
    : passed
      ? "rounded-md border border-risk-safe/40 bg-risk-safe/[0.05]"
      : "rounded-md border border-dashed border-edge-strong bg-bg-inset/40";

  return (
    <div className={wrap} style={real ? { borderLeft: `3px solid ${color}` } : undefined}>
      <div className="p-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded-sm border border-edge-subtle px-1.5 py-0.5 text-[9px] font-semibold ${CAT_TINT[f.category] ?? "text-ink-secondary"}`}>
            {f.category}
          </span>
          {real && (
            <span
              className="rounded-sm px-1.5 py-0.5 text-[9px] font-semibold uppercase"
              style={{ backgroundColor: `${color}22`, color }}
            >
              {f.severity}
            </span>
          )}
          {f.status === "unknown" && (
            <span className="inline-flex items-center gap-1 rounded-sm border border-dashed border-edge-strong px-1.5 py-0.5 text-[9px] font-medium text-ink-muted">
              <HelpCircle className="h-3 w-3" /> INSUFFICIENT DATA
            </span>
          )}
          {passed && (
            <span className="inline-flex items-center gap-1 rounded-sm bg-risk-safe/15 px-1.5 py-0.5 text-[9px] font-medium text-risk-safe">
              <CheckCircle2 className="h-3 w-3" /> PASSED
            </span>
          )}
          <span className="rounded-sm bg-bg-raised px-1.5 py-0.5 text-[9px] text-ink-muted">
            {f.source === "declared" ? "declared config" : "observed"}
          </span>
          <span className="text-small text-ink-primary">{f.title}</span>
        </div>

        <p className="mt-1.5 font-mono text-[11px] leading-relaxed text-ink-muted">{f.evidence}</p>

        {f.affected.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {f.affected.map((a) => (
              <span key={a} className="rounded-sm bg-bg-raised px-1.5 py-0.5 font-mono text-[10px] text-ink-secondary">
                {a}
              </span>
            ))}
          </div>
        )}

        {f.remediation_hint && (
          <p className="mt-1.5 text-[11px] text-ink-secondary">
            <span className="text-ink-muted">Fix:</span> {f.remediation_hint}
          </p>
        )}

        {f.finding_id && (
          <Link
            to={`/app/remediate/${f.finding_id}`}
            className="mt-2 inline-flex items-center gap-1 text-[11px] text-accent-400 hover:text-accent-300"
          >
            <Terminal className="h-3 w-3" /> Generate fix
          </Link>
        )}
      </div>
    </div>
  );
}

function ConsentForm({
  consented,
  setConsented,
  declare,
  setDeclare,
  form,
  setForm,
  pending,
  onCancel,
  onRun,
}: {
  consented: boolean;
  setConsented: (v: boolean) => void;
  declare: boolean;
  setDeclare: (v: boolean) => void;
  form: ConfigForm;
  setForm: (f: ConfigForm) => void;
  pending: boolean;
  onCancel: () => void;
  onRun: () => void;
}) {
  const input =
    "w-full rounded-md border border-edge-subtle bg-bg-inset px-2.5 py-1.5 font-mono text-small text-ink-primary outline-none focus:border-accent-500";
  return (
    <div className="rounded-md border border-risk-medium/40 bg-risk-medium/[0.06] p-3">
      <div className="flex items-center gap-2 text-small font-medium text-risk-medium">
        <ShieldQuestion className="h-4 w-4" /> Confirm authorization
      </div>
      <p className="mt-1.5 text-[11px] leading-relaxed text-ink-secondary">
        This reads your network's topology/configuration to help secure it — it never attacks or
        intercepts traffic. Only analyze networks you <b>own</b> or are <b>authorized to assess</b>.
      </p>
      <label className="mt-2.5 flex cursor-pointer items-start gap-2 text-[11px] text-ink-secondary">
        <input type="checkbox" className="mt-0.5 accent-accent-500" checked={consented} onChange={(e) => setConsented(e.target.checked)} />
        <span>I own this network or am authorized to assess it.</span>
      </label>

      <label className="mt-3 flex cursor-pointer items-center gap-2 text-[11px] text-ink-secondary">
        <input type="checkbox" className="accent-accent-500" checked={declare} onChange={(e) => setDeclare(e.target.checked)} />
        <span>Declare additional config for analysis (optional)</span>
      </label>

      {declare && (
        <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
          <label className="text-[10px] text-ink-muted">
            DMZ hosts (comma-separated IPs/hostnames)
            <input className={input} value={form.dmz_hosts} onChange={(e) => setForm({ ...form, dmz_hosts: e.target.value })} placeholder="10.0.1.11, web-app-01" />
          </label>
          <label className="text-[10px] text-ink-muted">
            DHCP servers (comma-separated IPs)
            <input className={input} value={form.dhcp_servers} onChange={(e) => setForm({ ...form, dhcp_servers: e.target.value })} placeholder="192.168.1.1, 192.168.1.66" />
          </label>
          <label className="text-[10px] text-ink-muted">
            Gateway IP
            <input className={input} value={form.gateway_ip} onChange={(e) => setForm({ ...form, gateway_ip: e.target.value })} placeholder="192.168.1.1" />
          </label>
          <label className="text-[10px] text-ink-muted">
            DHCP snooping
            <select
              className={input}
              value={form.dhcp_snooping}
              onChange={(e) => setForm({ ...form, dhcp_snooping: e.target.value })}
            >
              <option value="unknown">Unknown (don't assess)</option>
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
          </label>
          <label className="text-[10px] text-ink-muted sm:col-span-2">
            Port forwards — one per line: <span className="font-mono">externalPort,internalIP,internalPort</span>
            <textarea
              className={`${input} h-16`}
              value={form.port_forwards}
              onChange={(e) => setForm({ ...form, port_forwards: e.target.value })}
              placeholder={"3389,10.0.4.5,3389\n5432,10.0.3.11,5432"}
            />
          </label>
        </div>
      )}

      <div className="mt-3 flex gap-2">
        <Button variant="primary" size="sm" disabled={!consented || pending} onClick={onRun}>
          Analyze configuration
        </Button>
        <Button variant="ghost" size="sm" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

type ConfigForm = {
  dmz_hosts: string;
  dhcp_servers: string;
  gateway_ip: string;
  dhcp_snooping: string;
  port_forwards: string;
};

function statusRank(f: NetconfigFinding): number {
  if (f.status !== "real") return f.status === "unknown" ? 90 : 99;
  return { critical: 0, high: 1, medium: 2, low: 3 }[f.severity] ?? 4;
}

function buildConfig(form: ConfigForm): NetconfigInput {
  const list = (s: string) =>
    s.split(",").map((x) => x.trim()).filter(Boolean);
  const forwards = form.port_forwards
    .split("\n")
    .map((line) => line.split(",").map((x) => x.trim()))
    .filter((p) => p.length >= 3 && p[0] && p[1] && p[2])
    .map((p) => ({
      external_port: Number(p[0]) || 0,
      internal_ip: p[1],
      internal_port: Number(p[2]) || 0,
      proto: "tcp",
    }));
  return {
    dmz_hosts: list(form.dmz_hosts),
    dhcp_servers: list(form.dhcp_servers),
    gateway_ip: form.gateway_ip.trim() || null,
    dhcp_snooping: form.dhcp_snooping === "true" ? true : form.dhcp_snooping === "false" ? false : null,
    port_forwards: forwards,
  };
}
