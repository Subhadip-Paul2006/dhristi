// Drishti v0.1 — AI-powered remediation console | 11-Jul-2026
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ChevronRight,
  Cpu,
  Info,
  RotateCw,
  Sparkles,
  Terminal,
  Copy,
  Check,
  Server,
  Layers,
  FileCode,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../../api/client";
import type { Finding, Remediation } from "../../api/types";
import { Button } from "../../components/Button";
import { SeverityBadge } from "../../components/SeverityBadge";
import { Card, ErrorState, LoadingBlock } from "../../components/primitives";
import { useToast } from "../../store/graphStore";

const KINDS: { key: string; label: string; icon: typeof Terminal; desc: string }[] = [
  { key: "ansible", label: "Ansible Playbook", icon: Layers, desc: "Automated multi-node YAML playbook" },
  { key: "shell", label: "Shell Hardening", icon: Terminal, desc: "Direct Bash script with rollback logic" },
  { key: "cloud_cli", label: "Cloud Security Group", icon: Server, desc: "AWS CLI / VPC ingress firewall rule" },
];

export function RemediationConsole() {
  const { findingId } = useParams<{ findingId: string }>();
  const qc = useQueryClient();
  const toast = useToast();
  const [kind, setKind] = useState("shell");

  // load the finding context via direct lookup or findings list
  const findingQ = useQuery({
    queryKey: ["finding", findingId],
    queryFn: async () => {
      if (!findingId) return null;
      try {
        const direct = await api.getFinding(findingId);
        if (direct) return direct;
      } catch {
        // Fallback to client-side list filtering
      }
      const all = await api.findings();
      return all.find((f) => f.id === findingId) ?? null;
    },
  });


  const gen = useMutation({
    mutationFn: (regenerate: boolean) => api.remediate(findingId!, kind, regenerate),
    onError: () => toast.show("Fix generation failed — please retry", "error"),
    onSuccess: (r) => {
      if (!r.refused) toast.show("Defensive fix generated successfully", "success");
    },
  });

  const setStatus = useMutation({
    mutationFn: (status: string) => api.patchFinding(findingId!, status),
    onSuccess: (_d, status) => {
      qc.invalidateQueries();
      toast.show(status === "resolved" ? "Finding marked as resolved" : "Finding marked as remediating", "success");
    },
    onError: () => toast.show("Couldn't update finding status", "error"),
  });

  if (findingQ.isLoading) return <div className="p-10"><LoadingBlock label="Loading finding intelligence…" /></div>;
  if (findingQ.isError || !findingQ.data)
    return (
      <div className="p-10">
        <ErrorState message="Finding not found." onRetry={() => findingQ.refetch()} />
      </div>
    );
  const f = findingQ.data;
  const remediation = gen.data;
  return (
    <div className="w-full px-6 py-6 lg:px-10 space-y-6 font-mono">
      {/* Top Breadcrumb & Actions Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Link
          to="/app/findings"
          className="inline-flex items-center gap-2 rounded border border-hairline bg-surface-1/90 px-3.5 py-1.5 text-xs font-bold text-ink-primary hover:border-accent-500/50 hover:text-accent-400 transition-all shadow-sm"
        >
          <ArrowLeft className="h-4 w-4" /> [←] RETURN TO FINDINGS INDEX
        </Link>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 rounded border border-accent-500/30 bg-accent-500/10 px-3 py-1 text-xs font-mono font-bold text-accent-400">
            <span className="h-2 w-2 rounded-full bg-accent-500 animate-pulse shadow-[0_0_6px_#00ff66]" />
            <span>LLM_REMEDIATION_CORE // ONLINE</span>
          </div>
        </div>
      </div>

      {/* Main Studio Title & Target Overview Strip */}
      <div className="reg-frame relative overflow-hidden rounded border border-hairline bg-surface-1/80 p-6 shadow-md backdrop-blur">
        <span aria-hidden className="reg-tick reg-tr" />
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-[10px] font-mono font-bold uppercase tracking-wider text-accent-400 mb-1">
              <Zap className="h-3.5 w-3.5" /> CONTEXT-AWARE AUTOMATED DEFENSIVE PATCHING
            </div>
            <h1 className="font-mono text-2xl lg:text-3xl font-bold text-ink-primary tracking-tight">
              Remediation &amp; Defense Studio
            </h1>
            <p className="mt-1 font-sans text-xs text-ink-muted">
              Synthesizing production-grade defensive playbooks grounded strictly in real host telemetry. Zero offensive payloads.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Button
              loading={gen.isPending}
              onClick={() => gen.mutate(!!remediation)}
              className="font-mono uppercase font-bold tracking-wider text-xs px-5 py-2.5"
            >
              {remediation ? <RotateCw className="h-4 w-4" /> : <Sparkles className="h-4 w-4" />}
              {remediation ? "REGENERATE PATCH" : "SYNTHESIZE DEFENSIVE FIX"}
            </Button>
          </div>
        </div>
      </div>

      {/* Full Width 3-Column Responsive Grid */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[360px_1fr_360px]">
        {/* Left Column: Finding Context & Attack Chain */}
        <FindingContext finding={f} />

        {/* Center Column: Interactive Patch Studio & Terminal */}
        <div className="space-y-5">
          {/* Format Selection Tabs with High-Tech Badges */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
            {KINDS.map((k) => {
              const Icon = k.icon;
              const active = kind === k.key;
              return (
                <button
                  key={k.key}
                  onClick={() => setKind(k.key)}
                  className={`flex flex-col items-start justify-between rounded border p-3.5 text-left transition-all ${
                    active
                      ? "border-accent-500 bg-accent-500/10 shadow-[0_0_15px_rgba(0,255,102,0.15)] ring-1 ring-accent-500"
                      : "border-hairline bg-surface-1/60 hover:border-accent-500/40 hover:bg-surface-2/60"
                  }`}
                >
                  <div className="flex items-center gap-2 font-bold text-xs">
                    <div className={`flex h-6 w-6 items-center justify-center rounded ${active ? "bg-accent-500 text-black shadow-[0_0_8px_#00ff66]" : "bg-surface-2 text-ink-muted"}`}>
                      <Icon className="h-3.5 w-3.5" />
                    </div>
                    <span className={active ? "text-accent-400 font-bold" : "text-ink-primary"}>{k.label}</span>
                  </div>
                  <span className="mt-2 text-[10px] text-ink-muted leading-tight font-sans">{k.desc}</span>
                </button>
              );
            })}
          </div>

          {/* Generating Loading State */}
          {gen.isPending && (
            <div className="rounded border border-accent-500/30 bg-surface-1/90 p-12 text-center shadow-lg">
              <LoadingBlock label="Synthesizing zero-exploit defensive patch with local model…" />
            </div>
          )}

          {/* Refusal Card if AI guardrails reject non-defensive action */}
          {remediation?.refused && (
            <div className="flex items-start gap-3 rounded border border-amber-500/40 bg-amber-500/10 p-5 shadow-sm">
              <Info className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
              <div className="text-xs leading-relaxed text-ink-secondary font-mono">
                <div className="font-bold text-amber-400 mb-0.5">DEFENSIVE GUARDRAIL ENFORCED</div>
                Drishti generates defensive containment fixes only.
                {remediation.reason && (
                  <span className="block text-ink-muted mt-1">{remediation.reason}</span>
                )}
              </div>
            </div>
          )}

          {/* Generated Result View */}
          {remediation && !remediation.refused && (
            <TerminalCenterView remediation={remediation} />
          )}

          {/* Empty Initial State */}
          {!remediation && !gen.isPending && (
            <div className="rounded border border-hairline bg-surface-1/80 p-12 text-center shadow-md">
              <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-accent-500/10 text-accent-400 shadow-[0_0_15px_rgba(0,255,102,0.15)]">
                <Sparkles className="h-7 w-7" />
              </div>
              <h3 className="font-mono font-bold text-ink-primary text-lg">READY TO COMPILE PATCH</h3>
              <p className="mx-auto mt-2 max-w-lg text-xs font-sans text-ink-muted leading-relaxed">
                Click below to synthesize a verified, production-grade <b>{KINDS.find((k) => k.key === kind)?.label}</b> tailored to isolate and remediate this exposure.
              </p>
              <div className="mt-6">
                <button
                  onClick={() => gen.mutate(false)}
                  className="inline-flex items-center gap-2 rounded border border-accent-500 bg-accent-500/20 px-6 py-3 font-mono text-xs font-bold uppercase tracking-wider text-accent-400 hover:bg-accent-500 hover:text-black transition-all shadow-[0_0_15px_rgba(0,255,102,0.2)]"
                >
                  <Sparkles className="h-4 w-4" /> SYNTHESIZE {KINDS.find((k) => k.key === kind)?.label}
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Execution Runbook & Actions */}
        <ExecutionSidebar
          remediation={remediation}
          onResolve={() => setStatus.mutate("resolved")}
          onRemediating={() => setStatus.mutate("remediating")}
          resolving={setStatus.isPending}
        />
      </div>
    </div>
  );
}

function FindingContext({ finding: f }: { finding: Finding }) {
  return (
    <div className="space-y-4">
      <div className="rounded border border-hairline bg-surface-1/80 p-5 shadow-sm space-y-4">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-1.5">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-ink-muted">
              TARGET FINDING SPECIFICATION
            </span>
            {f.source === "endpoint" ? (
              <span className="rounded border border-cyan-500/40 bg-cyan-500/10 px-2 py-0.5 text-[9px] font-mono font-bold text-cyan-400">
                [ENDPOINT SOFTWARE]
              </span>
            ) : (
              <span className="rounded border border-hairline bg-surface-2 px-2 py-0.5 text-[9px] font-mono font-bold text-ink-muted">
                [NETWORK SCAN]
              </span>
            )}
            {f.in_kev && (
              <span className="rounded border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-[9px] font-mono font-bold text-red-400 animate-pulse">
                🚨 KNOWN EXPLOITED — CISA KEV
              </span>
            )}
          </div>
          <h3 className="font-sans text-sm font-bold leading-snug text-ink-primary">
            {f.title}
          </h3>
          <div className="mt-2.5 flex items-center gap-2">
            <SeverityBadge severity={f.severity} score={f.cvss} />
            <span className="font-mono text-xs font-bold text-ink-secondary">CVSS {f.cvss}</span>
          </div>
        </div>

        <div className="space-y-2.5 border-t border-b border-hairline py-3.5">
          <DefRow label="Evidence Source" value={f.source === "endpoint" ? "Endpoint Telemetry (Software Inventory)" : "Network DeepScan / Nmap Banner"} mono />
          {f.observed_product && <DefRow label="Affected Product" value={f.observed_product} mono />}
          {f.observed_version && <DefRow label="Observed Version" value={f.observed_version} mono />}
          <DefRow label="CVE Identifier" value={f.cve_id ?? "N/A (Architecture / ACL Flaw)"} mono />
          <DefRow label="Fixed Version" value={f.fixed_version ?? "<patched-version>"} mono />
          <DefRow label="KEV State" value={f.in_kev ? "YES (CISA KEV Listed)" : "NO"} mono />
          <DefRow label="Target Host" value={f.asset_hostname ?? f.asset_ip} mono />
          <DefRow label="Host IP Address" value={f.asset_ip} mono />
          <DefRow label="Exposed Port" value={f.service_port ? String(f.service_port) : (f.source === "endpoint" ? "Local Host Process / Package" : "All Ingress / Egress Ports")} mono />
          <DefRow label="Finding Status" value={f.status.toUpperCase()} mono />
        </div>


        {f.description && (
          <div className="rounded bg-surface-2/60 p-3.5 text-xs leading-relaxed text-ink-secondary border-l-2 border-accent-500 space-y-1">
            <span className="block font-bold text-[10px] uppercase tracking-wider text-ink-muted">
              EXPOSURE VECTOR &amp; THREAT CHAIN
            </span>
            <p className="font-sans">{f.description}</p>
          </div>
        )}
      </div>

      {/* Defense Guardrails Card */}
      <Card className="p-4 border border-emerald-500/30 bg-emerald-500/10 space-y-2">
        <div className="flex items-center gap-2 text-xs font-mono font-bold text-emerald-400">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          <span>OUTPUT SAFETY GUARDRAILS ACTIVE</span>
        </div>
        <p className="text-[11px] font-mono text-emerald-300/80 leading-relaxed">
          Zero offensive exploit markers permitted. Playbooks strictly enforce non-destructive containment and reversible configurations.
        </p>
      </Card>
    </div>
  );
}

function DefRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-2 text-xs">
      <span className="text-ink-muted font-medium">{label}</span>
      <span className={`font-semibold ${mono ? "font-mono text-ink-primary" : "text-ink-primary"}`}>
        {value}
      </span>
    </div>
  );
}

function TerminalCenterView({ remediation }: { remediation: Remediation }) {
  const [copied, setCopied] = useState(false);
  const toast = useToast();

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(remediation.script);
      setCopied(true);
      toast.show("Playbook copied to clipboard", "success");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.show("Failed to copy code", "error");
    }
  };

  return (
    <div className="space-y-4">
      {/* Executive Summary Card */}
      <Card className="p-5 border border-hairline bg-surface-1/90 shadow-2xl relative">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="max-w-xl">
            <span className="inline-block text-[10px] font-mono font-bold uppercase tracking-wider text-accent-400 mb-1">
              [SYNTHESIZED STRATEGY]
            </span>
            <h2 className="font-display text-base lg:text-lg font-bold text-ink-primary tracking-tight">{remediation.title}</h2>
            <p className="mt-1.5 text-xs leading-relaxed text-ink-secondary">{remediation.summary}</p>
            {remediation.model && (
              <div className="mt-3 inline-flex items-center gap-1.5 rounded border border-hairline bg-surface-2/60 px-2.5 py-1 text-[11px] font-mono text-ink-secondary">
                <Cpu className="h-3 w-3 text-accent-400" />
                <span>VERIFIED MODEL:</span>
                <span className="font-bold text-ink-primary">{remediation.model}</span>
              </div>
            )}
          </div>
          {remediation.estimated_risk_reduction != null && (
            <div className="rounded border border-emerald-500/30 bg-emerald-500/10 p-3 text-center min-w-[120px]">
              <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-400">
                RISK REDUCTION
              </div>
              <div className="text-xl font-mono font-extrabold text-emerald-300 mt-0.5">
                -{remediation.estimated_risk_reduction}%
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Terminal Code Window */}
      <div className="overflow-hidden rounded border border-hairline bg-canvas shadow-2xl relative">
        <div className="flex items-center justify-between border-b border-hairline bg-surface-1/90 px-4 py-2.5">
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <div className="h-2 w-2 rounded-full bg-red-500/80" />
              <div className="h-2 w-2 rounded-full bg-amber-500/80" />
              <div className="h-2 w-2 rounded-full bg-emerald-500/80" />
            </div>
            <span className="font-mono text-xs font-bold text-accent-400">
              {remediation.kind === "ansible" ? "remediate_exposure.yml" : remediation.kind === "shell" ? "harden_host.sh" : "cloud_policy.sh"}
            </span>
          </div>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 rounded border border-hairline bg-surface-2/60 px-3 py-1 text-xs font-mono font-bold text-ink-primary hover:bg-surface-3 transition-colors"
          >
            {copied ? (
              <>
                <Check className="h-3.5 w-3.5 text-accent-400" />
                <span className="text-accent-400">COPIED</span>
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5 text-ink-muted" />
                <span>COPY CODE</span>
              </>
            )}
          </button>
        </div>

        <pre className="overflow-x-auto p-4 font-mono text-[12px] leading-relaxed text-emerald-300/90 selection:bg-accent-500 selection:text-canvas max-h-[460px] bg-canvas">
          {remediation.script}
        </pre>
      </div>

      {/* Proof of Grounding Accordion */}
      {remediation.context && <AIInputInspector context={remediation.context} />}
    </div>
  );
}

function ExecutionSidebar({
  remediation,
  onResolve,
  onRemediating,
  resolving,
}: {
  remediation?: Remediation | null;
  onResolve: () => void;
  onRemediating: () => void;
  resolving: boolean;
}) {
  return (
    <div className="space-y-4">
      {/* Execution Runbook */}
      <Card className="p-5 border border-hairline bg-surface-1/90 shadow-2xl space-y-4">
        <div className="flex items-center justify-between border-b border-hairline pb-2">
          <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-ink-muted">
            EXECUTION RUNBOOK
          </span>
          <span className="rounded border border-hairline bg-surface-2/60 px-2 py-0.5 text-[10px] font-mono font-bold text-accent-400">
            {remediation?.steps?.length || 0} STEPS
          </span>
        </div>

        {remediation?.steps && remediation.steps.length > 0 ? (
          <div className="space-y-2.5">
            {remediation.steps.map((s, i) => (
              <div key={i} className="flex items-start gap-3 rounded bg-surface-2/50 p-3 text-xs text-ink-secondary border border-hairline">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-accent-500/15 font-mono text-[10px] font-bold text-accent-400 border border-accent-500/30">
                  0{i + 1}
                </span>
                <span className="pt-0.5 leading-relaxed font-mono text-ink-primary">{s}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-6 text-center text-xs font-mono text-ink-muted">
            Synthesize a fix to generate automated step-by-step validation guidance.
          </div>
        )}

        {remediation?.requires_restart && (
          <div className="flex items-center gap-2 rounded bg-amber-500/10 p-3 text-xs font-mono font-semibold text-amber-400 border border-amber-500/30">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span>REQUIRES DAEMON / SERVICE RESTART</span>
          </div>
        )}
      </Card>

      {/* Status Transition Action Card */}
      <Card className="p-5 border border-hairline bg-surface-1/90 shadow-2xl space-y-3">
        <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-ink-muted block">
          WORKFLOW STATUS ACTIONS
        </span>

        <Button
          loading={resolving}
          onClick={onResolve}
          className="w-full bg-emerald-500/20 border border-emerald-500/50 text-emerald-300 font-mono text-xs font-bold hover:bg-emerald-500/30 hover:text-white py-2.5 justify-center"
        >
          <CheckCircle2 className="h-4 w-4" /> MARK FINDING RESOLVED
        </Button>

        <Button
          variant="ghost"
          onClick={onRemediating}
          className="w-full border border-hairline bg-surface-2/60 font-mono text-xs font-semibold text-ink-secondary hover:bg-surface-3 hover:text-ink-primary py-2.5 justify-center"
        >
          MARK IN REMEDIATING STATE
        </Button>
      </Card>
    </div>
  );
}

function AIInputInspector({ context }: { context: Record<string, unknown> }) {
  const [open, setOpen] = useState(false);
  return (
    <Card className="p-0 overflow-hidden border border-hairline bg-surface-1/90 shadow-2xl">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between px-4 py-3 text-xs font-mono font-semibold text-ink-secondary hover:bg-surface-2/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <ChevronRight className={`h-4 w-4 text-ink-muted transition-transform ${open ? "rotate-90" : ""}`} />
          <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-accent-400">
            GROUNDING AUDIT
          </span>
          <span className="text-ink-muted text-[11px]">— Exact telemetry payload passed to LLM</span>
        </div>
        <FileCode className="h-3.5 w-3.5 text-ink-muted" />
      </button>
      {open && (
        <pre className="max-h-72 overflow-auto border-t border-hairline bg-canvas p-4 font-mono text-[11px] leading-relaxed text-emerald-400">
          {JSON.stringify(context, null, 2)}
        </pre>
      )}
    </Card>
  );
}


