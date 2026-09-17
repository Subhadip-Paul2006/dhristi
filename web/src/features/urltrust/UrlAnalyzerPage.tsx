// Drishti v0.1 — URL trust analyzer page | 11-Jul-2026
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import {
  AlertTriangle,
  CheckCircle2,
  Globe,
  HelpCircle,
  Lock,
  MinusCircle,
  Search,
  ShieldCheck,
  Sparkles,
  Unlink,
  WifiOff,
  XCircle,
} from "lucide-react";
import { useState } from "react";
import { api, ApiError } from "../../api/client";
import type {
  SignalStatus,
  TrustBand,
  UrlAnalysisResult,
  UrlSignal,
} from "../../api/types";
import { Card, EmptyState } from "../../components/primitives";
import { Button } from "../../components/Button";
import { RISK_TEXT, type RiskToken } from "../../lib/format";

/** Band → risk-ramp token (Trusted = teal, Caution = amber, High Risk = coral). */
const BAND_TOKEN: Record<TrustBand, RiskToken> = {
  Trusted: "safe",
  Caution: "medium",
  "High Risk": "critical",
};
const BAND_RING: Record<TrustBand, string> = {
  Trusted: "border-risk-safe/50 bg-risk-safe/10",
  Caution: "border-risk-medium/50 bg-risk-medium/10",
  "High Risk": "border-risk-critical/50 bg-risk-critical/10",
};

/** Each status gets a DISTINCT look. Unavailable states (unknown / not_configured
 * / unreachable) are muted + never rendered as a passing green. */
const STATUS_UI: Record<
  SignalStatus,
  { icon: typeof CheckCircle2; tint: string; label: string; counted: boolean }
> = {
  pass: { icon: CheckCircle2, tint: "text-risk-safe", label: "Pass", counted: true },
  warn: { icon: AlertTriangle, tint: "text-risk-medium", label: "Caution", counted: true },
  fail: { icon: XCircle, tint: "text-risk-critical", label: "Fail", counted: true },
  unknown: { icon: HelpCircle, tint: "text-ink-muted", label: "Unknown", counted: false },
  not_configured: { icon: MinusCircle, tint: "text-ink-muted", label: "Not configured", counted: false },
  unreachable: { icon: WifiOff, tint: "text-ink-muted", label: "Unreachable", counted: false },
};

export function UrlAnalyzerPage() {
  const [url, setUrl] = useState("");
  const qc = useQueryClient();

  const analyze = useMutation({
    mutationFn: (u: string) => api.analyzeUrl(u),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["url-history"] }),
  });

  const history = useQuery({ queryKey: ["url-history"], queryFn: () => api.urlHistory() });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) analyze.mutate(url.trim());
  };

  const result = analyze.data;
  const err = analyze.error as ApiError | null;

  return (
    <div className="console-atmos min-h-screen">
      <div className="mx-auto max-w-4xl space-y-6 p-4 sm:p-6 lg:p-8">
        <header className="border-b border-hairline/60 pb-6">
          <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-accent-400">
            <span className="inline-block h-2 w-2 rounded-full bg-accent-500 shadow-[0_0_8px_#00ff66] animate-pulse" />
            <span>SYS.REPUTATION // URL_TRUST_ANALYZER</span>
          </div>
          <h1 className="mt-2 font-display text-display font-semibold tracking-tight text-ink-primary">
            Autonomous URL &amp; Domain Interrogation
          </h1>
          <p className="mt-1.5 max-w-2xl font-mono text-small text-ink-secondary">
            Inspect live TLS certificate chain, domain registration age, HTTP redirects, and threat-intelligence reputation before establishing sockets.
          </p>
        </header>

        <form onSubmit={submit} className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Globe className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-accent-400/70" />
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="example.com  or  https://c2-domain.com/login"
              aria-label="URL to analyze"
              className="w-full rounded border border-hairline bg-surface-1 py-3 pl-10 pr-4 font-mono text-small text-ink-primary placeholder:text-ink-muted/60 focus-visible:border-accent-500 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent-500 shadow-inner"
            />
          </div>
          <Button type="submit" loading={analyze.isPending} disabled={!url.trim()} className="font-mono uppercase tracking-wider">
            <Search className="h-4 w-4" /> SCAN DOMAIN
          </Button>
        </form>

        {err && (
          <div className="rounded border border-risk-critical/40 bg-risk-critical/10 p-4 font-mono text-small text-risk-critical flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            {err.message || "Couldn't analyze that URL."}
          </div>
        )}

        {!result && !analyze.isPending && !err && (
          <EmptyState
            title="READY FOR TARGET INSPECTION"
            hint="Enter a destination URL or domain above to interrogate SSL, WHOIS, and threat reputation feeds."
          />
        )}

        {result && <ResultView result={result} />}

        {history.data && history.data.length > 0 && (
          <div className="mt-8">
            <div className="mb-2.5 font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-ink-muted">
              RECENT ANALYZED DOMAINS
            </div>
            <div className="reg-frame relative overflow-hidden rounded border border-hairline bg-surface-1/60 shadow-md backdrop-blur">
              <span aria-hidden className="reg-tick reg-tr" />
              <div className="divide-y divide-hairline font-mono">
                {history.data.map((h) => (
                  <div key={h.id} className="flex items-center justify-between gap-3 px-5 py-3 transition-colors hover:bg-surface-2/60">
                    <span className="truncate text-small font-bold text-ink-secondary">{h.url}</span>
                    <span className={clsx("shrink-0 text-small font-bold uppercase", RISK_TEXT[BAND_TOKEN[h.band]])}>
                      {h.band} · {h.score.toFixed(0)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ResultView({ result }: { result: UrlAnalysisResult }) {
  const token = BAND_TOKEN[result.band];
  return (
    <div className="space-y-6">
      {/* Verdict */}
      <div className={clsx("reg-frame relative overflow-hidden rounded border p-6 shadow-lg backdrop-blur", BAND_RING[result.band])}>
        <span aria-hidden className="reg-tick reg-tr" />
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <ShieldCheck className={clsx("h-7 w-7", RISK_TEXT[token])} />
              <span className={clsx("font-mono text-h1 font-bold uppercase tracking-wider", RISK_TEXT[token])}>
                {result.band}
              </span>
            </div>
            <div className="mt-1.5 font-mono text-[11px] text-ink-muted">
              EVALUATED {result.evaluated_count} SIGNALS · HOST: <strong className="text-ink-primary font-bold">{result.website.host}</strong>
            </div>
          </div>
          <div className="text-right font-mono">
            <div className={clsx("font-mono text-[clamp(2.5rem,5vw,3.5rem)] font-bold leading-none tabular-nums", RISK_TEXT[token])}>
              {result.score.toFixed(0)}
              <span className="text-h3 text-ink-muted">/100</span>
            </div>
            <div className="mt-1 text-[10px] font-bold uppercase tracking-[0.16em] text-ink-muted">REPUTATION METRIC</div>
          </div>
        </div>
      </div>

      {/* AI summary */}
      {result.ai_summary && (
        <div className="rounded border border-hairline bg-surface-1/80 p-4 font-mono">
          <div className="mb-2 flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-accent-400">
            <Sparkles className="h-3.5 w-3.5" /> REPUTATION ANALYSIS NARRATIVE
          </div>
          <p className="font-sans text-small leading-relaxed text-ink-secondary">{result.ai_summary}</p>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <WebsitePanel result={result} />
        <ReputationPanel result={result} />
      </div>

      <SignalsPanel signals={result.signals} />

      <p className="text-[11px] text-ink-muted">{result.disclaimer}</p>
    </div>
  );
}

function Row({ label, value, mono = true }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1.5">
      <span className="text-small text-ink-muted">{label}</span>
      <span className={clsx("text-right text-small text-ink-secondary", mono && "font-mono")}>{value}</span>
    </div>
  );
}

function WebsitePanel({ result }: { result: UrlAnalysisResult }) {
  const w = result.website;
  return (
    <Card className="p-4">
      <div className="mb-2 text-small font-medium text-ink-primary">Website details</div>
      <div className="divide-y divide-edge-subtle">
        <Row
          label="Connection"
          value={
            <span className={clsx("inline-flex items-center gap-1", w.https ? "text-risk-safe" : "text-risk-medium")}>
              <Lock className="h-3 w-3" /> {w.scheme.toUpperCase()}
            </span>
          }
        />
        <Row
          label="TLS certificate"
          value={
            w.tls.valid == null
              ? "—"
              : w.tls.valid
                ? `Valid · ${w.tls.issuer ?? "issuer unknown"}`
                : "Invalid / expired"
          }
        />
        {w.tls.expires && <Row label="Certificate expires" value={w.tls.expires} />}
        <Row
          label="Domain age"
          value={w.domain_age_days == null ? "Unknown" : `${w.domain_age_days.toLocaleString()} days`}
        />
        <Row label="Registrar" value={w.registrar ?? "Unknown"} mono={!!w.registrar} />
        <Row label="HTTP status" value={w.http_status ?? "—"} />
        <Row
          label="Final URL"
          value={
            <span className="inline-flex items-center gap-1" title={w.redirects_offsite ? "Redirects off-site" : undefined}>
              {w.redirects_offsite && <Unlink className="h-3 w-3 text-risk-medium" aria-label="Redirects off-site" />}
              <span className="max-w-[220px] truncate">{result.final_url ?? result.url}</span>
            </span>
          }
        />
        {w.redirect_chain.length > 1 && (
          <Row label="Redirects" value={`${w.redirect_chain.length - 1} hop(s)`} />
        )}
      </div>
    </Card>
  );
}

function ReputationPanel({ result }: { result: UrlAnalysisResult }) {
  const { safe_browsing: sb, virustotal: vt } = result.providers;
  return (
    <Card className="p-4">
      <div className="mb-2 text-small font-medium text-ink-primary">Threat-intel reputation</div>
      <div className="space-y-3">
        <ProviderRow
          name="Google Safe Browsing"
          configured={sb.configured}
          state={
            !sb.configured
              ? { kind: "unconfigured" }
              : sb.error
                ? { kind: "error", text: sb.error }
                : sb.verdict === "flagged"
                  ? { kind: "bad", text: `Flagged: ${(sb.threats ?? []).join(", ") || "threat"}` }
                  : { kind: "good", text: "No threats found" }
          }
        />
        <ProviderRow
          name="VirusTotal"
          configured={vt.configured}
          state={
            !vt.configured
              ? { kind: "unconfigured" }
              : vt.error
                ? { kind: "error", text: vt.error }
                : (vt.malicious ?? 0) > 0
                  ? { kind: "bad", text: `${vt.malicious} vendors flag malicious` }
                  : (vt.suspicious ?? 0) > 0
                    ? { kind: "warn", text: `${vt.suspicious} vendors suspicious` }
                    : { kind: "good", text: `Clean (${vt.harmless ?? 0} harmless)` }
          }
        />
      </div>
    </Card>
  );
}

type ProviderState =
  | { kind: "unconfigured" }
  | { kind: "good"; text: string }
  | { kind: "warn"; text: string }
  | { kind: "bad"; text: string }
  | { kind: "error"; text: string };

function ProviderRow({ name, state }: { name: string; configured: boolean; state: ProviderState }) {
  const tint =
    state.kind === "good"
      ? "text-risk-safe"
      : state.kind === "warn"
        ? "text-risk-medium"
        : state.kind === "bad"
          ? "text-risk-critical"
          : "text-ink-muted";
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-small text-ink-secondary">{name}</span>
      {state.kind === "unconfigured" ? (
        <span className="rounded-sm border border-dashed border-edge-subtle px-2 py-0.5 text-[11px] text-ink-muted">
          Not configured — add a key to enable
        </span>
      ) : (
        <span className={clsx("text-small font-medium", tint)}>{state.text}</span>
      )}
    </div>
  );
}

function SignalsPanel({ signals }: { signals: UrlSignal[] }) {
  const counted = signals.filter((s) => s.counted).length;
  return (
    <Card className="p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-small font-medium text-ink-primary">Signals</div>
        <div className="text-[11px] text-ink-muted">
          {counted} of {signals.length} counted toward the score
        </div>
      </div>
      <ul className="space-y-1.5">
        {signals.map((s) => {
          const ui = STATUS_UI[s.status];
          const Icon = ui.icon;
          return (
            <li
              key={s.key}
              className={clsx(
                "flex items-start gap-2.5 rounded-sm px-2 py-1.5",
                ui.counted ? "bg-bg-raised/30" : "border border-dashed border-edge-subtle opacity-70",
              )}
            >
              <Icon className={clsx("mt-0.5 h-4 w-4 shrink-0", ui.tint)} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-small text-ink-primary">{s.label}</span>
                  <span className={clsx("text-[10px] uppercase tracking-[0.02em]", ui.tint)}>{ui.label}</span>
                  {!ui.counted && (
                    <span className="text-[10px] text-ink-muted">· not counted</span>
                  )}
                </div>
                <div className="text-[12px] text-ink-muted">{s.detail}</div>
              </div>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
