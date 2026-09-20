// Drishti v0.1 — Live Network Traffic Analysis Panel | Phase 01
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Clock,
  Globe,
  Network,
  Radio,
  RefreshCw,
  Shield,
  ShieldAlert,
  StopCircle,
  TrendingUp,
  X,
} from "lucide-react";
import { useState } from "react";
import { api } from "../../api/client";
import type { TrackingResults, TrackingSession } from "../../api/types";
import { Button } from "../../components/Button";
import { formatBytes } from "../../lib/format";

export function LiveTrafficPanel({
  initialSession,
  onClose,
}: {
  initialSession: TrackingSession;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [stopped, setStopped] = useState(initialSession.status === "STOPPED");

  // Query live traffic results with 1500ms reactive polling
  const q = useQuery<TrackingResults>({
    queryKey: ["live", "tracking", initialSession.tracking_session_id],
    queryFn: () => api.getLiveTrackingResults(initialSession.tracking_session_id),
    refetchInterval: stopped ? false : 1500,
  });

  const stopMut = useMutation({
    mutationFn: () => api.stopLiveTracking(initialSession.tracking_session_id),
    onSuccess: () => {
      setStopped(true);
      qc.invalidateQueries({ queryKey: ["live", "tracking", initialSession.tracking_session_id] });
    },
  });

  const results = q.data;
  const session = results?.session ?? initialSession;
  const metrics = results?.metrics;
  const protocols = results?.protocols;
  const topDests = results?.top_destinations ?? [];
  const behaviour = results?.current_behaviour;
  const evidence = results?.evidence ?? [];
  const modelStatus = results?.model_status;
  const networkVisibility = results?.network_visibility;
  const visibilityReason = results?.visibility_reason;
  const windowCount = results?.window_count ?? 0;
  const forecast = results?.forecast;


  const isLive = session.status === "LIVE" && !stopped;
  const isUnavailable = session.status === "UNAVAILABLE" || networkVisibility === "UNAVAILABLE";

  return (
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center bg-black/75 p-3 sm:p-6 backdrop-blur-xs font-mono"
      onClick={onClose}
    >
      <div
        className="max-h-[92vh] w-full max-w-4xl overflow-y-auto rounded-lg border border-hairline/80 bg-[#070b09] p-5 shadow-[0_0_50px_rgba(0,0,0,0.85)]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* ── Top Header & Status ─────────────────────────────────────────── */}
        <div className="flex flex-col gap-3 border-b border-hairline/60 pb-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <span
              className={`flex h-10 w-10 items-center justify-center rounded-lg border ${
                isLive
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                  : stopped
                  ? "border-hairline bg-surface-2 text-ink-muted"
                  : "border-amber-500/40 bg-amber-500/10 text-amber-400"
              }`}
            >
              <Radio className={`h-5 w-5 ${isLive ? "animate-pulse" : ""}`} />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-display text-h3 font-bold tracking-tight text-ink-primary">
                  LIVE NETWORK TRAFFIC ANALYSIS
                </span>
                <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[9px] font-bold text-accent-400 border border-hairline">
                  PHASE 02 // AI THREAT DETECTION
                </span>
              </div>
              <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[11px] text-ink-secondary">
                <span>TARGET: <strong className="text-ink-primary">{session.target_hostname || session.target_ip}</strong></span>
                <span>· IP: <strong className="text-accent-400">{session.target_ip}</strong></span>
                {session.target_mac && <span>· MAC: <strong>{session.target_mac}</strong></span>}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Status Pill */}
            {isLive ? (
              <span className="flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-bold text-emerald-400 shadow-[0_0_8px_rgba(0,255,102,0.25)]">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
                ● LIVE CAPTURE
              </span>
            ) : stopped ? (
              <span className="flex items-center gap-1.5 rounded-full border border-hairline bg-surface-2 px-2.5 py-1 text-[10px] font-bold text-ink-muted">
                ○ STOPPED
              </span>
            ) : isUnavailable ? (
              <span className="flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-[10px] font-bold text-amber-400">
                ⚠ CAPTURE UNAVAILABLE
              </span>
            ) : (
              <span className="flex items-center gap-1.5 rounded-full border border-rose-500/40 bg-rose-500/10 px-2.5 py-1 text-[10px] font-bold text-rose-400">
                ⚠ ERROR
              </span>
            )}

            {isLive && (
              <Button
                variant="danger"
                size="sm"
                className="text-[11px] uppercase font-bold"
                onClick={() => stopMut.mutate()}
                disabled={stopMut.isPending}
              >
                <StopCircle className="mr-1.5 h-3.5 w-3.5" /> Stop Tracking
              </Button>
            )}

            <button
              onClick={onClose}
              className="rounded p-1 text-ink-muted hover:bg-surface-2 hover:text-ink-primary transition-colors"
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* ── Informational Notice / Truthful Capture & Model Source ───────── */}
        <div className="mt-4 flex flex-wrap items-center justify-between gap-2 rounded border border-hairline/60 bg-surface-1/70 px-3 py-2 text-[11px] text-ink-muted">
          <div className="flex items-center gap-2">
            <span className="text-ink-secondary">CAPTURE SOURCE:</span>
            <span className="font-bold text-accent-400 border border-hairline bg-surface-2 px-1.5 py-0.2 rounded text-[10px]">
              {session.capture_source}
            </span>
            <span className="text-ink-muted">· SESSION: <code className="text-ink-secondary">{session.tracking_session_id.slice(0, 8)}</code></span>
          </div>
          <div className="flex items-center gap-2">
            {networkVisibility && (
              <span
                className={`flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-bold ${
                  networkVisibility === "VISIBLE"
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                    : networkVisibility === "LIMITED"
                    ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
                    : "border-rose-500/40 bg-rose-500/10 text-rose-400"
                }`}
              >
                <span>VISIBILITY:</span>
                <strong>{networkVisibility}</strong>
              </span>
            )}
            <div className="flex items-center gap-1 text-[10px] text-ink-muted">
              <Clock className="h-3 w-3 text-ink-muted" />
              <span>STARTED: {new Date(session.started_at).toLocaleTimeString()}</span>
            </div>
          </div>
        </div>

        {/* ── AI Model Readiness & Temporal Window Status ─────────────────── */}
        <div className="mt-2 flex flex-wrap items-center justify-between gap-2 rounded border border-hairline/40 bg-surface-1/40 px-3 py-1.5 text-[10px] text-ink-muted">
          <div className="flex items-center gap-2">
            <span className="text-ink-secondary font-semibold">TEMPORAL WINDOWS:</span>
            <span className="text-accent-400 font-bold">
              {windowCount > 0 ? `${windowCount} / 5 Windows [W(t-4)..W(t)]` : "Single Window"}
            </span>
            <span>(10s Window / 5s Stride)</span>
          </div>
          {modelStatus && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-ink-secondary font-semibold">AI MODELS:</span>
              <span className="rounded border border-hairline bg-surface-2 px-1.5 py-0.5 font-bold text-accent-400">
                LSTM: {modelStatus.lstm}
              </span>
              <span className="rounded border border-hairline bg-surface-2 px-1.5 py-0.5 font-bold text-cyan-400">
                TRANSFORMER: {modelStatus.transformer}
              </span>
              <span className="rounded border border-hairline bg-surface-2 px-1.5 py-0.5 font-bold text-indigo-400">
                GNN: {modelStatus.gnn}
              </span>
              <span className="rounded border border-hairline bg-surface-2 px-1.5 py-0.5 font-bold text-purple-400">
                FUSION: {modelStatus.fusion}
              </span>
            </div>
          )}
        </div>

        {/* ── Status Message / Truthful Error Alert ────────────────────────── */}
        {q.isError && (
          <div className="mt-3 rounded border border-rose-500/40 bg-rose-500/10 p-3 text-[11px] text-rose-300 flex items-start gap-2.5">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
            <div>
              <div className="font-bold uppercase tracking-wider text-rose-400">TELEMETRY SYNC ERROR</div>
              <div className="mt-0.5 text-rose-200">
                Failed to communicate with Drishti backend telemetry engine. Retrying...
              </div>
            </div>
          </div>
        )}
        {(session.status_message || visibilityReason) && (
          <div className="mt-3 rounded border border-amber-500/40 bg-amber-500/10 p-3 text-[11px] text-amber-300 flex items-start gap-2.5">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400 mt-0.5" />
            <div>
              <div className="font-bold uppercase tracking-wider text-amber-400">OBSERVATION NOTICE</div>
              <div className="mt-0.5 text-amber-200">
                {visibilityReason || session.status_message}
              </div>
            </div>
          </div>
        )}

        {/* ── Live Traffic Metrics Grid ───────────────────────────────────── */}
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-6">
          <StatBox label="TOTAL PACKETS" value={metrics?.packet_count ?? 0} />
          <StatBox label="ACTIVE FLOWS" value={metrics?.flow_count ?? 0} />
          <StatBox label="TOTAL VOLUME" value={formatBytes(metrics?.byte_count ?? 0)} />
          <StatBox label="PACKETS / SEC" value={`${metrics?.packets_per_sec ?? 0}/s`} tone="accent" />
          <StatBox label="THROUGHPUT" value={`${formatBytes(metrics?.bytes_per_sec ?? 0)}/s`} tone="accent" />
          <StatBox label="CONNECTIONS" value={metrics?.active_connections ?? 0} />
        </div>

        {/* ── Network Protocols Breakdown ─────────────────────────────────── */}
        <div className="mt-4 rounded-lg border border-hairline/60 bg-surface-1/50 p-3.5">
          <div className="flex items-center justify-between border-b border-hairline/40 pb-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-muted flex items-center gap-1.5">
              <Network className="h-3.5 w-3.5 text-accent-400" />
              Observed Network Protocols
            </span>
            <span className="text-[9px] text-ink-muted">Only actively detected protocols shown</span>
          </div>
          <div className="mt-2.5 flex flex-wrap items-center gap-2">
            {protocols?.tcp ? (
              <ProtoBadge name="TCP" count={protocols.tcp} color="text-cyan-400 border-cyan-500/40 bg-cyan-500/10" />
            ) : null}
            {protocols?.udp ? (
              <ProtoBadge name="UDP" count={protocols.udp} color="text-indigo-400 border-indigo-500/40 bg-indigo-500/10" />
            ) : null}
            {protocols?.dns ? (
              <ProtoBadge name="DNS" count={protocols.dns} color="text-emerald-400 border-emerald-500/40 bg-emerald-500/10" />
            ) : null}
            {protocols?.http_https ? (
              <ProtoBadge name="HTTP/HTTPS" count={protocols.http_https} color="text-amber-400 border-amber-500/40 bg-amber-500/10" />
            ) : null}
            {protocols?.icmp ? (
              <ProtoBadge name="ICMP" count={protocols.icmp} color="text-purple-400 border-purple-500/40 bg-purple-500/10" />
            ) : null}
            {protocols?.other ? (
              <ProtoBadge name="OTHER" count={protocols.other} color="text-ink-muted border-hairline bg-surface-2" />
            ) : null}
            {(!protocols || Object.values(protocols).every((v) => v === 0)) && (
              <span className="text-[11px] text-ink-muted italic py-1">No protocol packets observed yet.</span>
            )}
          </div>
        </div>

        {/* ── Current Behaviour & Threat Detection ─────────────────────────── */}
        <div className="mt-4 rounded-lg border border-hairline/70 bg-surface-1/70 p-4">
          <div className="flex items-center justify-between border-b border-hairline/40 pb-2.5">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-accent-400" />
              <span className="text-[11px] font-bold uppercase tracking-wider text-ink-primary">
                Current Behaviour Analysis
              </span>
            </div>
            {behaviour && (
              <VerdictBadge verdict={behaviour.verdict} confidence={behaviour.confidence} category={behaviour.attack_category} />
            )}
          </div>

          <div className="mt-3">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-muted mb-1.5">
              Factual Observed Signals (Real Traffic Only):
            </div>
            {behaviour?.signals && behaviour.signals.length > 0 ? (
              <ul className="space-y-1.5 text-[11px]">
                {behaviour.signals.map((sig, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-ink-secondary">
                    <span className="text-accent-400 mt-0.5">•</span>
                    <span>{sig}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-[11px] text-ink-muted italic">
                Awaiting sufficient packet telemetry to formulate behavioral baseline…
              </p>
            )}
          </div>
        </div>

        {/* ── Future Behaviour Forecasting & MITRE ATT&CK ────────────────── */}
        <div className="mt-4 rounded-lg border border-hairline/70 bg-surface-1/70 p-4">
          <div className="flex flex-wrap items-center justify-between border-b border-hairline/40 pb-2.5 gap-2">
            <div className="flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-cyan-400" />
              <span className="text-[11px] font-bold uppercase tracking-wider text-ink-primary">
                Future Network Behaviour Forecast
              </span>
              <span className="rounded bg-cyan-500/10 px-1.5 py-0.2 text-[9px] font-bold text-cyan-400 border border-cyan-500/30">
                PHASE 03 // MULTI-STEP PREDICTION
              </span>
            </div>
            {forecast?.is_available && (
              <div className="flex items-center gap-2">
                <span className="text-[9px] text-ink-muted">RISK LEVEL:</span>
                <span
                  className={`rounded border px-2 py-0.5 text-[10px] font-bold uppercase ${
                    forecast.composite_risk_level === "CRITICAL"
                      ? "border-rose-500/50 bg-rose-500/20 text-rose-300"
                      : forecast.composite_risk_level === "HIGH"
                      ? "border-amber-500/50 bg-amber-500/20 text-amber-300"
                      : forecast.composite_risk_level === "MEDIUM"
                      ? "border-yellow-500/50 bg-yellow-500/10 text-yellow-300"
                      : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                  }`}
                  title={forecast.risk_formula}
                >
                  {forecast.composite_risk_level} ({Math.round(forecast.composite_risk_score)}/100)
                </span>
              </div>
            )}
          </div>

          {/* Horizon Multi-step Cards */}
          {forecast?.is_available && forecast.horizon_steps && forecast.horizon_steps.length > 0 ? (
            <div className="mt-3 grid grid-cols-1 gap-2.5 sm:grid-cols-3">
              {forecast.horizon_steps.map((step, idx) => (
                <div
                  key={idx}
                  className="rounded border border-hairline/60 bg-surface-2/70 p-2.5 shadow-sm"
                >
                  <div className="flex items-center justify-between">
                    <span className="rounded bg-cyan-500/15 border border-cyan-500/30 px-1.5 py-0.2 text-[9px] font-bold text-cyan-300">
                      {step.step}
                    </span>
                    <span className="rounded bg-black/40 border border-hairline px-1.5 py-0.2 text-[8.5px] font-bold tracking-wider text-amber-400">
                      ● {step.status_label}
                    </span>
                  </div>

                  <div className="mt-2 text-[11px] font-bold text-ink-primary leading-tight">
                    {step.state.replace(/_/g, " ")}
                  </div>

                  <div className="mt-1 flex items-center justify-between text-[10px]">
                    <span className="text-ink-muted">Confidence:</span>
                    <span className="font-bold text-cyan-400">{Math.round(step.probability * 100)}%</span>
                  </div>

                  {step.contributing_signals && step.contributing_signals.length > 0 && (
                    <div className="mt-1.5 border-t border-hairline/40 pt-1 text-[9.5px] text-ink-secondary">
                      {step.contributing_signals[0]}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="mt-3 rounded border border-hairline/40 bg-surface-2/40 p-3 text-center">
              <div className="text-[11px] font-semibold text-amber-400">
                {forecast?.status || "FORECAST UNAVAILABLE (INSUFFICIENT HISTORY)"}
              </div>
              <div className="mt-1 text-[10px] text-ink-muted">
                Requires at least 2 consecutive 10-second observation windows to formulate validated temporal trajectory.
              </div>
            </div>
          )}

          {/* Explainability ("WHY?") & MITRE ATT&CK Mapping */}
          {forecast?.is_available && (
            <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
              {/* Explainability */}
              <div className="rounded border border-hairline/40 bg-surface-2/40 p-2.5">
                <div className="flex items-center justify-between border-b border-hairline/30 pb-1">
                  <span className="text-[9.5px] font-bold uppercase tracking-wider text-ink-primary">
                    WHY THIS FORECAST? (CONTRIBUTORS)
                  </span>
                  {forecast.explainability?.state_transition && (
                    <span className="rounded bg-black/40 px-1.5 py-0.2 text-[8.5px] font-mono text-cyan-400">
                      TRAJECTORY: {forecast.explainability.state_transition}
                    </span>
                  )}
                </div>
                <ul className="mt-2 space-y-1 text-[10.5px]">
                  {forecast.explainability?.top_signals.map((sig, idx) => (
                    <li key={idx} className="flex items-start gap-1.5 text-ink-secondary">
                      <span className="text-cyan-400 mt-0.5">▸</span>
                      <span>{sig}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* MITRE ATT&CK & CAPEC */}
              <div className="rounded border border-hairline/40 bg-surface-2/40 p-2.5">
                <div className="flex items-center justify-between border-b border-hairline/30 pb-1">
                  <span className="text-[9.5px] font-bold uppercase tracking-wider text-ink-primary">
                    MITRE ATT&CK & CAPEC MAPPING
                  </span>
                  {forecast.mitre_attack && (
                    <span className="rounded bg-rose-500/10 border border-rose-500/30 px-1.5 py-0.2 text-[8.5px] font-bold text-rose-300">
                      {Math.round(forecast.mitre_attack.confidence * 100)}% CONFIDENCE
                    </span>
                  )}
                </div>

                {forecast.mitre_attack ? (
                  <div className="mt-2 space-y-1.5 text-[10.5px]">
                    <div className="flex items-center justify-between">
                      <span className="text-ink-muted">Tactic:</span>
                      <span className="font-bold text-ink-primary">
                        {forecast.mitre_attack.tactic} ({forecast.mitre_attack.tactic_id})
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-ink-muted">Technique:</span>
                      <span className="font-bold text-accent-400">
                        {forecast.mitre_attack.technique} ({forecast.mitre_attack.technique_id})
                      </span>
                    </div>
                    {forecast.mitre_attack.capec_id && (
                      <div className="flex items-center justify-between border-t border-hairline/30 pt-1 text-[10px]">
                        <span className="text-ink-muted">CAPEC Pattern:</span>
                        <span className="text-amber-400">
                          {forecast.mitre_attack.capec_name} ({forecast.mitre_attack.capec_id})
                        </span>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="mt-2 text-[10px] text-ink-muted italic">
                    Traffic aligns with benign baseline. No adversarial ATT&CK technique mapped.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* ── Top Destinations ────────────────────────────────────────────── */}
        <div className="mt-4 rounded-lg border border-hairline/60 bg-surface-1/40 p-3.5">
          <div className="flex items-center justify-between border-b border-hairline/40 pb-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-muted flex items-center gap-1.5">
              <Globe className="h-3.5 w-3.5 text-accent-400" />
              Observed Top Destinations ({topDests.length})
            </span>
            <span className="text-[9px] text-ink-muted">Filtered strictly to target device communications</span>
          </div>

          {topDests.length === 0 ? (
            <div className="py-4 text-center text-[11px] text-ink-muted italic">
              No outbound or inbound connections observed for this device.
            </div>
          ) : (
            <div className="mt-2.5 overflow-x-auto">
              <table className="w-full text-left text-[11px]">
                <thead>
                  <tr className="border-b border-hairline/40 text-[9px] uppercase tracking-wider text-ink-muted">
                    <th className="pb-1.5 font-semibold">Destination IP</th>
                    <th className="pb-1.5 font-semibold">Port</th>
                    <th className="pb-1.5 font-semibold">Protocol</th>
                    <th className="pb-1.5 font-semibold">Packets/Conns</th>
                    <th className="pb-1.5 font-semibold text-right">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline/30">
                  {topDests.map((dest, i) => (
                    <tr key={`${dest.destination_ip}:${dest.destination_port}:${i}`} className="hover:bg-surface-2/40">
                      <td className="py-2 font-bold text-ink-primary">{dest.destination_ip}</td>
                      <td className="py-2 text-accent-400">{dest.destination_port}</td>
                      <td className="py-2 text-ink-secondary">{dest.protocol}</td>
                      <td className="py-2 text-ink-primary font-semibold">{dest.connection_count}</td>
                      <td className="py-2 text-right text-ink-muted text-[10px]">
                        {dest.last_seen ? new Date(dest.last_seen).toLocaleTimeString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ── Evidence Stream (Strict Separation) ─────────────────────────── */}
        <div className="mt-4 rounded-lg border border-hairline/60 bg-surface-1/40 p-3.5">
          <div className="flex items-center justify-between border-b border-hairline/40 pb-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-muted flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5 text-accent-400" />
              Traffic Evidence Records ({evidence.length})
            </span>
            <span className="text-[9px] text-accent-400 font-bold">STRICT EVIDENCE SEPARATION</span>
          </div>

          {evidence.length === 0 ? (
            <div className="py-4 text-center text-[11px] text-ink-muted italic">
              No evidence recorded yet.
            </div>
          ) : (
            <div className="mt-2.5 space-y-1.5">
              {evidence.map((ev, i) => (
                <div
                  key={i}
                  className="flex flex-wrap items-center justify-between gap-2 rounded border border-hairline/40 bg-surface-2/60 px-3 py-1.5 text-[10px]"
                >
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-cyan-500/10 border border-cyan-500/30 px-1.5 py-0.2 text-[9px] font-bold text-cyan-400">
                      [{ev.evidence_type}]
                    </span>
                    <span className="text-ink-primary font-bold">{ev.details?.destination_ip}:{ev.details?.destination_port}</span>
                    <span className="text-ink-muted">({ev.details?.protocol})</span>
                  </div>
                  <div className="flex items-center gap-3 text-ink-muted text-[9.5px]">
                    <span>SOURCE: <strong className="text-ink-secondary">{ev.source}</strong></span>
                    <span>CONFIDENCE: <strong className="text-emerald-400">{ev.confidence.toUpperCase()}</strong></span>
                    <span>{new Date(ev.observed_at).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── Footer / Close Action ───────────────────────────────────────── */}
        <div className="mt-5 flex items-center justify-between border-t border-hairline/60 pt-3">
          <div className="text-[10px] text-ink-muted">
            {isLive ? (
              <span className="flex items-center gap-1 text-emerald-400">
                <RefreshCw className="h-3 w-3 animate-spin" /> Live continuous flow aggregation active
              </span>
            ) : (
              <span>Session completed. Historical findings preserved.</span>
            )}
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="text-[11px]">
            Close Panel
          </Button>
        </div>
      </div>
    </div>
  );
}

function StatBox({ label, value, tone = "default" }: { label: string; value: string | number; tone?: "default" | "accent" }) {
  return (
    <div className="rounded border border-hairline bg-surface-1/70 p-2.5 shadow-sm">
      <div className="text-[9px] uppercase tracking-wider text-ink-muted font-semibold">{label}</div>
      <div className={`mt-1 text-h4 font-bold ${tone === "accent" ? "text-accent-400" : "text-ink-primary"}`}>
        {value}
      </div>
    </div>
  );
}

function ProtoBadge({ name, count, color }: { name: string; count: number; color: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded border px-2 py-1 text-[10.5px] font-bold ${color}`}>
      <span>{name}</span>
      <span className="rounded bg-black/40 px-1 text-[9px]">{count}</span>
    </span>
  );
}

function VerdictBadge({
  verdict,
  confidence,
  category,
}: {
  verdict: string;
  confidence: number;
  category?: string | null;
}) {
  let badgeColor = "border-emerald-500/40 bg-emerald-500/10 text-emerald-400";
  if (verdict === "ANOMALOUS") {
    badgeColor = "border-rose-500/50 bg-rose-500/15 text-rose-400";
  } else if (verdict === "SUSPICIOUS") {
    badgeColor = "border-amber-500/50 bg-amber-500/15 text-amber-400";
  } else if (verdict === "INSUFFICIENT_DATA") {
    badgeColor = "border-hairline bg-surface-2 text-ink-muted";
  }

  return (
    <div className="flex items-center gap-2">
      {category && (
        <span className="rounded border border-rose-500/40 bg-rose-500/10 px-2 py-0.5 text-[10px] font-bold text-rose-300">
          [{category.toUpperCase()}]
        </span>
      )}
      <span className={`rounded border px-2.5 py-0.5 text-[11px] font-bold uppercase ${badgeColor}`}>
        {verdict} ({Math.round(confidence * 100)}%)
      </span>
    </div>
  );
}
