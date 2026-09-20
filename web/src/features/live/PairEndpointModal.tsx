// Drishti — Pair Endpoint Agent Modal | Phase 01 Foundation
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Laptop,
  CheckCircle2,
  AlertTriangle,
  X,
  RefreshCw,
  Terminal,
  Activity,
  Radio,
} from "lucide-react";
import { api, ApiError } from "../../api/client";
import type { EndpointAgent, EndpointPairingSubmitResult } from "../../api/types";
import { Button } from "../../components/Button";

type PairingState =
  | "WAITING"
  | "PAIRING"
  | "PAIRED"
  | "ALREADY_PAIRED"
  | "EXPIRED_CODE"
  | "INVALID_CODE"
  | "UNAUTHORIZED"
  | "ERROR";

interface PairEndpointModalProps {
  onClose: () => void;
}

export function PairEndpointModal({ onClose }: PairEndpointModalProps) {
  const qc = useQueryClient();
  const [code, setCode] = useState("");
  const [state, setState] = useState<PairingState>("WAITING");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [lastPaired, setLastPaired] = useState<EndpointPairingSubmitResult | null>(null);

  // Poll registered endpoint agents every 4 seconds to observe real heartbeat status
  const agentsQuery = useQuery({
    queryKey: ["endpoint", "agents"],
    queryFn: () => api.listEndpointAgents(),
    refetchInterval: 4000,
  });

  const pairMutation = useMutation({
    mutationFn: (rawCode: string) => api.pairEndpointAgent(rawCode),
    onMutate: () => {
      setState("PAIRING");
      setErrorMessage(null);
    },
    onSuccess: (data) => {
      setState("PAIRED");
      setLastPaired(data);
      setCode("");
      qc.invalidateQueries({ queryKey: ["endpoint", "agents"] });
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        const msg = (err.message || "").toLowerCase();
        if (msg.includes("expired")) {
          setState("EXPIRED_CODE");
          setErrorMessage("Pairing code has expired. Please restart the agent for a fresh code.");
        } else if (msg.includes("already consumed") || msg.includes("already paired") || msg.includes("reused")) {
          setState("ALREADY_PAIRED");
          setErrorMessage("This pairing code was already consumed. Codes are strictly one-time use.");
        } else if (msg.includes("invalid") || msg.includes("not found")) {
          setState("INVALID_CODE");
          setErrorMessage("Invalid pairing code. Check the 8-character code on the agent console.");
        } else if (err.status === 401 || err.status === 403 || msg.includes("organization")) {
          setState("UNAUTHORIZED");
          setErrorMessage("Unauthorized or organization scope mismatch.");
        } else {
          setState("ERROR");
          setErrorMessage(err.message || "Pairing failed.");
        }
      } else {
        setState("ERROR");
        setErrorMessage("Network or connection error during pairing.");
      }
    },
  });

  const handlePairSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanCode = code.trim().toUpperCase();
    if (!cleanCode) return;
    pairMutation.mutate(cleanCode);
  };

  const formatCodeInput = (val: string) => {
    // Strip everything except alphanumeric, capitalize, insert dash after 4 chars
    const cleaned = val.replace(/[^A-Za-z0-9]/g, "").toUpperCase().slice(0, 8);
    if (cleaned.length > 4) {
      setCode(`${cleaned.slice(0, 4)}-${cleaned.slice(4)}`);
    } else {
      setCode(cleaned);
    }
  };

  const agents = agentsQuery.data ?? [];

  return (
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="max-h-[90vh] w-full max-w-xl overflow-hidden rounded-lg border border-hairline-soft bg-surface-1 shadow-2xl flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-hairline px-5 py-4 bg-surface-2/60">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-md border border-accent-500/30 bg-accent-500/10 text-accent-400">
              <Laptop className="h-4 w-4" />
            </div>
            <div>
              <div className="font-mono text-xs uppercase tracking-wider text-accent-400">
                Phase 01 · Zero Fabrication
              </div>
              <h2 className="text-base font-semibold text-ink">Pair Endpoint Agent</h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1.5 text-ink-muted transition-colors hover:bg-surface-3 hover:text-ink"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6">
          {/* Pairing Code Input Section */}
          <div className="rounded-md border border-hairline bg-surface-2 p-4">
            <div className="mb-2 text-xs text-ink-muted">
              Start the Drishti Endpoint Agent on the host (Windows / macOS). Enter the 8-character pairing code
              displayed in the agent console below.
            </div>

            <form onSubmit={handlePairSubmit} className="mt-3 space-y-3">
              <label className="block text-[11px] font-mono uppercase text-ink-muted">
                Enter Pairing Code (5-minute expiration)
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={code}
                  onChange={(e) => formatCodeInput(e.target.value)}
                  placeholder="e.g. AB7X-92KF"
                  maxLength={9}
                  className="flex-1 rounded border border-hairline bg-surface-1 px-3 py-2 font-mono text-sm tracking-widest text-ink uppercase placeholder:text-ink-muted/50 focus:border-accent-500 focus:outline-none"
                  autoFocus
                />
                <Button
                  type="submit"
                  disabled={code.replace(/[^A-Za-z0-9]/g, "").length < 8 || state === "PAIRING"}
                  variant="primary"
                  className="px-5 font-mono text-xs"
                >
                  {state === "PAIRING" ? (
                    <span className="flex items-center gap-1.5">
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" /> Pairing...
                    </span>
                  ) : (
                    "PAIR"
                  )}
                </Button>
              </div>
            </form>

            {/* State Feedback Banners */}
            {state === "PAIRED" && lastPaired && (
              <div className="mt-3 rounded border border-risk-low/40 bg-risk-low/10 p-3 text-xs text-risk-low">
                <div className="flex items-center gap-1.5 font-semibold">
                  <CheckCircle2 className="h-4 w-4" /> Endpoint Agent Registered
                </div>
                <div className="mt-1 font-mono text-[11px] text-ink">
                  Hostname: <span className="font-semibold text-accent-400">{lastPaired.agent.hostname}</span> · OS:{" "}
                  {lastPaired.agent.os} ({lastPaired.agent.os_version})
                </div>
                <div className="mt-0.5 text-[10px] text-ink-muted">
                  Agent successfully paired and authorized. Heartbeat synchronization started.
                </div>
              </div>
            )}

            {state === "ALREADY_PAIRED" && (
              <div className="mt-3 rounded border border-risk-medium/40 bg-risk-medium/10 p-3 text-xs text-risk-medium flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold">Already Paired</div>
                  <div className="text-[11px] text-ink-muted">{errorMessage}</div>
                </div>
              </div>
            )}

            {state === "EXPIRED_CODE" && (
              <div className="mt-3 rounded border border-risk-critical/40 bg-risk-critical/10 p-3 text-xs text-risk-critical flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold">Expired Code</div>
                  <div className="text-[11px] text-ink-muted">{errorMessage}</div>
                </div>
              </div>
            )}

            {state === "INVALID_CODE" && (
              <div className="mt-3 rounded border border-risk-critical/40 bg-risk-critical/10 p-3 text-xs text-risk-critical flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold">Invalid Code</div>
                  <div className="text-[11px] text-ink-muted">{errorMessage}</div>
                </div>
              </div>
            )}

            {state === "UNAUTHORIZED" && (
              <div className="mt-3 rounded border border-risk-critical/40 bg-risk-critical/10 p-3 text-xs text-risk-critical flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold">Unauthorized</div>
                  <div className="text-[11px] text-ink-muted">{errorMessage}</div>
                </div>
              </div>
            )}

            {state === "ERROR" && (
              <div className="mt-3 rounded border border-risk-critical/40 bg-risk-critical/10 p-3 text-xs text-risk-critical flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <div>
                  <div className="font-semibold">Pairing Error</div>
                  <div className="text-[11px] text-ink-muted">{errorMessage}</div>
                </div>
              </div>
            )}
          </div>

          {/* Registered Endpoint Agents List */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-accent-400" />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-ink font-mono">
                  Registered Endpoint Agents ({agents.length})
                </h3>
              </div>
              <span className="font-mono text-[10px] text-ink-muted flex items-center gap-1">
                <Radio className="h-3 w-3 text-accent-400 animate-pulse" /> Live Status Poll
              </span>
            </div>

            {agents.length === 0 ? (
              <div className="rounded-md border border-dashed border-hairline p-6 text-center text-xs text-ink-muted bg-surface-2/40">
                <Terminal className="h-5 w-5 mx-auto mb-2 text-ink-muted/60" />
                No endpoint agents paired in this organization yet.
                <div className="mt-2 text-[11px] font-mono text-ink-muted/80">
                  Run: <code className="text-accent-400">python endpoint-agent/cli.py --server http://localhost:8000</code>
                </div>
              </div>
            ) : (
              <div className="space-y-2.5">
                {agents.map((ag) => (
                  <AgentCard key={ag.id} agent={ag} />
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-hairline px-5 py-3 bg-surface-2/40 text-[11px] text-ink-muted font-mono">
          <span>Status derived by server last heartbeat (ONLINE &lt;60s · STALE &lt;180s)</span>
          <Button variant="ghost" onClick={onClose} className="text-xs">
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}

function AgentCard({ agent }: { agent: EndpointAgent }) {
  const isOnline = agent.status === "ONLINE";
  const isStale = agent.status === "STALE";

  const statusBadge = isOnline ? (
    <span className="inline-flex items-center gap-1 rounded-full border border-risk-low/50 bg-risk-low/10 px-2 py-0.5 text-[10px] font-mono font-semibold text-risk-low">
      <span className="h-1.5 w-1.5 rounded-full bg-risk-low animate-ping" /> ONLINE
    </span>
  ) : isStale ? (
    <span className="inline-flex items-center gap-1 rounded-full border border-risk-medium/50 bg-risk-medium/10 px-2 py-0.5 text-[10px] font-mono font-semibold text-risk-medium">
      <span className="h-1.5 w-1.5 rounded-full bg-risk-medium" /> STALE
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-full border border-hairline bg-surface-3 px-2 py-0.5 text-[10px] font-mono font-semibold text-ink-muted">
      <span className="h-1.5 w-1.5 rounded-full bg-ink-muted/60" /> OFFLINE
    </span>
  );

  const formatTime = (iso: string | null) => {
    if (!iso) return "Never";
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch {
      return iso;
    }
  };

  return (
    <div className="rounded-md border border-hairline bg-surface-2 p-3 text-xs transition hover:border-hairline-soft">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <Laptop className="h-4 w-4 text-accent-400" />
          <span className="font-semibold text-ink font-mono">{agent.hostname}</span>
          <span className="rounded bg-surface-3 px-1.5 py-0.5 text-[10px] font-mono text-ink-muted">
            {agent.os} {agent.os_version}
          </span>
        </div>
        {statusBadge}
      </div>

      <div className="mt-2.5 grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-[11px] text-ink-muted">
        <div>
          Agent ID: <span className="text-ink">{agent.agent_id.slice(0, 8)}...</span>
        </div>
        <div>
          Agent Version: <span className="text-ink">v{agent.agent_version}</span>
        </div>
        <div>
          Current IP: <span className="text-ink">{agent.current_ip || "Unknown"}</span>
        </div>
        <div>
          Last Heartbeat: <span className="text-ink">{formatTime(agent.last_heartbeat)}</span>
        </div>
      </div>
    </div>
  );
}
