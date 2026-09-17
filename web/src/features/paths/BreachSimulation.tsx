// Drishti — Breach Simulation overlay. Replays a REAL computed attack path as a
// step-by-step intrusion (MITRE ATT&CK tactics), then shows the fix severing the
// chain. Pure visualisation of engine output — no exploit is ever run.
import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  ChevronRight,
  Crosshair,
  Globe,
  Pause,
  Play,
  RotateCcw,
  Shield,
  ShieldCheck,
  Skull,
  X,
} from "lucide-react";
import type { PathDetail } from "../../api/types";
import { Button } from "../../components/Button";
import { moneyFull } from "../../lib/format";
import { RISK_HEX } from "../../lib/format";
import { buildBreachFrames, containmentPlan, type BreachFrame } from "./breachSim";

const TICK_MS = 1600;

function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const m = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(m.matches);
    const on = () => setReduced(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return reduced;
}

const TACTIC_HEX: Record<BreachFrame["tactic"], string> = {
  "Initial Access": RISK_HEX.high,
  "Privilege Escalation": RISK_HEX.critical,
  "Lateral Movement": RISK_HEX.medium,
  Exfiltration: RISK_HEX.critical,
  Impact: RISK_HEX.critical,
};

export function BreachSimulation({
  path,
  onClose,
  onBreakPath,
}: {
  path: PathDetail;
  onClose: () => void;
  onBreakPath: () => void;
}) {
  const frames = useMemo(() => buildBreachFrames(path), [path]);
  const plan = useMemo(() => containmentPlan(path), [path]);
  const reduced = usePrefersReducedMotion();

  // cursor = how many frames have been revealed (0..frames.length)
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [contained, setContained] = useState(false);

  // when contained, the attacker is stopped AT the fixed hop — reveal up to it
  const stopAt = contained && plan ? plan.fixStepIndex : frames.length - 1;
  const maxCursor = stopAt + 1;
  const done = cursor >= maxCursor;

  const logRef = useRef<HTMLDivElement>(null);

  // start: reduced-motion users get the whole story at once
  useEffect(() => {
    if (reduced) {
      setCursor(maxCursor);
      setPlaying(false);
    } else {
      setCursor(0);
      setPlaying(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [contained, reduced]);

  // playback tick
  useEffect(() => {
    if (!playing || reduced) return;
    if (cursor >= maxCursor) {
      setPlaying(false);
      return;
    }
    const t = window.setTimeout(() => setCursor((c) => c + 1), cursor === 0 ? 350 : TICK_MS);
    return () => window.clearTimeout(t);
  }, [playing, cursor, maxCursor, reduced]);

  // keep the console scrolled to the newest line
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: reduced ? "auto" : "smooth" });
  }, [cursor, reduced]);

  const revealed = frames.slice(0, cursor);
  const active = cursor > 0 ? frames[Math.min(cursor - 1, frames.length - 1)] : null;
  const shownExposure = contained
    ? // fix strands the attacker before the target — only exposure up to the
      // blocked hop accrued; the exact org recompute happens on "mark resolved"
      (revealed.length > 1 ? frames[Math.max(0, stopAt - 1)].exposureUsd : 0)
    : revealed.length
    ? revealed[revealed.length - 1].exposureUsd
    : 0;

  const replay = () => {
    setCursor(0);
    setPlaying(!reduced);
  };

  return createPortal(
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/85 p-4 backdrop-blur-md">
      <div className="flex max-h-[90vh] w-full max-w-3xl flex-col overflow-hidden rounded border border-hairline bg-[#080B09] shadow-[0_0_50px_rgba(0,0,0,0.9)] scanline">
        {/* header */}
        <div className="flex items-start justify-between border-b border-hairline/70 bg-surface-1/90 px-5 py-4">
          <div>
            <div className="flex items-center gap-2 font-mono">
              <span className="inline-flex items-center gap-1 rounded border border-risk-critical/60 bg-risk-critical/15 px-2 py-0.5 text-[10px] uppercase tracking-wider text-risk-critical animate-pulse font-bold">
                <Crosshair className="h-3 w-3" /> BREACH SIMULATION ENGINE
              </span>
              <span className="rounded border border-hairline px-2 py-0.5 text-[10px] uppercase tracking-wider text-ink-muted">
                SAFE REPLAY // ZERO EXPLOIT
              </span>
            </div>
            <h2 className="mt-2 font-mono text-h3 font-bold text-ink-primary">
              {path.entry_label} <span className="text-accent-400">→</span> {path.target_hostname}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="rounded border border-hairline/60 p-1.5 text-ink-muted hover:border-accent-500/50 hover:text-accent-400"
            aria-label="Close simulation"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* kill-chain rail */}
        <div className="border-b border-hairline/60 bg-surface-2/40 px-5 py-3.5">
          <div className="flex items-center gap-1 overflow-x-auto pb-1">
            <ChainNode icon={<Globe className="h-4 w-4" />} label="INTERNET" state="root" />
            {frames.map((f, i) => {
              const reachedIdx = cursor - 1;
              const isFixed = contained && plan && i === plan.fixStepIndex;
              const reached = i <= reachedIdx && !(isFixed && contained);
              const isActive = i === reachedIdx && !done;
              const state: ChainState = isFixed
                ? "blocked"
                : reached
                ? "breached"
                : "pending";
              return (
                <div key={f.stepIndex} className="flex items-center gap-1">
                  <ChevronRight className="h-3.5 w-3.5 shrink-0 text-hairline" />
                  <ChainNode
                    icon={
                      i === frames.length - 1 ? (
                        <Skull className="h-4 w-4" />
                      ) : (
                        <span className="font-mono text-[11px]">{i + 1}</span>
                      )
                    }
                    label={f.hostname}
                    state={state}
                    active={isActive}
                  />
                </div>
              );
            })}
          </div>
        </div>

        {/* console + status */}
        <div className="grid flex-1 grid-cols-1 gap-0 overflow-hidden md:grid-cols-[1fr_210px]">
          <div
            ref={logRef}
            className="max-h-[38vh] overflow-y-auto px-5 py-4 font-mono text-[12px] leading-relaxed bg-[#050706]"
          >
            {revealed.length === 0 && (
              <div className="text-accent-400/60 font-mono animate-pulse">&gt; ARMING INTRUSION SIMULATOR…</div>
            )}
            {revealed.map((f, i) => {
              const isBlocked = contained && plan && f.stepIndex === plan.fixStepIndex;
              return (
                <div key={f.stepIndex} className="mb-3.5 border-b border-hairline/30 pb-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-accent-400 font-bold">
                      [T+{String(Math.round((i * TICK_MS) / 1000)).padStart(2, "0")}s]
                    </span>
                    <span
                      className="rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider"
                      style={{ color: TACTIC_HEX[f.tactic], backgroundColor: `${TACTIC_HEX[f.tactic]}15`, borderColor: `${TACTIC_HEX[f.tactic]}40` }}
                    >
                      {f.tactic}
                    </span>
                    <span className="text-[10px] text-ink-muted">
                      {f.techniqueId} · {f.techniqueName}
                    </span>
                  </div>
                  {isBlocked ? (
                    <div className="mt-1.5 flex items-start gap-1.5 text-risk-safe font-bold">
                      <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 animate-pulse" />
                      <span>
                        CONTAINED AT {f.hostname}. Security rule applied — attacker stranded before {path.target_hostname}.
                      </span>
                    </div>
                  ) : (
                    <div className="mt-1 text-ink-primary">{f.narration}</div>
                  )}
                  <div className="mt-1 flex items-start gap-1.5 text-[11px] text-accent-400">
                    <Shield className="mt-0.5 h-3 w-3 shrink-0" />
                    <span>DETECTION: {f.detection}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* side status */}
          <div className="border-t border-hairline/60 bg-surface-1/40 p-4 md:border-l md:border-t-0 font-mono flex flex-col justify-between">
            <div>
              <div className="text-[10px] font-bold uppercase tracking-wider text-ink-muted">
                {contained ? "EXPOSURE POST-FIX" : "EXPOSURE AT RISK"}
              </div>
              <div
                className="font-mono text-h2 font-bold tabular-nums mt-1"
                style={{ color: contained ? RISK_HEX.safe : RISK_HEX.critical }}
              >
                {moneyFull(shownExposure)}
              </div>
              {!contained && (
                <div className="mt-1 text-[10px] text-ink-muted">
                  of {moneyFull(path.impact_usd)} vector peak
                </div>
              )}
              {active && !done && (
                <div className="mt-3 rounded border border-hairline bg-surface-2/80 p-2 text-[10px]">
                  <div className="text-ink-muted uppercase">ACTIVE HOP</div>
                  <div className="font-bold text-accent-400">{active.hostname}</div>
                  {active.cve && (
                    <div className="mt-0.5 text-risk-high">{active.cve}</div>
                  )}
                </div>
              )}
            </div>
            {done && contained && (
              <div className="mt-3 flex items-center gap-1.5 rounded border border-risk-safe/50 bg-risk-safe/15 p-2 text-[11px] font-bold text-risk-safe">
                <ShieldCheck className="h-3.5 w-3.5" /> ATTACK CONTAINED
              </div>
            )}
            {done && !contained && (
              <div className="mt-3 flex items-center gap-1.5 rounded border border-risk-critical/50 bg-risk-critical/15 p-2 text-[11px] font-bold text-risk-critical animate-pulse">
                <Skull className="h-3.5 w-3.5" /> ASSET BREACHED
              </div>
            )}
          </div>
        </div>

        {/* controls */}
        <div className="flex flex-wrap items-center gap-2 border-t border-hairline/60 bg-surface-1/90 px-5 py-3 font-mono">
          {!reduced && (
            <Button variant="ghost" size="sm" onClick={() => setPlaying((p) => !p)} disabled={done} className="font-mono uppercase text-[11px]">
              {playing ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
              {playing ? "PAUSE" : "PLAY"}
            </Button>
          )}
          <Button variant="ghost" size="sm" onClick={replay} className="font-mono uppercase text-[11px]">
            <RotateCcw className="h-3.5 w-3.5" /> REPLAY
          </Button>
          <div className="flex-1" />
          {!contained ? (
            <Button
              size="sm"
              onClick={() => setContained(true)}
              disabled={!plan}
              title={plan ? `Sever the ${plan.fixHostname} hop` : "No severable hop"}
              className="font-mono uppercase text-[11px] font-bold tracking-wider"
            >
              <ShieldCheck className="h-3.5 w-3.5" /> CONTAIN VECTOR
            </Button>
          ) : (
            <Button size="sm" onClick={onBreakPath} className="font-mono uppercase text-[11px] font-bold tracking-wider">
              <ShieldCheck className="h-3.5 w-3.5" /> RESOLVE &amp; RECOMPUTE
            </Button>
          )}
        </div>
      </div>
    </div>,
    document.body,
  );
}

type ChainState = "root" | "pending" | "breached" | "blocked";

function ChainNode({
  icon,
  label,
  state,
  active,
}: {
  icon: React.ReactNode;
  label: string;
  state: ChainState;
  active?: boolean;
}) {
  const color =
    state === "root"
      ? "#6b7a94"
      : state === "breached"
      ? RISK_HEX.critical
      : state === "blocked"
      ? RISK_HEX.safe
      : "#3a4150";
  const filled = state === "breached" || state === "blocked";
  return (
    <div className="flex w-[68px] shrink-0 flex-col items-center gap-1">
      <div
        className={`flex h-9 w-9 items-center justify-center rounded-full border-2 transition-all duration-300 ${
          active ? "motion-safe:animate-pulse" : ""
        }`}
        style={{
          borderColor: color,
          color: filled ? "#0b0e13" : color,
          backgroundColor: filled ? color : "transparent",
          boxShadow: active ? `0 0 14px ${color}` : "none",
        }}
      >
        {state === "blocked" ? <ShieldCheck className="h-4 w-4" /> : icon}
      </div>
      <span className="w-full truncate text-center font-mono text-[9px] text-ink-muted" title={label}>
        {label}
      </span>
    </div>
  );
}
