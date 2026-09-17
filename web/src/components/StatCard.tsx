// Drishti v0.1 — dashboard stat card component | 11-Jul-2026
import clsx from "clsx";
import type { ReactNode } from "react";

export function StatCard({
  label,
  value,
  hint,
  accent = false,
  children,
}: {
  label: string;
  value?: ReactNode;
  hint?: string;
  accent?: boolean;
  children?: ReactNode;
}) {
  return (
    <div
      className={clsx(
        "group relative overflow-hidden rounded border bg-surface-1/80 p-5 backdrop-blur-xl transition-all duration-200 hover:-translate-y-0.5",
        accent
          ? "border-risk-critical/40 hover:border-risk-critical/80 hover:bg-risk-critical/10 hover:shadow-[0_0_30px_-8px_rgba(239,68,68,0.4)]"
          : "border-hairline hover:border-accent-500/50 hover:bg-accent-500/5 hover:shadow-[0_0_30px_-8px_rgba(0,255,102,0.25)]",
      )}
    >
      {/* top accent rule — full on the critical card, hairline elsewhere */}
      <span
        aria-hidden
        className={clsx(
          "absolute inset-x-0 top-0 h-px transition-colors duration-300",
          accent
            ? "bg-gradient-to-r from-transparent via-risk-critical to-transparent shadow-[0_1px_12px_rgba(239,68,68,0.8)]"
            : "bg-hairline group-hover:bg-gradient-to-r group-hover:from-transparent group-hover:via-accent-500/80 group-hover:to-transparent group-hover:shadow-[0_1px_10px_rgba(0,255,102,0.5)]",
        )}
      />
      {/* HUD corner bracket, top-right */}
      <span
        aria-hidden
        className={clsx(
          "absolute right-2 top-2 h-2.5 w-2.5 border-r border-t transition-colors",
          accent ? "border-risk-critical/60" : "border-hairline group-hover:border-accent-500/70",
        )}
      />
      <div className="relative z-10 font-mono text-[10px] uppercase tracking-[0.14em] text-ink-muted">{label}</div>
      <div className="mt-2 font-mono text-h1 font-bold leading-none text-ink-primary tabular-nums">
        {children ?? value}
      </div>
      {hint && <div className="mt-1.5 font-mono text-xs text-ink-muted">{hint}</div>}
    </div>
  );
}

/** Slim inline stat — for list-page header strips (Findings/Assets/Paths)
 * where a full StatCard would out-weigh a one-line table. */
export function MiniStat({
  label,
  value,
  toneClass,
}: {
  label: string;
  value: ReactNode;
  toneClass?: string;
}) {
  return (
    <div className="rounded border border-hairline bg-surface-1/90 px-3.5 py-2.5">
      <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-muted">{label}</div>
      <div className={clsx("mt-1 font-mono text-h3 font-bold leading-none tabular-nums", toneClass ?? "text-ink-primary")}>
        {value}
      </div>
    </div>
  );
}
