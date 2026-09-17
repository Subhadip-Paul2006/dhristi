// Drishti v0.1 — shared layout and card primitives | 11-Jul-2026
import clsx from "clsx";
import { AlertTriangle, ChevronDown, Inbox, Loader2, RotateCw } from "lucide-react";
import type { ReactNode, SelectHTMLAttributes } from "react";

export function Card({
  children,
  className,
  enter = false,
}: {
  children: ReactNode;
  className?: string;
  /** opt-in fade/slide-up on mount (CSS, reduced-motion aware) */
  enter?: boolean;
}) {
  return (
    <div
      className={clsx(
        "relative rounded border border-hairline bg-surface-1/90 backdrop-blur-xl shadow-md transition-all duration-200 hover:border-hairline hover:shadow-[0_0_15px_rgba(0,0,0,0.5)]",
        enter && "animate-card-enter",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** Styled `<select>` — native semantics (a11y, mobile keyboards) with a
 * custom chevron for the dark terminal theme. */
export function Select({
  uiSize = "md",
  className,
  ...select
}: { uiSize?: "sm" | "md" } & SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <div className="relative inline-flex">
      <select
        {...select}
        className={clsx(
          "appearance-none rounded border border-hairline bg-surface-2 outline-none transition-colors hover:border-accent-500/40 focus-visible:border-accent-500 focus-visible:ring-1 focus-visible:ring-accent-500/40 text-ink-primary",
          uiSize === "sm"
            ? "py-1 pl-2.5 pr-7 font-mono text-[11px]"
            : "py-1.5 pl-3 pr-8 text-small font-mono",
          className,
        )}
      />
      <ChevronDown
        aria-hidden
        className={clsx(
          "pointer-events-none absolute top-1/2 -translate-y-1/2 text-ink-muted",
          uiSize === "sm" ? "right-2 h-3 w-3" : "right-2.5 h-3.5 w-3.5",
        )}
      />
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={clsx("animate-shimmer rounded bg-surface-2/60 border border-hairline/50", className)}
      aria-hidden
    />
  );
}

export function LoadingBlock({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-6 font-mono text-xs text-accent-400">
      <Loader2 className="h-4 w-4 animate-spin text-accent-500" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({
  title,
  hint,
  action,
}: {
  title: string;
  hint?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-2.5 rounded border border-dashed border-hairline bg-surface-1/60 p-8 text-center">
      <Inbox className="h-7 w-7 text-ink-muted" />
      <div className="font-display text-h3 text-ink-primary">{title}</div>
      {hint && <p className="max-w-sm font-mono text-xs text-ink-muted">{hint}</p>}
      {action}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded border border-risk-critical/40 bg-surface-1/80 p-8 text-center shadow-[0_0_20px_rgba(239,68,68,0.1)]">
      <AlertTriangle className="h-6 w-6 text-risk-critical" />
      <p className="max-w-sm font-mono text-xs text-ink-secondary">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="inline-flex items-center gap-1.5 rounded border border-hairline bg-surface-2 px-3 py-1.5 font-mono text-xs text-ink-secondary hover:border-accent-500/40 hover:text-accent-400 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent-500/70"
        >
          <RotateCw className="h-3.5 w-3.5" /> Retry
        </button>
      )}
    </div>
  );
}
