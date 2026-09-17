// Drishti v0.1 — threat-instrument console primitives | 20-Jul-2026
/** One shared visual language for the authed app: framed panels with corner
 * registration ticks, monospace telemetry eyebrows with an index, Clash Display
 * hero numerals, and a reduced-motion-aware count-up. Every screen (dashboard /
 * live watch / report) is built from these so the app reads as one instrument.
 *
 * Colour comes only from the existing SOC-blue + risk tokens — no new palette. */
import clsx from "clsx";
import { animate, useReducedMotion } from "framer-motion";
import type { LucideIcon } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";

/** Four L-shaped corner ticks that light up on panel hover. */
export function RegTicks() {
  return (
    <>
      <span aria-hidden className="reg-tick reg-tl" />
      <span aria-hidden className="reg-tick reg-tr" />
      <span aria-hidden className="reg-tick reg-bl" />
      <span aria-hidden className="reg-tick reg-br" />
    </>
  );
}

/** Monospace, tracked, uppercase label with a pulsing telemetry dot. The unit
 * of "this is an instrument reading", not a heading. */
export function Eyebrow({
  children,
  tone = "accent",
  className,
}: {
  children: ReactNode;
  tone?: "accent" | "critical" | "safe" | "muted";
  className?: string;
}) {
  const dot =
    tone === "critical"
      ? "text-risk-critical"
      : tone === "safe"
        ? "text-risk-safe"
        : tone === "muted"
          ? "text-ink-muted"
          : "text-accent-400";
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-muted",
        className,
      )}
    >
      <span className={clsx("tele-dot inline-block h-1.5 w-1.5 rounded-full bg-current", dot)} />
      {children}
    </span>
  );
}

/**
 * A framed instrument panel. Replaces the ad-hoc Card+header pattern: an
 * optional registration index (e.g. "03"), a telemetry eyebrow, a Clash title,
 * right-aligned meta/actions, and the corner ticks. `tone` sets the accent used
 * by the top rule + hover.
 */
export function Panel({
  index,
  eyebrow,
  title,
  icon: Icon,
  meta,
  tone = "accent",
  glow = false,
  bodyClassName,
  className,
  children,
}: {
  index?: string;
  eyebrow?: ReactNode;
  title?: ReactNode;
  icon?: LucideIcon;
  meta?: ReactNode;
  tone?: "accent" | "critical" | "safe";
  glow?: boolean;
  bodyClassName?: string;
  className?: string;
  children: ReactNode;
}) {
  const rule =
    tone === "critical"
      ? "via-risk-critical/80"
      : tone === "safe"
        ? "via-risk-safe/80"
        : "via-accent-500/80";
  const hoverBorder =
    tone === "critical" ? "hover:border-risk-critical/50" : "hover:border-accent-500/50";
  return (
    <section
      className={clsx(
        "reg-frame group relative overflow-hidden rounded-md border border-hairline bg-surface-1/80 backdrop-blur-xl transition-all duration-200",
        hoverBorder,
        glow &&
          (tone === "critical"
            ? "shadow-[0_0_40px_-15px_rgba(239,68,68,0.45)]"
            : "shadow-[0_0_40px_-15px_rgba(0,255,102,0.30)]"),
        className,
      )}
    >
      {/* top registration rule */}
      <span
        aria-hidden
        className={clsx(
          "absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent to-transparent",
          rule,
        )}
      />
      <RegTicks />
      {(eyebrow || title || meta || index) && (
        <header className="flex items-start justify-between gap-3 px-5 pt-4">
          <div className="min-w-0">
            {eyebrow && <Eyebrow tone={tone === "critical" ? "critical" : tone === "safe" ? "safe" : "accent"}>{eyebrow}</Eyebrow>}
            {title && (
              <h2 className="mt-1 flex items-center gap-2 font-display text-h2 font-bold tracking-tight text-ink-primary">
                {Icon && <Icon className="h-4 w-4 text-accent-400" />}
                {title}
              </h2>
            )}
          </div>
          <div className="flex shrink-0 items-center gap-2.5">
            {meta}
            {index && (
              <span className="select-none font-mono text-[11px] font-semibold tabular-nums text-ink-muted transition-colors group-hover:text-accent-400">
                {index}
              </span>
            )}
          </div>
        </header>
      )}
      <div className={clsx(bodyClassName ?? "p-5")}>{children}</div>
    </section>
  );
}

/** Instrument stat readout — mono label, big Clash numeral, corner tick,
 * optional delta chip. The number is the hero; the label is the caption. */
export function StatReadout({
  label,
  children,
  delta,
  index,
  tone = "neutral",
  className,
}: {
  label: string;
  children: ReactNode;
  delta?: ReactNode;
  index?: string;
  tone?: "neutral" | "accent" | "critical";
  className?: string;
}) {
  const ring =
    tone === "critical"
      ? "border-risk-critical/25 hover:border-risk-critical/70"
      : tone === "accent"
        ? "border-accent-500/25 hover:border-accent-500/70"
        : "border-hairline hover:border-accent-500/50";
  const topRule =
    tone === "critical"
      ? "via-risk-critical"
      : tone === "accent"
        ? "via-accent-500"
        : "via-hairline group-hover:via-accent-500/70";
  return (
    <div
      className={clsx(
        "reg-frame group relative overflow-hidden rounded-md border bg-surface-1/40 px-4 py-4 backdrop-blur-xl transition-all duration-300 hover:-translate-y-0.5",
        ring,
        className,
      )}
    >
      <span
        aria-hidden
        className={clsx("absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent to-transparent", topRule)}
      />
      <span aria-hidden className="reg-tick reg-tr" />
      <div className="flex items-center justify-between">
        <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-muted">
          {label}
        </span>
        <div className="flex items-center gap-2">
          {delta}
          {index && (
            <span className="font-mono text-[10px] text-ink-muted/70 tabular-nums">
              [{index}]
            </span>
          )}
        </div>
      </div>
      <div className="mt-2.5 font-display text-[2rem] font-semibold leading-none tracking-tight text-ink-primary tabular-nums">
        {children}
      </div>
    </div>
  );
}

/** Reduced-motion-aware count-up. Animates from 0 to `value` once on mount (or
 * whenever `value` changes), formatting each frame with `format`. */
export function CountUp({
  value,
  format = (n) => String(Math.round(n)),
  durationMs = 1100,
  className,
}: {
  value: number;
  format?: (n: number) => string;
  durationMs?: number;
  className?: string;
}) {
  const reduce = useReducedMotion();
  const [display, setDisplay] = useState(() => (reduce ? format(value) : format(0)));
  const fromRef = useRef(0);

  useEffect(() => {
    if (reduce) {
      setDisplay(format(value));
      return;
    }
    const controls = animate(fromRef.current, value, {
      duration: durationMs / 1000,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (v) => setDisplay(format(v)),
    });
    fromRef.current = value;
    return () => controls.stop();
    // format is stable enough for our call sites; re-run only on value change
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value, reduce, durationMs]);

  return <span className={className}>{display}</span>;
}

/** Delta chip — e.g. "▲ 2" / "▼ $200k". tone drives colour. */
export function Delta({
  children,
  tone = "up",
}: {
  children: ReactNode;
  tone?: "up" | "down" | "flat";
}) {
  const cls =
    tone === "down"
      ? "bg-risk-safe/15 text-risk-safe"
      : tone === "up"
        ? "bg-risk-critical/15 text-risk-critical"
        : "bg-surface-2 text-ink-muted";
  return (
    <span className={clsx("rounded-sm px-1.5 py-0.5 font-mono text-[10px] font-semibold tabular-nums", cls)}>
      {children}
    </span>
  );
}
