// Drishti v0.1 — formatted currency display | 11-Jul-2026
import clsx from "clsx";
import { money, moneyFull } from "../lib/format";

/** Compact $ with full value on hover (UIUX.md §6). Mono font. */
export function MoneyValue({
  value,
  className,
  tint = false,
  size = "md",
}: {
  value: number | null | undefined;
  className?: string;
  tint?: boolean;
  size?: "sm" | "md" | "lg" | "xl";
}) {
  const sizes = {
    sm: "text-small",
    md: "text-mono-data",
    lg: "text-h3",
    xl: "font-display text-display",
  };
  return (
    <span
      title={moneyFull(value)}
      className={clsx(
        "font-mono tabular-nums",
        sizes[size],
        tint && value != null && value > 1_000_000 ? "text-risk-critical" : "text-ink-primary",
        className,
      )}
    >
      {money(value)}
    </span>
  );
}
