// Drishti v0.1 — reusable button component | 11-Jul-2026
import clsx from "clsx";
import { Loader2 } from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "ghost" | "danger";
type Size = "sm" | "md";

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  children: ReactNode;
}

const VARIANTS: Record<Variant, string> = {
  primary:
    "bg-accent-500 text-canvas font-semibold border border-accent-400 shadow-[0_0_15px_rgba(56,198,244,0.25)] hover:bg-accent-400 hover:shadow-[0_0_22px_rgba(56,198,244,0.4)] active:bg-accent-600 disabled:opacity-50",
  ghost:
    "bg-surface-2/80 text-ink-primary hover:bg-surface-3 hover:text-accent-400 border border-hairline shadow-md backdrop-blur-md hover:border-accent-500/40 hover:shadow-[0_0_12px_rgba(56,198,244,0.15)]",
  danger:
    "bg-risk-critical/10 text-risk-critical border border-risk-critical/40 hover:bg-risk-critical/20 hover:border-risk-critical/70 disabled:opacity-50",
};
const SIZES: Record<Size, string> = {
  sm: "text-[12px] px-3 py-1.5 rounded-md gap-1.5 tracking-wide",
  md: "text-[14px] px-5 py-2.5 rounded-lg gap-2 tracking-wide",
};

export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  disabled,
  children,
  className,
  ...rest
}: Props) {
  return (
    <button
      className={clsx(
        "inline-flex items-center justify-center font-medium transition-colors duration-150",
        // press micro-interaction — transform only when the user allows motion
        "motion-safe:transition-[color,background-color,border-color,transform] motion-safe:active:scale-[0.97]",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-500/70",
        "disabled:cursor-not-allowed",
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      disabled={disabled || loading}
      {...rest}
    >
      {loading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}
