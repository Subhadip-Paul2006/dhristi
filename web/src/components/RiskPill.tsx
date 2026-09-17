// Drishti v0.1 — color-coded risk pill badge | 11-Jul-2026
import clsx from "clsx";
import { RISK_TEXT, riskBucket, riskScore, type RiskToken } from "../lib/format";

const LABELS: Record<RiskToken, string> = {
  safe: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};
const RING: Record<RiskToken, string> = {
  safe: "border-risk-safe/30 bg-risk-safe/10",
  medium: "border-risk-medium/30 bg-risk-medium/10",
  high: "border-risk-high/30 bg-risk-high/10",
  critical: "border-risk-critical/40 bg-risk-critical/15 shadow-[0_0_8px_rgba(239,68,68,0.2)]",
};

/** Maps a score/severity to the risk ramp. Always pairs color with a label
 * (a11y: never color-only, UIUX.md §10). */
export function RiskPill({
  score,
  showNumber = true,
  className,
}: {
  score: number | null | undefined;
  showNumber?: boolean;
  className?: string;
}) {
  const bucket = riskBucket(score);
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider",
        RING[bucket],
        RISK_TEXT[bucket],
        className,
      )}
    >
      <span aria-hidden className={clsx("h-1.5 w-1.5 rounded-full", `bg-current`)} />
      {LABELS[bucket]}
      {showNumber && score != null && (
        <span className="font-mono text-ink-primary font-bold">{riskScore(score)}</span>
      )}
    </span>
  );
}
