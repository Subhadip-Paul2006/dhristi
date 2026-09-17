// Drishti v0.1 — blast radius color legend | 11-Jul-2026
import { RISK_HEX } from "../../lib/format";

const ITEMS = [
  { hex: RISK_HEX.safe, label: "NOMINAL // LOW" },
  { hex: RISK_HEX.medium, label: "ELEVATED // MEDIUM" },
  { hex: RISK_HEX.high, label: "SEVERE // HIGH" },
  { hex: RISK_HEX.critical, label: "BLAST RADIUS // CRITICAL" },
];

export function BlastLegend() {
  return (
    <div className="reg-frame relative rounded border border-hairline/70 bg-surface-1/90 p-3 shadow-[0_0_15px_rgba(0,0,0,0.5)] backdrop-blur">
      <span aria-hidden className="reg-tick reg-tr" />
      <div className="mb-2 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-muted">
        RISK_INDEX // SPECTRUM
      </div>
      <div className="space-y-1.5 font-mono">
        {ITEMS.map((i) => (
          <div key={i.label} className="flex items-center gap-2 text-[10px] text-ink-secondary">
            <span
              className="h-2 w-2 rounded-full shrink-0"
              style={{ background: i.hex, boxShadow: `0 0 6px ${i.hex}99` }}
            />
            <span className="tracking-wider">{i.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
