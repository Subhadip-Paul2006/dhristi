// Drishti — breach simulation: derive a safe, replayable attack story from a
// real computed attack path. Pure + deterministic (no exploits, no network) —
// it VISUALISES the path the engine already produced, mapped to MITRE ATT&CK
// tactics, so a viewer sees "how the attack happens" and "how the fix breaks it".
import type { PathDetail, PathStep } from "../../api/types";

export type Tactic =
  | "Initial Access"
  | "Privilege Escalation"
  | "Lateral Movement"
  | "Exfiltration"
  | "Impact";

export interface BreachFrame {
  stepIndex: number;
  kind: "entry" | "pivot" | "impact";
  tactic: Tactic;
  techniqueId: string;
  techniqueName: string;
  hostname: string;
  ip: string;
  assetType: string;
  cve: string | null;
  severity: string | null;
  cvss: number | null;
  narration: string; // attacker's move (what happens)
  detection: string; // Drishti's defensive read (why we already flagged it)
  tOffsetMs: number; // cumulative time offset for playback
  exposureUsd: number; // exposure "accrued" up to this hop (ramps to impact_usd)
}

export interface ContainmentPlan {
  // the last reachable hop backed by an open finding — severing it strands the
  // attacker before the crown jewel; this is the highest-leverage single fix
  fixStepIndex: number;
  fixHostname: string;
  fixCve: string | null;
  fixSeverity: string | null;
}

const HOP_MS = 2600;

function hostOf(s: PathStep): string {
  return s.asset_hostname || s.asset_ip || s.asset_id;
}

function dataCrownJewel(assetType: string): boolean {
  return /database|cloud|webapp|storage|data/i.test(assetType);
}

function technique(tactic: Tactic, title: string | null): [string, string] {
  const t = (title ?? "").toLowerCase();
  switch (tactic) {
    case "Initial Access":
      if (/ssrf|server-side request/.test(t)) return ["T1190", "Exploit Public-Facing App (SSRF)"];
      if (/rce|remote code|command inj|deserial|injection|sql/.test(t))
        return ["T1190", "Exploit Public-Facing Application"];
      return ["T1133", "External Remote Services"];
    case "Privilege Escalation":
      return ["T1068", "Exploitation for Privilege Escalation"];
    case "Lateral Movement":
      if (/cred|password|auth|token|secret|key/.test(t)) return ["T1078", "Valid Accounts"];
      return ["T1210", "Exploitation of Remote Services"];
    case "Exfiltration":
      return ["T1567", "Exfiltration Over Web Service"];
    case "Impact":
      return ["T1486", "Data Encrypted for Impact"];
  }
}

function tacticForStep(step: PathStep, i: number, n: number): Tactic {
  if (i === 0) return "Initial Access";
  if (i === n - 1) return dataCrownJewel(step.asset_type) ? "Exfiltration" : "Impact";
  if (/priv|escal|admin|root|sudo/i.test(step.via_title ?? "")) return "Privilege Escalation";
  return "Lateral Movement";
}

function narrate(tactic: Tactic, host: string, cve: string | null): string {
  const via = cve ? ` exploiting ${cve}` : "";
  switch (tactic) {
    case "Initial Access":
      return `Attacker breaches ${host}${via} — the internet-facing entry point.`;
    case "Privilege Escalation":
      return `Attacker escalates to admin on ${host}${via}.`;
    case "Lateral Movement":
      return `Attacker pivots to ${host}${via}, moving deeper toward the target.`;
    case "Exfiltration":
      return `Attacker reaches ${host} and exfiltrates the crown-jewel data.`;
    case "Impact":
      return `Attacker lands on ${host} — the crown jewel — full compromise.`;
  }
}

function detect(kind: BreachFrame["kind"], host: string, impactUsd: number): string {
  switch (kind) {
    case "entry":
      return `Drishti already flagged ${host} as internet-reachable with an exploitable finding — this is why it topped the fix list.`;
    case "pivot":
      return `Drishti mapped this hop inside ${host}'s blast radius; the trust edge is a known reachable route.`;
    case "impact":
      return `Drishti priced this breach at $${Math.round(impactUsd).toLocaleString("en-US")} and drafted the fix that severs the chain.`;
  }
}

/** Build the ordered replay frames from a real path. Deterministic: same path in,
 *  same frames out — the demo can never flake. */
export function buildBreachFrames(path: PathDetail): BreachFrame[] {
  const steps = path.steps ?? [];
  const n = steps.length;
  if (n === 0) return [];
  const impact = path.impact_usd ?? 0;
  return steps.map((s, i) => {
    const tactic = tacticForStep(s, i, n);
    const [techniqueId, techniqueName] = technique(tactic, s.via_title);
    const kind: BreachFrame["kind"] = i === 0 ? "entry" : i === n - 1 ? "impact" : "pivot";
    const host = hostOf(s);
    return {
      stepIndex: s.step_index,
      kind,
      tactic,
      techniqueId,
      techniqueName,
      hostname: host,
      ip: s.asset_ip,
      assetType: s.asset_type,
      cve: s.via_cve,
      severity: s.via_severity,
      cvss: s.via_cvss,
      narration: narrate(tactic, host, s.via_cve),
      detection: detect(kind, host, impact),
      tOffsetMs: i * HOP_MS,
      // ramp exposure to the exact engine figure on the final hop
      exposureUsd: i === n - 1 ? impact : Math.round((impact * (i + 1)) / n),
    };
  });
}

/** Which single hop to sever. Prefer the last hop carrying an open finding (that
 *  strands the attacker nearest the target); fall back to the final hop. */
export function containmentPlan(path: PathDetail): ContainmentPlan | null {
  const steps = path.steps ?? [];
  if (steps.length < 2) return null;
  for (let i = steps.length - 1; i >= 1; i--) {
    if (steps[i].via_cve) {
      return {
        fixStepIndex: i,
        fixHostname: hostOf(steps[i]),
        fixCve: steps[i].via_cve,
        fixSeverity: steps[i].via_severity,
      };
    }
  }
  const last = steps[steps.length - 1];
  return {
    fixStepIndex: steps.length - 1,
    fixHostname: hostOf(last),
    fixCve: last.via_cve,
    fixSeverity: last.via_severity,
  };
}
