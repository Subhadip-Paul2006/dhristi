import { describe, expect, it } from "vitest";
import { buildBreachFrames, containmentPlan } from "./breachSim";
import type { PathDetail, PathStep } from "../../api/types";

function step(i: number, over: Partial<PathStep> = {}): PathStep {
  return {
    step_index: i,
    asset_id: `a${i}`,
    asset_hostname: `host-${i}`,
    asset_ip: `10.0.0.${i}`,
    asset_type: "server",
    zone: "dmz",
    via_cve: null,
    via_title: null,
    via_severity: null,
    via_cvss: null,
    edge_weight: 0.5,
    ...over,
  };
}

// mirrors the Acme headline path shape: INTERNET → web → api → app → jump → db
const path: PathDetail = {
  id: "p1",
  entry_label: "INTERNET",
  target_asset_id: "a4",
  target_hostname: "db-prod-01",
  hop_count: 5,
  path_risk: 71.3,
  likelihood: 0.142,
  impact_usd: 568000,
  narrative: null,
  drivers: [],
  steps: [
    step(0, { asset_hostname: "web-app-01", asset_type: "webapp", via_cve: "CVE-2024-0001", via_title: "RCE in upload handler", via_severity: "critical" }),
    step(1, { asset_hostname: "api-gw-01", via_cve: "CVE-2024-0002", via_title: "SSRF in proxy", via_severity: "high" }),
    step(2, { asset_hostname: "app-svc-01" }),
    step(3, { asset_hostname: "jump-01", via_cve: "CVE-2024-0004", via_title: "Privilege escalation via sudo", via_severity: "high" }),
    step(4, { asset_hostname: "db-prod-01", asset_type: "database", via_cve: "CVE-2024-0005", via_title: "Auth bypass", via_severity: "critical" }),
  ],
};

describe("buildBreachFrames", () => {
  const frames = buildBreachFrames(path);

  it("emits one frame per step", () => {
    expect(frames).toHaveLength(5);
  });

  it("opens with Initial Access and ends at the crown jewel", () => {
    expect(frames[0].tactic).toBe("Initial Access");
    expect(frames[0].kind).toBe("entry");
    expect(frames[4].kind).toBe("impact");
    expect(frames[4].tactic).toBe("Exfiltration"); // database → data theft
  });

  it("labels a priv-esc hop correctly", () => {
    expect(frames[3].tactic).toBe("Privilege Escalation");
    expect(frames[3].techniqueId).toBe("T1068");
  });

  it("ramps exposure monotonically to the exact engine figure", () => {
    for (let i = 1; i < frames.length; i++) {
      expect(frames[i].exposureUsd).toBeGreaterThanOrEqual(frames[i - 1].exposureUsd);
    }
    expect(frames[4].exposureUsd).toBe(568000);
  });

  it("advances playback time each hop", () => {
    for (let i = 1; i < frames.length; i++) {
      expect(frames[i].tOffsetMs).toBeGreaterThan(frames[i - 1].tOffsetMs);
    }
  });

  it("is empty for a path with no steps", () => {
    expect(buildBreachFrames({ ...path, steps: [] })).toEqual([]);
  });
});

describe("containmentPlan", () => {
  it("severs the last hop that carries an open finding", () => {
    const plan = containmentPlan(path);
    expect(plan?.fixStepIndex).toBe(4);
    expect(plan?.fixCve).toBe("CVE-2024-0005");
  });

  it("falls back to an earlier finding when the target hop has none", () => {
    const p2 = { ...path, steps: path.steps.map((s, i) => (i === 4 ? { ...s, via_cve: null } : s)) };
    expect(containmentPlan(p2)?.fixStepIndex).toBe(3);
  });

  it("returns null when there is nothing to sever", () => {
    expect(containmentPlan({ ...path, steps: [path.steps[0]] })).toBeNull();
  });
});
