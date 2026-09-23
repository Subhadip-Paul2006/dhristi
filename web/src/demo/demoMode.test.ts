import { describe, expect, it } from "vitest";
import {
  DEMO_ASSETS,
  DEMO_FINDINGS,
  DEMO_GRAPH,
  DEMO_ORG,
  DEMO_PATHS,
  DEMO_USER,
  getDemoEndpointTelemetry,
  getDemoEndpointVulnerabilities,
  getDemoRemediation,
} from "./demoData";

describe("Frontend Demo Mode Data Integrity", () => {
  it("uses canonical demo user and organization", () => {
    expect(DEMO_USER.email).toBe("analyst@acme-retail.dev");
    expect(DEMO_USER.role).toBe("analyst");
    expect(DEMO_ORG.slug).toBe("acme-retail");
  });

  it("strictly avoids fabricated CVE IDs for demo findings", () => {
    DEMO_FINDINGS.forEach((finding) => {
      // Must not invent CVE IDs
      expect(finding.cve_id).toBeNull();
      expect(finding.title).toContain("[SYNTHETIC DEMO FINDING]");
      expect(finding.description).toContain("SIMULATED FINDING");
    });
  });

  it("maintains internal identity consistency across assets and findings", () => {
    const assetIds = new Set(DEMO_ASSETS.map((a) => a.id));
    DEMO_FINDINGS.forEach((finding) => {
      // Every finding must point to a real asset in DEMO_ASSETS
      expect(assetIds.has(finding.asset_id)).toBe(true);
    });
  });

  it("maintains graph node and attack path coherence", () => {
    expect(DEMO_PATHS.length).toBeGreaterThan(0);
    const heroPath = DEMO_PATHS[0];
    expect(heroPath.path_risk).toBe(0.94);
    expect(heroPath.impact_usd).toBe(3500000);

    // Verify graph has crown jewel and internet gateway nodes
    const nodeIds = DEMO_GRAPH.nodes.map((n) => n.id);
    expect(nodeIds).toContain("asset-fw-edge-01");
    expect(nodeIds).toContain("asset-db-prod-01");

    // All graph edges must carry path metadata
    DEMO_GRAPH.edges.forEach((edge) => {
      expect(edge.data?.path_id !== undefined).toBe(true);
    });
  });

  it("provides deterministic safe remediation without executing commands", () => {
    const rem = getDemoRemediation("finding-demo-001", "ansible");
    expect(rem.summary).toContain("DEMO REMEDIATION // NOT EXECUTED");
    expect(rem.disclaimer).toContain("No commands have been executed");
  });

  it("provides deterministic endpoint telemetry and vulnerability scans", () => {
    const telemetry = getDemoEndpointTelemetry("dev-win-01");
    expect(telemetry.device_id).toBe("dev-win-01");
    expect(telemetry.hostname).toBe("WIN-ADMIN-01");
    expect(telemetry.os_name).toBe("Windows");
    expect(telemetry.os_version).toContain("Enterprise");

    const vulns = getDemoEndpointVulnerabilities("dev-win-01");
    expect(vulns.device_id).toBe("dev-win-01");
    expect(vulns.findings.length).toBeGreaterThan(0);
    expect(vulns.findings[0].title).toContain("SYNTHETIC DEMO FINDING");
  });
});
