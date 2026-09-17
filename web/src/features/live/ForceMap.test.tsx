// Drishti v0.1 — force-map graph builder tests | 18-Jul-2026
/** The map must be N-agnostic: the SAME builder produces N gateway clusters for
 * N ∈ {1,3,8} with no count-specific branch. Off-link (no-MAC) devices, ghost
 * SSIDs, and large-subnet collapse all fall out of the data, not hardcoded N. */
import { describe, expect, it } from "vitest";
import { buildGraph } from "./ForceMap";
import type { NetworkCoverage, NetworkDevice } from "../../api/types";

function dev(part: Partial<NetworkDevice>): NetworkDevice {
  return {
    id: part.id ?? Math.random().toString(36).slice(2),
    ip: part.ip ?? "10.0.0.2",
    mac: part.mac ?? "aa:bb:cc:dd:ee:ff",
    subnet: part.subnet ?? "10.0.0.0/24",
    subnet_inferred: part.subnet_inferred ?? false,
    discovery: part.discovery ?? "arp",
    label: part.label ?? null,
    hostname: null,
    vendor: null,
    is_self: part.is_self ?? false,
    is_gateway: part.is_gateway ?? false,
    online: part.online ?? true,
    first_seen: "2026-07-18T00:00:00Z",
    last_seen: "2026-07-18T00:00:00Z",
    scanned: false,
    vuln_count: null,
    worst_severity: null,
    last_scanned_at: null,
  };
}

function makeSubnets(n: number): NetworkDevice[] {
  const out: NetworkDevice[] = [];
  for (let i = 0; i < n; i++) {
    const subnet = `10.${i}.0.0/24`;
    out.push(dev({ id: `gw${i}`, ip: `10.${i}.0.1`, subnet, is_gateway: true }));
    out.push(dev({ id: `c${i}a`, ip: `10.${i}.0.10`, subnet }));
    out.push(dev({ id: `c${i}b`, ip: `10.${i}.0.11`, subnet }));
  }
  return out;
}

describe("buildGraph — N-agnostic clustering", () => {
  it.each([1, 3, 8])("produces N=%i gateway clusters, one INTERNET root", (n) => {
    const g = buildGraph(makeSubnets(n));
    expect(g.gatewayCount).toBe(n);
    expect(g.nodes.filter((x) => x.kind === "gateway")).toHaveLength(n);
    expect(g.nodes.filter((x) => x.kind === "internet")).toHaveLength(1);
    // every gateway links to INTERNET
    const gwIds = g.nodes.filter((x) => x.kind === "gateway").map((x) => x.id);
    for (const id of gwIds) {
      expect(g.links).toContainEqual({ source: "INTERNET", target: id });
    }
    // clients present: 2 per subnet
    expect(g.nodes.filter((x) => x.kind === "client")).toHaveLength(2 * n);
  });

  it("N=1 still centers a single cluster without breaking", () => {
    const g = buildGraph(makeSubnets(1));
    expect(g.gatewayCount).toBe(1);
    expect(g.nodes.some((x) => x.kind === "internet")).toBe(true);
  });

  it("renders every device the API returns (liveness is gated server-side)", () => {
    // The server decides what's live (prunes/omits stale rows); the map renders
    // whatever it's handed, so an offline row still appears as a node here.
    const g = buildGraph([
      dev({ id: "gw", ip: "10.0.0.1", is_gateway: true }),
      dev({ id: "off", ip: "10.0.0.9", online: false }),
    ]);
    expect(g.nodes.some((x) => x.id === "off")).toBe(true);
  });

  it("keeps off-link (mac=null, l3) devices as distinct client nodes", () => {
    const g = buildGraph([
      dev({ id: "a", ip: "10.0.5.50", subnet: "10.0.5.0/24", mac: null, discovery: "l3" }),
      dev({ id: "b", ip: "10.0.5.51", subnet: "10.0.5.0/24", mac: null, discovery: "l3" }),
    ]);
    expect(g.nodes.filter((x) => x.kind === "client")).toHaveLength(2);
  });

  it("renders seen-but-not-joined SSIDs as ghost nodes linked to INTERNET", () => {
    const coverage: NetworkCoverage[] = [
      {
        id: "cov1", ssid: "Floor-3-Guest", subnet: null, gateway_ip: null,
        label: null, status: "seen_not_joined", evidence: "beacon",
        device_count: 0, last_seen: "2026-07-18T00:00:00Z",
      },
    ];
    const g = buildGraph(makeSubnets(1), coverage);
    const ghosts = g.nodes.filter((x) => x.kind === "ghost");
    expect(ghosts).toHaveLength(1);
    expect(ghosts[0].label).toBe("Floor-3-Guest");
    expect(g.links).toContainEqual({ source: "INTERNET", target: ghosts[0].id });
  });

  it("collapses a subnet over the threshold into one expandable cluster node", () => {
    const many: NetworkDevice[] = [
      dev({ id: "gw", ip: "192.168.1.1", subnet: "192.168.1.0/24", is_gateway: true }),
    ];
    for (let i = 0; i < 60; i++) {
      many.push(dev({ id: `c${i}`, ip: `192.168.1.${i + 2}`, subnet: "192.168.1.0/24" }));
    }
    const g = buildGraph(many);
    expect(g.nodes.filter((x) => x.kind === "cluster")).toHaveLength(1);
    expect(g.nodes.filter((x) => x.kind === "client")).toHaveLength(0);
    // expanding the subnet reveals the individual devices
    const expanded = buildGraph(many, [], new Set(["192.168.1.0/24"]));
    expect(expanded.nodes.filter((x) => x.kind === "client")).toHaveLength(60);
  });
});
