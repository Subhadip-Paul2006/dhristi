// Drishti v0.1 — Obsidian-style force-directed network map | 18-Jul-2026
/** One unified force-directed graph across every discovered subnet. Physics —
 * not rings — separate the clusters, so the layout is N-agnostic: one synthetic
 * INTERNET root, one hub per gateway, its subnet's devices linked to it, and
 * ghost nodes for SSIDs seen but never inventoried (the holes in the map are
 * the point). Force parameters are functions of the live graph, never constants
 * tuned for one count. Rendering reuses React Flow; d3-force drives layout. */
import {
 forceCenter,
 forceCollide,
 forceLink,
 forceManyBody,
 forceSimulation,
 forceX,
 forceY,
 type Simulation,
} from "d3-force";
import { Crosshair, Network } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, {
 Background,
 BackgroundVariant,
 Controls,
 Handle,
 Position,
 ReactFlowProvider,
 useReactFlow,
 type Edge,
 type Node,
 type NodeProps,
} from "reactflow";
import "reactflow/dist/style.css";
import type { NetworkCoverage, NetworkDevice } from "../../api/types";
import { RISK_HEX, riskBucket } from "../../lib/format";

// ── graph model (pure, unit-testable) ────────────────────────────────────────
export type GraphNodeKind = "internet" | "gateway" | "client" | "cluster" | "ghost";

export interface GraphNode {
 id: string;
 kind: GraphNodeKind;
 label: string;
 subnet: string | null;
 device?: NetworkDevice; // client / gateway when backed by a real device
 degree: number; // filled in by buildGraph — drives node radius
 count?: number; // cluster nodes: how many devices collapsed
 gatewayIp?: string | null;
}

export interface GraphLink {
 source: string;
 target: string;
}

export interface GraphModel {
 nodes: GraphNode[];
 links: GraphLink[];
 gatewayCount: number;
}

const INTERNET_ID = "INTERNET";
// a subnet with more clients than this collapses into one expandable node,
// so the sim stays fast and the canvas readable at ~150 nodes
const CLUSTER_THRESHOLD = 50;

/** Build the N-agnostic graph from live devices + coverage. Nothing here knows
 * how many subnets exist — clusters fall out of grouping by observed subnet. */
export function buildGraph(
 devices: NetworkDevice[],
 coverage: NetworkCoverage[] = [],
 expanded: Set<string> = new Set(),
): GraphModel {
 const live = devices;
 const nodes: GraphNode[] = [];
 const links: GraphLink[] = [];
 const degree: Record<string, number> = {};
 const bump = (a: string, b: string) => {
 links.push({ source: a, target: b });
 degree[a] = (degree[a] ?? 0) + 1;
 degree[b] = (degree[b] ?? 0) + 1;
 };

 nodes.push({ id: INTERNET_ID, kind: "internet", label: "INTERNET", subnet: null, degree: 0 });

 // group by observed subnet; a device with no subnet falls back to "unknown"
 const bySubnet = new Map<string, NetworkDevice[]>();
 for (const d of live) {
 const key = d.subnet ?? "unknown";
 (bySubnet.get(key) ?? bySubnet.set(key, []).get(key)!).push(d);
 }

 let gatewayCount = 0;
 for (const [subnet, subnetDevices] of bySubnet) {
 const gatewayDevice = subnetDevices.find((d) => d.is_gateway);
 const clients = subnetDevices.filter((d) => !d.is_gateway);
 const hubId = gatewayDevice ? gatewayDevice.id : `gw:${subnet}`;
 gatewayCount++;

 nodes.push({
 id: hubId,
 kind: "gateway",
 label: gatewayDevice ? gatewayDevice.ip : subnet,
 subnet,
 device: gatewayDevice,
 degree: 0,
 gatewayIp: gatewayDevice?.ip ?? null,
 });
 bump(INTERNET_ID, hubId);

 // collapse large subnets unless the operator expanded this one
 if (clients.length > CLUSTER_THRESHOLD && !expanded.has(subnet)) {
 const clusterId = `cluster:${subnet}`;
 nodes.push({
 id: clusterId,
 kind: "cluster",
 label: `${clients.length} devices`,
 subnet,
 degree: 0,
 count: clients.length,
 });
 bump(hubId, clusterId);
 continue;
 }
 for (const d of clients) {
 nodes.push({ id: d.id, kind: "client", label: d.ip, subnet, device: d, degree: 0 });
 bump(hubId, d.id);
 }
 }

 // ghost nodes: SSIDs we can SEE but have no inventory for — outlined holes
 for (const c of coverage) {
 if (c.status !== "seen_not_joined") continue;
 const id = `ghost:${c.id}`;
 nodes.push({
 id,
 kind: "ghost",
 label: c.ssid ?? c.subnet ?? "unknown network",
 subnet: c.subnet,
 degree: 0,
 });
 bump(INTERNET_ID, id);
 }

 for (const n of nodes) n.degree = degree[n.id] ?? 0;
 return { nodes, links, gatewayCount };
}

// ── colour: reuse the live-watch risk palette, never a new one ────────────────
function nodeAccent(n: GraphNode, scanRisk: Record<string, number>): string {
 if (n.kind === "internet") return RISK_HEX.medium;
 if (n.kind === "ghost") return "#6b7a94";
 const d = n.device;
 if (d && scanRisk[d.id] != null) return RISK_HEX[riskBucket(scanRisk[d.id])];
 if (d && d.scanned && (d.vuln_count ?? 0) > 0) return RISK_HEX[riskBucket(d.worst_severity === "critical" ? 90 : d.worst_severity === "high" ? 70 : 45)];
 if (n.kind === "gateway") return RISK_HEX.medium;
 if (d?.is_self) return RISK_HEX.safe;
 return "#6b7a94";
}

function nodeRadius(n: GraphNode): number {
 if (n.kind === "internet") return 34;
 if (n.kind === "gateway") return 24;
 if (n.kind === "cluster") return 20;
 // client / ghost radius grows with degree for visibility
 return 14 + Math.min(8, n.degree);
}

// ── the map ───────────────────────────────────────────────────────────────────
const forceNodeTypes = { fnode: ForceNode };

export function ForceMap({
 devices,
 coverage,
 onPick,
 scanRisk,
}: {
 devices: NetworkDevice[];
 coverage: NetworkCoverage[];
 onPick: (d: NetworkDevice) => void;
 scanRisk: Record<string, number>;
}) {
 const [expanded, setExpanded] = useState<Set<string>>(new Set());
 const model = useMemo(
 () => buildGraph(devices, coverage, expanded),
 [devices, coverage, expanded],
 );
 return (
 <ReactFlowProvider>
 <ForceCanvas
 model={model}
 onPick={onPick}
 scanRisk={scanRisk}
 onExpand={(subnet) => setExpanded((s) => new Set(s).add(subnet))}
 />
 </ReactFlowProvider>
 );
}

interface SimNode extends GraphNode {
 x: number;
 y: number;
 vx?: number;
 vy?: number;
 fx?: number | null;
 fy?: number | null;
}

function ForceCanvas({
 model,
 onPick,
 scanRisk,
 onExpand,
}: {
 model: GraphModel;
 onPick: (d: NetworkDevice) => void;
 scanRisk: Record<string, number>;
 onExpand: (subnet: string) => void;
}) {
 const [rfNodes, setRfNodes] = useState<Node[]>([]);
 const [hovered, setHovered] = useState<string | null>(null);
 const simRef = useRef<Simulation<SimNode, undefined> | null>(null);
 const simNodesRef = useRef<Map<string, SimNode>>(new Map());
 const rf = useReactFlow();
 const fittedRef = useRef(0);

 // adjacency for the Obsidian hover-highlight (a node + its direct neighbours)
 const neighbours = useMemo(() => {
 const m = new Map<string, Set<string>>();
 for (const n of model.nodes) m.set(n.id, new Set([n.id]));
 for (const l of model.links) {
 m.get(l.source)?.add(l.target);
 m.get(l.target)?.add(l.source);
 }
 return m;
 }, [model]);

 // Structure signature: node ids + link pairs. The 5s poll returns fresh array
 // refs every time; only an ACTUAL topology change may rebuild the simulation,
 // otherwise the map reheats and wanders on every poll.
 const structureKey = useMemo(
 () =>
 model.nodes.map((n) => n.id).sort().join("|") +
 "§" +
 model.links.map((l) => `${l.source}>${l.target}`).sort().join("|"),
 [model],
 );
 const modelRef = useRef(model);
 modelRef.current = model;

 // (re)build the simulation only when the graph SHAPE changes. Force params are
 // functions of node/gateway count — no constant is tuned for one N.
 useEffect(() => {
 const m = modelRef.current;
 const n = m.nodes.length;
 const gw = Math.max(1, m.gatewayCount);
 // carry positions across rebuilds so a topology change doesn't teleport
 // the nodes that survived it
 const prev = simNodesRef.current;
 const carried = m.nodes.some((node) => prev.has(node.id));
 const simNodes: SimNode[] = m.nodes.map((node, i) => {
 const p = prev.get(node.id);
 const angle = (2 * Math.PI * i) / n;
 return {
 ...node,
 x: p?.x ?? Math.cos(angle) * 200,
 y: p?.y ?? Math.sin(angle) * 200,
 };
 });
 const byId = new Map(simNodes.map((s) => [s.id, s]));
 simNodesRef.current = byId;

 // radial cluster centre per gateway, computed from N (helps physics separate
 // clusters cleanly when charge alone leaves them overlapping)
 const centreFor = new Map<string, { x: number; y: number }>();
 let gi = 0;
 const spread = 260 + gw * 60;
 for (const node of m.nodes) {
 if (node.kind === "gateway") {
 const a = (2 * Math.PI * gi) / gw;
 centreFor.set(node.subnet ?? node.id, {
 x: Math.cos(a) * spread,
 y: Math.sin(a) * spread,
 });
 gi++;
 }
 }
 const clusterCentre = (s: SimNode) =>
 (s.subnet && centreFor.get(s.subnet)) || { x: 0, y: 0 };

 const sim = forceSimulation<SimNode>(simNodes)
 .force(
 "link",
 forceLink<SimNode, GraphLink>(m.links.map((l) => ({ ...l })))
 .id((d) => d.id)
 // short within a subnet, long from gateway → INTERNET
 .distance((l: any) =>
 l.source.kind === "internet" || l.target.kind === "internet" ? 220 : 70,
 )
 .strength(0.5),
 )
 // repulsion scales with node count so dense graphs push apart harder
 .force("charge", forceManyBody().strength(-120 - n * 2))
 .force("collide", forceCollide<SimNode>((d) => nodeRadius(d) + 8))
 .force("center", forceCenter(0, 0))
 .force("x", forceX<SimNode>((d) => clusterCentre(d).x).strength(0.06))
 .force("y", forceY<SimNode>((d) => clusterCentre(d).y).strength(0.06))
 // existing layout gets a gentle nudge, only a cold start heats fully
 .alpha(carried ? 0.25 : 1)
 .alphaDecay(0.028);

 // pre-tick 60 steps synchronously so initial layout is instantly stable
 sim.tick(60);

 let lastPaint = 0;
 const paint = () => {
 const now = performance.now();
 if (now - lastPaint < 33 && sim.alpha() > 0.05) return; // throttle to ~30fps max
 lastPaint = now;
 setRfNodes(
 simNodes.map((s) => ({
 id: s.id,
 type: "fnode",
 position: { x: Math.round(s.x), y: Math.round(s.y) },
 data: { node: s },
 draggable: s.kind !== "internet",
 })),
 );
 };

 sim.on("tick", paint);
 sim.on("end", () => {
 paint();
 });

 paint();
 simRef.current = sim;

 return () => {
 sim.stop();
 };
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [structureKey, rf]);

 // Fit the viewport ONLY once on initial mount so camera never jumps during live polling
 useEffect(() => {
 if (rfNodes.length === 0) return;
 if (fittedRef.current === 0) {
 const t = window.setTimeout(() => {
 rf.fitView({ padding: 0.25, duration: 400, maxZoom: 1.3 });
 fittedRef.current = rfNodes.length;
 }, 250);
 return () => window.clearTimeout(t);
 }
 }, [rfNodes.length, rf]);

 // merge FRESH per-node data (risk, vuln counts, callbacks) into the painted
 // positions — data updates never touch the simulation
 const styledNodes = useMemo(() => {
 const fresh = new Map(model.nodes.map((gn) => [gn.id, gn]));
 const near = hovered ? neighbours.get(hovered) ?? new Set([hovered]) : null;
 return rfNodes.map((nd) => ({
 ...nd,
 data: {
 node: fresh.get(nd.id) ?? nd.data.node,
 onPick,
 onExpand,
 scanRisk,
 dim: near ? !near.has(nd.id) : false,
 focus: nd.id === hovered,
 },
 }));
 }, [rfNodes, hovered, neighbours, model, onPick, onExpand, scanRisk]);

 const edges: Edge[] = useMemo(() => {
 const near = hovered ? neighbours.get(hovered) : null;
 return model.links.map((l, i) => {
 const active = !near || (near.has(l.source) && near.has(l.target));
 return {
 id: `e${i}:${l.source}-${l.target}`,
 source: l.source,
 target: l.target,
 style: {
 stroke: active ? "rgba(0,255,102,0.7)" : "rgba(21,34,25,0.75)",
 strokeWidth: active ? 1.5 : 0.9,
 },
 };
 });
 }, [model, hovered, neighbours]);

 return (
 <ReactFlow
 nodes={styledNodes}
 edges={edges}
 nodeTypes={forceNodeTypes}
 fitView
 fitViewOptions={{ padding: 0.25, maxZoom: 1.4 }}
 minZoom={0.05}
 maxZoom={2}
 proOptions={{ hideAttribution: true }}
 nodesConnectable={false}
 onNodeMouseEnter={(_, nd) => setHovered(nd.id)}
 onNodeMouseLeave={() => setHovered(null)}
 onNodeDragStart={(_, nd) => {
 const s = simNodesRef.current.get(nd.id);
 if (s) {
 s.fx = nd.position.x;
 s.fy = nd.position.y;
 }
 simRef.current?.alphaTarget(0.3).restart();
 }}
 onNodeDrag={(_, nd) => {
 const s = simNodesRef.current.get(nd.id);
 if (s) {
 s.fx = nd.position.x;
 s.fy = nd.position.y;
 }
 }}
 onNodeDragStop={(_, nd) => {
 // release → the node springs back into the simulation
 const s = simNodesRef.current.get(nd.id);
 if (s) {
 s.fx = null;
 s.fy = null;
 }
 simRef.current?.alphaTarget(0);
 }}
 className="bg-[#050706]"
 >
 <Background variant={BackgroundVariant.Dots} gap={26} size={1.2} color="#152219" />
 <Controls className="!border-hairline !bg-surface-1/90 !rounded !text-ink-primary" showInteractive={false} />
 <div className="absolute bottom-3 left-3 z-10">
 <button
 onClick={() => rf.fitView({ padding: 0.25, duration: 400, maxZoom: 1.3 })}
 className="flex items-center gap-1.5 rounded border border-hairline/80 bg-surface-1/90 px-3 py-1.5 font-mono text-[10px] uppercase font-semibold text-ink-secondary backdrop-blur transition-all hover:border-accent-500/50 hover:text-accent-400 shadow-md"
 title="Recenter all nodes in view"
 >
 <Crosshair className="h-3.5 w-3.5 text-accent-400" /> RECENTER TOPOLOGY
 </button>
 </div>
 </ReactFlow>
 );
}

function ForceNode({ data }: NodeProps) {
 const n: GraphNode = data.node;
 const dim: boolean = data.dim;
 const focus: boolean = data.focus;
 const accent = nodeAccent(n, data.scanRisk);
 const r = nodeRadius(n);
 const highRisk =
 n.device?.scanned && (n.device.vuln_count ?? 0) > 0 &&
 (n.device.worst_severity === "critical" || n.device.worst_severity === "high");

 const clickable = n.kind === "client" || n.kind === "gateway";
 const onClick = () => {
 if (n.kind === "cluster" && n.subnet) return data.onExpand(n.subnet);
 if (n.device) data.onPick(n.device);
 };

 // build a human-readable tooltip label
 const tooltipLines: string[] = [];
 tooltipLines.push(n.label);
 if (n.kind === "gateway" && n.device) {
 if (n.device.mac) tooltipLines.push(`MAC: ${n.device.mac}`);
 if (n.gatewayIp) tooltipLines.push(`IP: ${n.gatewayIp}`);
 }
 if (n.kind === "client" && n.device) {
 if (n.device.mac) tooltipLines.push(`MAC: ${n.device.mac}`);
 if (n.device.vendor) tooltipLines.push(n.device.vendor);
 if (n.device.scanned) tooltipLines.push(`${n.device.vuln_count ?? 0} CVEs`);
 }
 if (n.kind === "internet") tooltipLines.push("Internet gateway");

 return (
 <button
 onClick={onClick}
 className="group flex flex-col items-center transition-opacity duration-200"
 style={{ opacity: dim ? 0.2 : 1, cursor: clickable || n.kind === "cluster" ? "pointer" : "default" }}
 title={tooltipLines.join("\n")}
 >
 <Handle type="source" position={Position.Top} className="!opacity-0" />
 <Handle type="target" position={Position.Top} className="!opacity-0" />
 <div
 className="flex items-center justify-center rounded-full transition-transform duration-200 group-hover:scale-110"
 style={{
 width: r * 2,
 height: r * 2,
 // ghost = outlined + unfilled; everything else filled
 border: `2px ${n.kind === "ghost" ? "dashed" : "solid"} ${accent}`,
 // L3 (no MAC) devices get a dashed border too — visibly "less known"
 borderStyle:
 n.kind === "ghost" || n.device?.discovery === "l3" ? "dashed" : "solid",
 backgroundColor: n.kind === "ghost" ? "transparent" : `${accent}22`,
 color: accent,
 boxShadow: highRisk
 ? `0 0 24px ${accent}aa`
 : focus
 ? `0 0 18px ${accent}88`
 : n.kind === "gateway"
 ? `0 0 16px ${accent}66`
 : n.kind === "internet"
 ? `0 0 14px ${accent}55`
 : "none",
 }}
 >
 {n.kind === "internet" && <Network className="h-7 w-7" />}
 {n.kind === "gateway" && (
 <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
 <path d="M12 2L2 7l10 5 10-5-10-5z" />
 <path d="M2 17l10 5 10-5" />
 <path d="M2 12l10 5 10-5" />
 </svg>
 )}
 {n.kind === "cluster" && <span className="text-[10px] font-semibold">{n.count}</span>}
 </div>
 <div
 className="mt-2 max-w-[130px] truncate rounded-md border border-hairline bg-surface-1/80 px-2 py-1 font-mono text-[10px] text-ink backdrop-blur-sm"
 style={{ opacity: dim ? 0 : 1 }}
 >
 {n.kind === "internet"
 ? "INTERNET"
 : n.kind === "gateway"
 ? n.device?.mac
 ? n.label
 : `⌂ ${n.label}`
 : n.kind === "ghost"
 ? `⃝ ${n.label}`
 : n.label}
 </div>
 {/* Gateway IP/mac subtitle beneath the label for maximum visibility */}
 {n.kind === "gateway" && n.device?.mac && (
 <div
 className="max-w-[130px] truncate text-center font-mono text-[9px] text-ink-muted"
 style={{ opacity: dim ? 0 : 1 }}
 >
 {n.device.mac}
 </div>
 )}

 {/* Active App & Website Telemetry Badges directly on map node */}
 {n.device && ((n.device.active_apps && n.device.active_apps.length > 0) || (n.device.active_domains && n.device.active_domains.length > 0)) && (
 <div
 className="mt-1 flex max-w-[145px] flex-wrap items-center justify-center gap-1"
 style={{ opacity: dim ? 0 : 1 }}
 >
 {n.device.active_apps?.slice(0, 2).map((app) => (
 <span
 key={app}
 className="inline-flex items-center gap-1 rounded border border-orange-500/40 bg-orange-500/15 px-1.5 py-0.5 text-[8.5px] font-semibold text-orange-600 shadow-sm backdrop-blur-sm"
 >
 <span className="h-1.5 w-1.5 rounded-full bg-orange-500 animate-pulse" />
 {app}
 </span>
 ))}
 {n.device.active_domains?.slice(0, 1).map((dom) => (
 <span
 key={dom}
 className="inline-flex max-w-[125px] items-center gap-1 truncate rounded border border-sky-500/30 bg-sky-500/10 px-1.5 py-0.5 font-mono text-[8px] text-sky-600 shadow-sm backdrop-blur-sm"
 title={dom}
 >
 🌐 {dom}
 </span>
 ))}
 </div>
 )}
 </button>
 );
}

// ── coverage strip: "N networks seen · M inventoried · K uncovered" ──────────
export function CoverageStrip({ coverage }: { coverage: NetworkCoverage[] }) {
 if (coverage.length === 0) return null;
 const seen = coverage.length;
 const inventoried = coverage.filter((c) => c.status === "inventoried").length;
 const uncovered = coverage.filter(
 (c) => c.status === "seen_not_joined" || c.status === "unreachable" || c.status === "reachable_not_scanned",
 ).length;
 return (
 <div className="mb-3 flex flex-wrap items-center gap-2 text-[11px] text-ink-muted">
 <span className="rounded-full border border-hairline px-2.5 py-0.5">
 <b className="text-ink">{seen}</b> networks seen
 </span>
 <span className="rounded-full border border-risk-safe/40 bg-risk-safe/10 px-2.5 py-0.5 text-risk-safe">
 <b>{inventoried}</b> inventoried
 </span>
 {uncovered > 0 && (
 <span className="rounded-full border border-risk-medium/40 bg-risk-medium/10 px-2.5 py-0.5 text-risk-medium">
 <b>{uncovered}</b> uncovered
 </span>
 )}
 </div>
 );
}
