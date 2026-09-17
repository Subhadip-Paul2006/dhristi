import React, { useRef, useEffect, useCallback, useState, type ReactNode } from "react";
import "./NetworkGraph.css";

interface NodeData {
 id: string;
 label: string;
 type: "entry" | "internal" | "crown";
 x?: number;
 y?: number;
 vx?: number;
 vy?: number;
}

interface EdgeData {
 from: string;
 to: string;
 label?: string;
}

interface NetworkGraphProps {
 nodes?: NodeData[];
 edges?: EdgeData[];
 width?: number;
 height?: number;
 className?: string;
 overlayContent?: ReactNode;
}

const DEFAULT_NODES: NodeData[] = [
 { id: "internet", label: "INTERNET", type: "entry" },
 { id: "firewall", label: "Edge Firewall", type: "internal" },
 { id: "loadbalancer", label: "Load Balancer", type: "internal" },
 { id: "webserver1", label: "Web Server 01", type: "internal" },
 { id: "webserver2", label: "Web Server 02", type: "internal" },
 { id: "apigateway", label: "API Gateway", type: "internal" },
 { id: "auth", label: "Auth (Keycloak)", type: "internal" },
 { id: "database", label: "PostgreSQL DB", type: "crown" },
 { id: "redis", label: "Redis Cache", type: "internal" },
 { id: "monitor", label: "SIEM Monitor", type: "internal" },
];

const DEFAULT_EDGES: EdgeData[] = [
 { from: "internet", to: "firewall" },
 { from: "firewall", to: "loadbalancer" },
 { from: "loadbalancer", to: "webserver1" },
 { from: "loadbalancer", to: "webserver2" },
 { from: "webserver1", to: "apigateway" },
 { from: "webserver2", to: "apigateway" },
 { from: "apigateway", to: "auth" },
 { from: "apigateway", to: "database" },
 { from: "apigateway", to: "redis" },
 { from: "auth", to: "database" },
 { from: "database", to: "monitor" },
 { from: "firewall", to: "monitor" },
];

const TYPE_COLORS = {
 entry: "#e11d48",
 internal: "#38c6f4",
 crown: "#ea580c",
};

const TYPE_GLOW = {
 entry: "rgba(225, 29, 72, 0.6)",
 internal: "rgba(56, 198, 244, 0.5)",
 crown: "rgba(234, 88, 12, 0.7)",
};

export default function NetworkGraph({
 nodes: inputNodes,
 edges: inputEdges,
 className = "",
 overlayContent,
}: NetworkGraphProps) {
 const canvasRef = useRef<HTMLCanvasElement>(null);
 const containerRef = useRef<HTMLDivElement>(null);
 const nodesRef = useRef<NodeData[]>([]);
 const edgesRef = useRef<EdgeData[]>([]);
 const animFrameRef = useRef<number>(0);
 const mouseRef = useRef({ x: 0, y: 0, active: false });
 const hoveredNodeRef = useRef<string | null>(null);
 const packetsRef = useRef<{ from: string; to: string; progress: number; speed: number }[]>([]);
 const [hoveredNode, setHoveredNode] = useState<string | null>(null);
 const [tooltip, setTooltip] = useState<{ x: number; y: number; label: string; type: string } | null>(null);
 const [dims, setDims] = useState({ width: 800, height: 600 });

 const nodes = inputNodes || DEFAULT_NODES;
 const edges = inputEdges || DEFAULT_EDGES;

 // Resize observer
 useEffect(() => {
 const container = containerRef.current;
 if (!container) return;

 const updateDims = () => {
 const rect = container.getBoundingClientRect();
 setDims({ width: rect.width, height: Math.max(rect.height, 500) });
 };
 updateDims();

 const observer = new ResizeObserver(updateDims);
 observer.observe(container);
 return () => observer.disconnect();
 }, []);

 // Initialize nodes
 useEffect(() => {
 const cx = dims.width / 2;
 const cy = dims.height / 2;
 const radius = Math.min(dims.width, dims.height) * 0.3;

 nodesRef.current = nodes.map((n, i) => {
 const angle = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
 const wobble = (Math.random() - 0.5) * 60;
 return {
 ...n,
 x: cx + Math.cos(angle) * radius + wobble,
 y: cy + Math.sin(angle) * radius + wobble,
 vx: 0,
 vy: 0,
 };
 });

 edgesRef.current = edges;

 // Spawn initial packets
 const spawnPackets = () => {
 packetsRef.current = edges
 .filter(() => Math.random() > 0.5)
 .slice(0, 8)
 .map((e) => ({
 from: e.from,
 to: e.to,
 progress: Math.random(),
 speed: 0.003 + Math.random() * 0.004,
 }));
 };
 spawnPackets();
 setInterval(spawnPackets, 3000);
 }, [nodes, edges, dims]);

 // Force simulation + render
 useEffect(() => {
 const canvas = canvasRef.current;
 if (!canvas) return;
 const ctx = canvas.getContext("2d");
 if (!ctx) return;

 const dpr = Math.min(window.devicePixelRatio || 1, 2);
 canvas.width = dims.width * dpr;
 canvas.height = dims.height * dpr;
 ctx.scale(dpr, dpr);

 const cx = dims.width / 2;
 const cy = dims.height / 2;

 const render = () => {
 animFrameRef.current = requestAnimationFrame(render);
 const currentNodes = nodesRef.current;
 const currentEdges = edgesRef.current;

 ctx.clearRect(0, 0, dims.width, dims.height);

 // Background grid
 ctx.strokeStyle = "rgba(255, 255, 255, 0.03)";
 ctx.lineWidth = 1;
 const gridSize = 40;
 for (let x = 0; x < dims.width; x += gridSize) {
 ctx.beginPath();
 ctx.moveTo(x, 0);
 ctx.lineTo(x, dims.height);
 ctx.stroke();
 }
 for (let y = 0; y < dims.height; y += gridSize) {
 ctx.beginPath();
 ctx.moveTo(0, y);
 ctx.lineTo(dims.width, y);
 ctx.stroke();
 }

 // Force simulation step
 const nodeMap = new Map(currentNodes.map((n) => [n.id, n]));
 const repulsion = 8000;
 const attraction = 0.01;
 const damping = 0.85;
 const centerPull = 0.005;

 currentNodes.forEach((node) => {
 // Center gravity
 node.vx = (node.vx || 0) + (cx - node.x!) * centerPull;
 node.vy = (node.vy || 0) + (cy - node.y!) * centerPull;

 // Repulsion from other nodes
 currentNodes.forEach((other) => {
 if (node.id === other.id) return;
 const dx = node.x! - other.x!;
 const dy = node.y! - other.y!;
 const distSq = Math.max(dx * dx + dy * dy, 1);
 const force = repulsion / distSq;
 const dist = Math.sqrt(distSq);
 node.vx = (node.vx || 0) + (dx / dist) * force * 0.3;
 node.vy = (node.vy || 0) + (dy / dist) * force * 0.3;
 });
 });

 // Edge attraction
 currentEdges.forEach((edge) => {
 const source = nodeMap.get(edge.from);
 const target = nodeMap.get(edge.to);
 if (!source || !target) return;

 const dx = target.x! - source.x!;
 const dy = target.y! - source.y!;

 source.vx = (source.vx || 0) + dx * attraction;
 source.vy = (source.vy || 0) + dy * attraction;
 target.vx = (target.vx || 0) - dx * attraction;
 target.vy = (target.vy || 0) - dy * attraction;
 });

 // Mouse repulsion
 if (mouseRef.current.active) {
 const mx = mouseRef.current.x;
 const my = mouseRef.current.y;
 currentNodes.forEach((node) => {
 const dx = node.x! - mx;
 const dy = node.y! - my;
 const dist = Math.sqrt(dx * dx + dy * dy) || 1;
 if (dist < 150) {
 const force = (150 - dist) * 0.03;
 node.vx = (node.vx || 0) + (dx / dist) * force;
 node.vy = (node.vy || 0) + (dy / dist) * force;
 }
 });
 }

 // Apply velocity
 currentNodes.forEach((node) => {
 node.vx = (node.vx || 0) * damping;
 node.vy = (node.vy || 0) * damping;
 node.x = Math.max(60, Math.min(dims.width - 60, (node.x || 0) + (node.vx || 0)));
 node.y = Math.max(60, Math.min(dims.height - 60, (node.y || 0) + (node.vy || 0)));
 });

 // Draw edges
 currentEdges.forEach((edge) => {
 const source = nodeMap.get(edge.from);
 const target = nodeMap.get(edge.to);
 if (!source || !target) return;

 const isHighlighted =
 hoveredNodeRef.current &&
 (edge.from === hoveredNodeRef.current || edge.to === hoveredNodeRef.current);

 const gradient = ctx.createLinearGradient(
 source.x!, source.y!, target.x!, target.y!
 );
 if (isHighlighted) {
 gradient.addColorStop(0, TYPE_COLORS[source.type] || "#38c6f4");
 gradient.addColorStop(1, TYPE_COLORS[target.type] || "#38c6f4");
 } else {
 gradient.addColorStop(0, "rgba(255, 255, 255, 0.06)");
 gradient.addColorStop(1, "rgba(255, 255, 255, 0.06)");
 }

 ctx.beginPath();
 ctx.moveTo(source.x!, source.y!);
 ctx.lineTo(target.x!, target.y!);
 ctx.strokeStyle = gradient;
 ctx.lineWidth = isHighlighted ? 2 : 1;
 ctx.stroke();

 // Animated data packets
 if (isHighlighted) {
 packetsRef.current.forEach((pkt) => {
 if ((pkt.from === edge.from && pkt.to === edge.to) || (pkt.from === edge.to && pkt.to === edge.from)) {
 pkt.progress += pkt.speed;
 if (pkt.progress > 1) pkt.progress = 0;

 const px = source.x! + (target.x! - source.x!) * pkt.progress;
 const py = source.y! + (target.y! - source.y!) * pkt.progress;

 ctx.beginPath();
 ctx.arc(px, py, 3, 0, Math.PI * 2);
 ctx.fillStyle = "#ea580c";
 ctx.fill();
 ctx.beginPath();
 ctx.arc(px, py, 6, 0, Math.PI * 2);
 ctx.fillStyle = "rgba(234, 88, 12, 0.3)";
 ctx.fill();
 }
 });
 }
 });

 // Draw nodes
 currentNodes.forEach((node) => {
 const isHovered = hoveredNodeRef.current === node.id;
 const isConnected = hoveredNodeRef.current
 ? currentEdges.some(
 (e) =>
 (e.from === hoveredNodeRef.current && e.to === node.id) ||
 (e.to === hoveredNodeRef.current && e.from === node.id)
 )
 || hoveredNodeRef.current === node.id
 : true;

 const opacity = (hoveredNodeRef.current && !isConnected) ? 0.2 : 1;
 const color = TYPE_COLORS[node.type] || "#38c6f4";
 const glow = TYPE_GLOW[node.type] || "rgba(56, 198, 244, 0.5)";
 const radius = node.type === "crown" ? 18 : node.type === "entry" ? 14 : 12;

 ctx.globalAlpha = opacity;

 // Glow
 if (isHovered) {
 ctx.beginPath();
 ctx.arc(node.x!, node.y!, radius + 12, 0, Math.PI * 2);
 ctx.fillStyle = glow;
 ctx.fill();
 }

 // Node circle
 ctx.beginPath();
 ctx.arc(node.x!, node.y!, radius, 0, Math.PI * 2);
 ctx.fillStyle = isHovered ? color : `${color}22`;
 ctx.fill();
 ctx.strokeStyle = color;
 ctx.lineWidth = isHovered ? 2.5 : 1.5;
 ctx.stroke();

 // Inner dot
 ctx.beginPath();
 ctx.arc(node.x!, node.y!, radius * 0.4, 0, Math.PI * 2);
 ctx.fillStyle = color;
 ctx.fill();

 // Crown jewel indicator
 if (node.type === "crown") {
 ctx.font = "bold 10px var(--font-family-mono)";
 ctx.fillStyle = color;
 ctx.textAlign = "center";
 ctx.fillText("👑", node.x!, node.y! - radius - 8);
 }

 // Label
 ctx.font = `600 11px var(--font-family-primary)`;
 ctx.fillStyle = isHovered ? "#ffffff" : "#94a3b8";
 ctx.textAlign = "center";
 ctx.fillText(node.label, node.x!, node.y! + radius + 16);

 ctx.globalAlpha = 1;
 });
 };

 render();

 return () => {
 cancelAnimationFrame(animFrameRef.current);
 };
 }, [dims, hoveredNode]);

 // Mouse handlers
 const handleMouseMove = useCallback((e: React.MouseEvent) => {
 const rect = canvasRef.current?.getBoundingClientRect();
 if (!rect) return;
 mouseRef.current = {
 x: e.clientX - rect.left,
 y: e.clientY - rect.top,
 active: true,
 };

 // Check hover on nodes
 const nodeMap = new Map(nodesRef.current.map((n) => [n.id, n]));
 let found: string | null = null;
 nodesRef.current.forEach((node) => {
 const dx = mouseRef.current.x - node.x!;
 const dy = mouseRef.current.y - node.y!;
 const dist = Math.sqrt(dx * dx + dy * dy);
 if (dist < 20) found = node.id;
 });

 if (found !== hoveredNodeRef.current) {
 hoveredNodeRef.current = found;
 setHoveredNode(found);

 if (found) {
 const node = nodeMap.get(found);
 if (node) {
 setTooltip({
 x: node.x! + 20,
 y: node.y! - 10,
 label: node.label,
 type: node.type,
 });
 }
 } else {
 setTooltip(null);
 }
 }
 }, []);

 const handleMouseLeave = () => {
 mouseRef.current.active = false;
 hoveredNodeRef.current = null;
 setHoveredNode(null);
 setTooltip(null);
 };

 return (
 <div ref={containerRef} className={`network-graph ${className}`} style={{ position: "relative", width: "100%", height: "100%" }}>
 <canvas
 ref={canvasRef}
 onMouseMove={handleMouseMove}
 onMouseLeave={handleMouseLeave}
 style={{ display: "block", width: "100%", height: "100%" }}
 />

 {/* Legend */}
 <div className="network-graph__legend">
 <div className="network-graph__legend-item">
 <span className="network-graph__legend-dot" style={{ background: TYPE_COLORS.entry }} />
 <span>Entry Point</span>
 </div>
 <div className="network-graph__legend-item">
 <span className="network-graph__legend-dot" style={{ background: TYPE_COLORS.internal }} />
 <span>Internal</span>
 </div>
 <div className="network-graph__legend-item">
 <span className="network-graph__legend-dot" style={{ background: TYPE_COLORS.crown }} />
 <span>Crown Jewel</span>
 </div>
</div>

 {/* Tooltip */}
 {tooltip && (
 <div
 className="network-graph__tooltip"
 style={{
 left: tooltip.x,
 top: tooltip.y,
 }}
 >
 <div className="network-graph__tooltip-label">{tooltip.label}</div>
 <div className="network-graph__tooltip-type">{tooltip.type.toUpperCase()}</div>
 </div>
 )}

 {/* Overlay content (for titles, etc.) */}
 {overlayContent}
 </div>
 );
}
