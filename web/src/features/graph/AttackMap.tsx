// Drishti — interactive attack graph visualization
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Crosshair, Trash2 } from "lucide-react";
import { useEffect, useMemo, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  type Edge,
  type Node,
  ReactFlowProvider,
  useReactFlow,
} from "reactflow";
import "reactflow/dist/style.css";
import { api } from "../../api/client";
import type { GraphResponse } from "../../api/types";
import { Drawer } from "../../components/Drawer";
import { ErrorState, LoadingBlock } from "../../components/primitives";
import { useGraphStore, useToast } from "../../store/graphStore";
import { AssetDetailPanel } from "../assets/AssetDetailPanel";
import { PathDetailPanel } from "../paths/PathDetailPanel";
import { BlastLegend } from "./BlastLegend";
import { GraphNode, type RfNodeData } from "./GraphNode";

// nodeTypes MUST be defined outside the component (ERROR_HANDLING.md graph gotcha).
const nodeTypes = { asset: GraphNode, internet: GraphNode, device: GraphNode };

export function AttackMap() {
  return (
    <ReactFlowProvider>
      <AttackMapInner />
    </ReactFlowProvider>
  );
}

function AttackMapInner() {
  const [params] = useSearchParams();
  const focusParam = params.get("focus");

  const graphQ = useQuery({ queryKey: ["graph"], queryFn: () => api.graph(), refetchInterval: 5000 });
  const qc = useQueryClient();
  // demo attack lives on the same graph query — running it makes the intruder
  // node + ARP-spoofed gateway light up here on the next poll (or immediately).
  const demoActive = useMemo(
    () =>
      (graphQ.data?.nodes ?? []).some(
        (n) =>
          (n.data.mac ?? "").startsWith("de:ad:be:ef") ||
          n.data.label === "unknown-intruder" ||
          n.data.label === "attacker-mitm",
      ),
    [graphQ.data],
  );
  const demo = useMutation({
    mutationFn: () => api.demoAttack(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["graph"] }),
  });
  const clearDemo = useMutation({
    mutationFn: () => api.clearDemoAttack(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["graph"] }),
  });
  const {
    selectedNodeId,
    blastRadiusIds,
    topPathsOnly,
    drawerOpen,
    drawerView,
    activePathId,
    selectNode,
    selectPath,
    clearSelection,
    toggleTopPaths,
  } = useGraphStore();
  const toast = useToast();

  const rf = useReactFlow();

  // When a node is clicked, fetch its blast radius and light it up.
  const blastQ = useQuery({
    queryKey: ["blast", selectedNodeId],
    queryFn: () => api.blastRadius(selectedNodeId!),
    enabled: !!selectedNodeId && selectedNodeId !== "INTERNET",
  });
  useEffect(() => {
    if (blastQ.data && selectedNodeId) {
      selectNode(selectedNodeId, blastQ.data.reachable_ids);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [blastQ.data]);
  // a failed blast fetch must not be a silent no-op — say so and clear the pending selection
  useEffect(() => {
    if (blastQ.isError) {
      toast.show("Couldn't load the blast radius for that node — try again.", "error");
      clearSelection(); // don't leave the node half-selected with no drawer
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [blastQ.isError]);

  // clicking a top-path edge opens the Path Detail drawer for its attack path
  const onEdgeClick = (_: React.MouseEvent, edge: Edge) => {
    const pathId = (edge.data as { path_id?: string | null } | undefined)?.path_id;
    if (pathId) selectPath(pathId);
  };

  // deep-link ?focus= selects a node on load
  useEffect(() => {
    if (focusParam) {
      useGraphStore.getState().selectNode(focusParam, []);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusParam]);

  const onNodeSelect = (id: string) => {
    // INTERNET and live-device nodes ("dev:") aren't risk-assessed assets — no
    // blast radius / asset drawer to open, so selecting them would 404. Skip.
    if (id === "INTERNET" || id.startsWith("dev:")) return;
    useGraphStore.setState({ selectedNodeId: id });
  };

  const { nodes, edges } = useMemo(
    () => buildFlow(graphQ.data, { selectedNodeId, blastRadiusIds, topPathsOnly, onNodeSelect }),
    [graphQ.data, selectedNodeId, blastRadiusIds, topPathsOnly],
  );

  // fit the viewport only once, on the first successful load — refetches poll
  // every 5s and must not yank the user's pan/zoom back each time.
  const didFit = useRef(false);
  useEffect(() => {
    // Fit exactly once, when nodes first appear — not on every 5s poll (which
    // would yank the user's pan/zoom). didFit is only set *after* the fit runs,
    // so React StrictMode's mount/cleanup/mount can't leave it "true" with the
    // single scheduled fitView cleared (which left the map blank).
    if (didFit.current || nodes.length === 0) return;
    const t = setTimeout(() => {
      rf.fitView({ padding: 0.15, duration: 300 });
      didFit.current = true;
    }, 60);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes.length, rf]);

  return (
    <div className="relative h-[calc(100vh-56px)] w-full bg-[#050706] overflow-hidden">
      {/* HUD Telemetry Watermark */}
      <div className="pointer-events-none absolute left-5 top-5 z-10 flex flex-col gap-1.5 rounded border border-hairline/60 bg-surface-1/80 p-3 font-mono text-[11px] backdrop-blur-md shadow-[0_0_20px_rgba(0,0,0,0.5)]">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-accent-500 shadow-[0_0_8px_#00ff66] animate-pulse" />
          <span className="font-semibold uppercase tracking-wider text-accent-400">ATTACK_GRAPH // REPLAY</span>
        </div>
        <div className="flex items-center gap-3 text-ink-muted text-[10px]">
          <span>VERTICES: <strong className="text-ink-primary font-bold">{nodes.length}</strong></span>
          <span>·</span>
          <span>EDGES: <strong className="text-ink-primary font-bold">{edges.length}</strong></span>
          <span>·</span>
          <span>ENGINE: <span className="text-accent-400">ACTIVE</span></span>
        </div>
      </div>

      {graphQ.isLoading && <LoadingBlock label="Computing blast radius & traversing attack paths…" />}
      {graphQ.isError && (
        <div className="p-8">
          <ErrorState message="Couldn't load the attack graph." onRetry={() => graphQ.refetch()} />
        </div>
      )}
      {graphQ.data && (
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onPaneClick={clearSelection}
          onEdgeClick={onEdgeClick}
          fitView
          minZoom={0.3}
          maxZoom={1.6}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={24} size={1.2} color="#152219" />
          <Controls className="!border-hairline !bg-surface-1/90 !rounded !text-ink-primary" showInteractive={false} />
        </ReactFlow>
      )}

      {/* control cluster */}
      <div className="pointer-events-none absolute right-5 top-5 z-10 flex flex-col items-end gap-2.5">
        {demoActive ? (
          <button
            onClick={() => clearDemo.mutate()}
            disabled={clearDemo.isPending}
            className="pointer-events-auto inline-flex items-center gap-2 rounded border border-risk-critical bg-risk-critical/15 px-3.5 py-2 font-mono text-[11px] font-bold uppercase tracking-wider text-risk-critical shadow-[0_0_15px_rgba(239,68,68,0.25)] backdrop-blur transition-all hover:bg-risk-critical hover:text-white"
          >
            <Trash2 className="h-3.5 w-3.5 animate-pulse" /> PURGE DEMO INTRUSION
          </button>
        ) : (
          <button
            onClick={() => demo.mutate()}
            disabled={demo.isPending}
            title="Inject a live demo intrusion — watch the gateway and intruder light up"
            className="pointer-events-auto inline-flex items-center gap-2 rounded border border-hairline bg-surface-1/90 px-3.5 py-2 font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-secondary shadow-[0_0_15px_rgba(0,0,0,0.5)] backdrop-blur transition-all hover:border-risk-critical/70 hover:text-risk-critical hover:shadow-[0_0_15px_rgba(239,68,68,0.2)]"
          >
            <Crosshair className="h-3.5 w-3.5" /> SIMULATE INTRUSION
          </button>
        )}
        <button
          onClick={toggleTopPaths}
          className={`pointer-events-auto rounded border px-3.5 py-2 font-mono text-[11px] font-semibold uppercase tracking-wider backdrop-blur transition-all shadow-[0_0_15px_rgba(0,0,0,0.5)] ${
            topPathsOnly
              ? "border-accent-500 bg-accent-500/15 text-accent-400 shadow-[0_0_15px_rgba(0,255,102,0.2)]"
              : "border-hairline bg-surface-1/90 text-ink-secondary hover:border-accent-500/40 hover:text-ink-primary"
          }`}
        >
          {topPathsOnly ? "[✓] FILTER: TOP VECTORS" : "FILTER: TOP VECTORS"}
        </button>
        <div className="pointer-events-auto">
          <BlastLegend />
        </div>
        {selectedNodeId && (
          <div className="pointer-events-auto rounded border border-hairline bg-surface-1/95 px-3 py-1.5 font-mono text-[11px] text-ink-muted backdrop-blur shadow-lg">
            PRESS <kbd className="font-bold text-accent-400">[ESC]</kbd> TO UNSELECT
          </div>
        )}
      </div>

      <EscHandler onEsc={clearSelection} />

      <Drawer
        open={drawerOpen}
        onClose={clearSelection}
        title={drawerView === "path" ? "Attack path" : "Asset detail"}
      >
        {drawerView === "asset" && selectedNodeId && (
          <AssetDetailPanel assetId={selectedNodeId} showViewOnMap={false} />
        )}
        {drawerView === "path" && activePathId && <PathDetailPanel pathId={activePathId} />}
      </Drawer>
    </div>
  );
}

function EscHandler({ onEsc }: { onEsc: () => void }) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onEsc();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onEsc]);
  return null;
}

function buildFlow(
  graph: GraphResponse | undefined,
  opts: {
    selectedNodeId: string | null;
    blastRadiusIds: Set<string>;
    topPathsOnly: boolean;
    onNodeSelect: (id: string) => void;
  },
): { nodes: Node<RfNodeData>[]; edges: Edge[] } {
  if (!graph) return { nodes: [], edges: [] };
  const { selectedNodeId, blastRadiusIds, topPathsOnly, onNodeSelect } = opts;
  const hasSelection = !!selectedNodeId;

  const topPathNodeIds = new Set<string>();
  if (topPathsOnly) {
    graph.edges.forEach((e) => {
      if (e.data.on_top_path) {
        topPathNodeIds.add(e.source);
        topPathNodeIds.add(e.target);
      }
    });
  }

  const nodes: Node<RfNodeData>[] = graph.nodes
    .filter((n) => !topPathsOnly || topPathNodeIds.has(n.id) || n.id === "INTERNET")
    .map((n) => {
      const inBlast = blastRadiusIds.has(n.id);
      const isSelected = n.id === selectedNodeId;
      const dimmed = hasSelection && !inBlast && !isSelected && n.id !== "INTERNET";
      return {
        id: n.id,
        type: n.type === "internet" ? "internet" : n.type === "device" ? "device" : "asset",
        position: n.position,
        draggable: false,
        data: {
          ...n.data,
          nodeId: n.id,
          selected: isSelected,
          inBlast,
          dimmed,
          onSelect: onNodeSelect,
        },
      };
    });

  const visibleIds = new Set(nodes.map((n) => n.id));
  const edges: Edge[] = graph.edges
    .filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target))
    .map((e) => {
      const onPath = e.data.on_top_path;
      const dim =
        hasSelection && !(blastRadiusIds.has(e.source) && blastRadiusIds.has(e.target));
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        type: "default",
        animated: false,
        className: onPath ? "rf-edge-toppath" : undefined,
        data: { path_id: e.data.path_id },
        style: {
          stroke: onPath ? "#00ff66" : "#1f3325",
          strokeWidth: onPath ? 2.5 : 1.2,
          opacity: dim ? 0.15 : onPath ? 1 : 0.65,
          cursor: e.data.path_id ? "pointer" : undefined,
        },
        label: e.data.via_cve ?? undefined,
        labelStyle: { fill: onPath ? "#00ff66" : "#8ca094", fontSize: 9, fontFamily: "JetBrains Mono", fontWeight: 600 },
        labelBgStyle: { fill: "#080B09", fillOpacity: 0.95 },
      };
    });

  return { nodes, edges };
}
