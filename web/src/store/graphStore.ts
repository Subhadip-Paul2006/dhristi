// Drishti v0.1 — attack graph UI selection state | 11-Jul-2026
/** UI selection state for the attack graph (APP_FLOW.md §8). Query owns server
 * data; this store owns *what the user is looking at*. */
import { create } from "zustand";

interface GraphState {
  selectedNodeId: string | null;
  blastRadiusIds: Set<string>;
  topPathsOnly: boolean;
  drawerOpen: boolean;
  drawerView: "asset" | "path" | null;
  activePathId: string | null;

  selectNode: (id: string, blast: string[]) => void;
  selectPath: (pathId: string) => void;
  clearSelection: () => void;
  toggleTopPaths: () => void;
}

export const useGraphStore = create<GraphState>((set) => ({
  selectedNodeId: null,
  blastRadiusIds: new Set(),
  topPathsOnly: false,
  drawerOpen: false,
  drawerView: null,
  activePathId: null,

  selectNode: (id, blast) =>
    set({
      selectedNodeId: id,
      blastRadiusIds: new Set(blast),
      drawerOpen: true,
      drawerView: "asset",
      activePathId: null,
    }),
  selectPath: (pathId) =>
    set({ activePathId: pathId, drawerOpen: true, drawerView: "path" }),
  clearSelection: () =>
    set({
      selectedNodeId: null,
      blastRadiusIds: new Set(),
      drawerOpen: false,
      drawerView: null,
      activePathId: null,
    }),
  toggleTopPaths: () => set((s) => ({ topPathsOnly: !s.topPathsOnly })),
}));

interface ToastState {
  message: string | null;
  variant: "success" | "error" | "info";
  show: (message: string, variant?: "success" | "error" | "info") => void;
  hide: () => void;
}
export const useToast = create<ToastState>((set) => ({
  message: null,
  variant: "info",
  show: (message, variant = "info") => set({ message, variant }),
  hide: () => set({ message: null }),
}));
