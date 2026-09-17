// Drishti v0.1 — graph store unit tests | 11-Jul-2026
import { beforeEach, describe, expect, it } from "vitest";
import { useGraphStore } from "./graphStore";

describe("graphStore (APP_FLOW.md §8)", () => {
  beforeEach(() => useGraphStore.getState().clearSelection());

  it("selecting a node sets id + derives blast radius + opens drawer", () => {
    useGraphStore.getState().selectNode("db-1", ["a", "b", "c"]);
    const s = useGraphStore.getState();
    expect(s.selectedNodeId).toBe("db-1");
    expect(s.blastRadiusIds.has("a")).toBe(true);
    expect(s.blastRadiusIds.size).toBe(3);
    expect(s.drawerOpen).toBe(true);
    expect(s.drawerView).toBe("asset");
  });

  it("clearing resets selection and blast radius", () => {
    useGraphStore.getState().selectNode("db-1", ["a"]);
    useGraphStore.getState().clearSelection();
    const s = useGraphStore.getState();
    expect(s.selectedNodeId).toBeNull();
    expect(s.blastRadiusIds.size).toBe(0);
    expect(s.drawerOpen).toBe(false);
  });

  it("selecting a path opens the path drawer view", () => {
    useGraphStore.getState().selectPath("path-9");
    const s = useGraphStore.getState();
    expect(s.activePathId).toBe("path-9");
    expect(s.drawerView).toBe("path");
  });

  it("topPathsOnly toggles", () => {
    expect(useGraphStore.getState().topPathsOnly).toBe(false);
    useGraphStore.getState().toggleTopPaths();
    expect(useGraphStore.getState().topPathsOnly).toBe(true);
  });
});
