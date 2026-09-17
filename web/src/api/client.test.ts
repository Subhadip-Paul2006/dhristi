// Drishti v0.1 — API client unit tests | 11-Jul-2026
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, registerLogout, setTokens } from "./client";

describe("apiClient auth flow (TESTING.md §4)", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    setTokens({ access_token: "acc", refresh_token: "ref", token_type: "bearer" });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("refreshes once on 401 then retries, no infinite loop", async () => {
    // 1st call → 401, refresh → 200, retry → 200
    fetchMock
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "new", refresh_token: "ref2" }), {
          status: 200,
        }),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify({ total_exposure_usd: 1 }), { status: 200 }));

    const data = await api.dashboard();
    expect(data.total_exposure_usd).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("logs out after refresh fails on repeated 401 (no loop)", async () => {
    const onLogout = vi.fn();
    registerLogout(onLogout);
    fetchMock
      .mockResolvedValueOnce(new Response(null, { status: 401 })) // first request
      .mockResolvedValueOnce(new Response(null, { status: 401 })) // refresh fails
      .mockResolvedValueOnce(new Response(null, { status: 401 })); // retry still 401

    await expect(api.dashboard()).rejects.toBeTruthy();
    expect(onLogout).toHaveBeenCalledTimes(1);
    // no runaway: at most first + refresh + one retry
    expect(fetchMock.mock.calls.length).toBeLessThanOrEqual(3);
  });

  it("coalesces concurrent 401s into a single refresh call", async () => {
    let refreshCalls = 0;
    const retried = new Set<string>();
    fetchMock.mockImplementation((path: string) => {
      if (path === "/api/auth/refresh") {
        refreshCalls++;
        return Promise.resolve(
          new Response(JSON.stringify({ access_token: "new", refresh_token: "ref2" }), {
            status: 200,
          }),
        );
      }
      if (!retried.has(path)) {
        retried.add(path);
        return Promise.resolve(new Response(null, { status: 401 }));
      }
      return Promise.resolve(new Response(JSON.stringify({ ok: path }), { status: 200 }));
    });

    const [dashboard, stats] = await Promise.all([api.dashboard(), api.stats()]);
    expect(dashboard).toMatchObject({ ok: "/api/dashboard" });
    expect(stats).toMatchObject({ ok: "/api/stats" });
    expect(refreshCalls).toBe(1);
  });

  it("normalizes the error envelope into ApiError", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: { code: "not_found", message: "Asset not found" } }), {
        status: 404,
      }),
    );
    await expect(api.asset("x")).rejects.toMatchObject({ code: "not_found", status: 404 });
  });
});
