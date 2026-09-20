import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { LiveTrafficPanel } from "./LiveTrafficPanel";
import type { TrackingResults, TrackingSession } from "../../api/types";
import { api } from "../../api/client";

let queryClient: QueryClient;

function renderWithClient(ui: React.ReactElement) {
  return render(
    <QueryClientProvider client={queryClient}>
      {ui}
    </QueryClientProvider>
  );
}

function createMockSession(id: string, overrides: Partial<TrackingSession> = {}): TrackingSession {
  return {
    tracking_session_id: id,
    device_id: "dev-mock-01",
    target_ip: "192.168.1.55",
    target_mac: "00:11:22:33:44:55",
    target_hostname: "workstation-lab-01",
    status: "LIVE",
    capture_source: "SCAPY / MONITORED INTERFACE",
    status_message: null,
    started_at: "2026-09-19T10:00:00Z",
    packet_count: 42,
    flow_count: 5,
    byte_count: 15420,
    ...overrides,
  };
}

function createMockResults(session: TrackingSession): TrackingResults {
  return {
    session,
    metrics: {
      packet_count: 42,
      flow_count: 5,
      byte_count: 15420,
      packets_per_sec: 14.5,
      bytes_per_sec: 5200.0,
      active_connections: 5,
    },
    protocols: {
      tcp: 30,
      udp: 12,
      icmp: 0,
      dns: 12,
      http_https: 25,
      other: 0,
    },
    top_destinations: [
      {
        destination_ip: "1.1.1.1",
        destination_port: 53,
        protocol: "UDP",
        connection_count: 12,
        last_seen: "2026-09-19T10:02:00Z",
      },
      {
        destination_ip: "142.250.190.46",
        destination_port: 443,
        protocol: "TCP",
        connection_count: 30,
        last_seen: "2026-09-19T10:02:05Z",
      },
    ],
    current_behaviour: {
      verdict: "NORMAL",
      confidence: 0.92,
      signals: [
        "Observed traffic aligns with typical benign communication profiles",
        "Balanced flow characteristics",
      ],
      attack_category: null,
    },
    evidence: [
      {
        evidence_type: "NETWORK_TRAFFIC",
        source: "SCAPY / MONITORED INTERFACE",
        observed_at: "2026-09-19T10:02:00Z",
        device_id: "dev-mock-01",
        confidence: "high",
        details: {
          destination_ip: "1.1.1.1",
          destination_port: 53,
          protocol: "UDP",
          connection_count: 12,
        },
      },
    ],
  };
}

describe("LiveTrafficPanel Component", () => {
  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false, gcTime: 0 },
      },
    });
    vi.restoreAllMocks();
  });

  it("renders target device identity, capture source, and live status badge", async () => {
    const session = createMockSession("sess-1");
    const results = createMockResults(session);
    vi.spyOn(api, "getLiveTrackingResults").mockResolvedValue(results);

    renderWithClient(<LiveTrafficPanel initialSession={session} onClose={vi.fn()} />);

    expect(screen.getByText("LIVE NETWORK TRAFFIC ANALYSIS")).toBeInTheDocument();
    expect(screen.getByText("workstation-lab-01")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.55")).toBeInTheDocument();
    expect(screen.getByText("00:11:22:33:44:55")).toBeInTheDocument();
    expect(screen.getByText("SCAPY / MONITORED INTERFACE")).toBeInTheDocument();
    expect(screen.getByText("● LIVE CAPTURE")).toBeInTheDocument();
  });

  it("displays live metrics and observed protocols", async () => {
    const session = createMockSession("sess-2");
    const results = createMockResults(session);
    vi.spyOn(api, "getLiveTrackingResults").mockResolvedValue(results);

    renderWithClient(<LiveTrafficPanel initialSession={session} onClose={vi.fn()} />);

    expect(await screen.findByText("TOTAL PACKETS")).toBeInTheDocument();
    expect(screen.getByText("ACTIVE FLOWS")).toBeInTheDocument();
    expect(screen.getByText("PACKETS / SEC")).toBeInTheDocument();
    expect(screen.getByText("THROUGHPUT")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getAllByText("TCP").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText("UDP").length).toBeGreaterThanOrEqual(1);
    });
    expect(screen.getByText("DNS")).toBeInTheDocument();
    expect(screen.getByText("HTTP/HTTPS")).toBeInTheDocument();
  });

  it("displays top destinations and current behaviour detection results", async () => {
    const session = createMockSession("sess-3");
    const results = createMockResults(session);
    vi.spyOn(api, "getLiveTrackingResults").mockResolvedValue(results);

    renderWithClient(<LiveTrafficPanel initialSession={session} onClose={vi.fn()} />);

    expect(await screen.findByText("1.1.1.1")).toBeInTheDocument();
    expect(screen.getByText("142.250.190.46")).toBeInTheDocument();

    expect(screen.getByText(/NORMAL \(92%\)/)).toBeInTheDocument();
    expect(
      screen.getByText("Observed traffic aligns with typical benign communication profiles")
    ).toBeInTheDocument();
  });

  it("stops tracking when Stop Tracking button is clicked", async () => {
    const session = createMockSession("sess-4");
    const results = createMockResults(session);
    vi.spyOn(api, "getLiveTrackingResults").mockResolvedValue(results);
    const stopSpy = vi.spyOn(api, "stopLiveTracking").mockResolvedValue({
      ...session,
      status: "STOPPED",
    });

    renderWithClient(<LiveTrafficPanel initialSession={session} onClose={vi.fn()} />);

    const stopBtn = screen.getByRole("button", { name: /stop tracking/i });
    expect(stopBtn).toBeInTheDocument();
    fireEvent.click(stopBtn);

    await waitFor(() => {
      expect(stopSpy).toHaveBeenCalledWith("sess-4");
    });
    expect(await screen.findByText("○ STOPPED")).toBeInTheDocument();
  });

  it("renders truthful UNAVAILABLE state without fabricated metrics", async () => {
    const unavailSession = createMockSession("sess-5", {
      status: "UNAVAILABLE",
      capture_source: "UNAVAILABLE",
      status_message: "No traffic observable from this monitoring point without endpoint agent.",
      packet_count: 0,
      flow_count: 0,
      byte_count: 0,
    });

    const unavailResults: TrackingResults = {
      session: unavailSession,
      metrics: {
        packet_count: 0,
        flow_count: 0,
        byte_count: 0,
        packets_per_sec: 0,
        bytes_per_sec: 0,
        active_connections: 0,
      },
      protocols: { tcp: 0, udp: 0, icmp: 0, dns: 0, http_https: 0, other: 0 },
      top_destinations: [],
      current_behaviour: {
        verdict: "INSUFFICIENT_DATA",
        confidence: 0,
        signals: ["No live traffic observed from this monitoring point without endpoint agent."],
      },
      evidence: [],
    };

    vi.spyOn(api, "getLiveTrackingResults").mockResolvedValue(unavailResults);

    renderWithClient(<LiveTrafficPanel initialSession={unavailSession} onClose={vi.fn()} />);

    expect(screen.getByText("⚠ CAPTURE UNAVAILABLE")).toBeInTheDocument();
    expect(screen.getByText("OBSERVATION NOTICE")).toBeInTheDocument();
    expect(
      screen.getByText("No traffic observable from this monitoring point without endpoint agent.")
    ).toBeInTheDocument();
  });
});
