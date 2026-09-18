import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { LiveActivitySection, CapabilityBadge } from "./LiveWatchPage";
import type { NetworkDevice } from "../../api/types";

function mockDevice(overrides: Partial<NetworkDevice> = {}): NetworkDevice {
  return {
    id: "dev-test-1",
    ip: "192.168.1.50",
    mac: "00:11:22:33:44:55",
    subnet: "192.168.1.0/24",
    subnet_inferred: false,
    discovery: "arp",
    label: null,
    hostname: "workstation-lab",
    vendor: null,
    is_self: false,
    is_gateway: false,
    online: true,
    first_seen: "2026-09-18T00:00:00Z",
    last_seen: "2026-09-18T00:00:00Z",
    scanned: false,
    vuln_count: null,
    worst_severity: null,
    last_scanned_at: null,
    capability_state: "FULL ENDPOINT TELEMETRY",
    ...overrides,
  };
}

describe("LiveActivitySection UI Component", () => {
  it("13. renders running user applications with [USER APPLICATION] and [WINDOWS ENDPOINT] badges", () => {
    const dev = mockDevice({
      is_self: true,
      capability_state: "FULL ENDPOINT TELEMETRY",
      endpoint_processes: [
        {
          name: "code.exe",
          evidence_type: "ENDPOINT_PROCESS",
          source: "windows_endpoint",
          category: "USER_APPLICATION",
          observed_at: "2026-09-18T10:00:00Z",
          details: "PID: 5432 | [USER_APPLICATION]",
        },
        {
          name: "chrome.exe",
          evidence_type: "ENDPOINT_PROCESS",
          source: "windows_endpoint",
          category: "USER_APPLICATION",
          observed_at: "2026-09-18T10:00:00Z",
          details: "PID: 8876 | [USER_APPLICATION]",
        },
      ],
    });

    render(<LiveActivitySection device={dev} />);

    expect(screen.getByText(/Running Applications/i)).toBeInTheDocument();
    expect(screen.getByText("code.exe")).toBeInTheDocument();
    expect(screen.getByText("chrome.exe")).toBeInTheDocument();
    expect(screen.getByText("PID: 5432")).toBeInTheDocument();
    expect(screen.getByText("PID: 8876")).toBeInTheDocument();
    expect(screen.getByText("[USER APPLICATION]")).toBeInTheDocument();
    expect(screen.getAllByText("[WINDOWS ENDPOINT]")[0]).toBeInTheDocument();
    expect(screen.getByText("[FULL ENDPOINT TELEMETRY]")).toBeInTheDocument();
  });

  it("14. renders background processes separately with [BACKGROUND PROCESS] badge", () => {
    const dev = mockDevice({
      is_self: true,
      capability_state: "AGENT CONNECTED",
      endpoint_processes: [
        {
          name: "node.exe",
          evidence_type: "ENDPOINT_PROCESS",
          source: "windows_endpoint",
          category: "BACKGROUND_PROCESS",
          observed_at: "2026-09-18T10:00:00Z",
          details: "PID: 4321 | [BACKGROUND_PROCESS]",
        },
      ],
    });

    render(<LiveActivitySection device={dev} />);

    expect(screen.getByText(/Background Processes/i)).toBeInTheDocument();
    expect(screen.getByText("node.exe")).toBeInTheDocument();
    expect(screen.getByText("PID: 4321")).toBeInTheDocument();
    expect(screen.getByText("[BACKGROUND PROCESS]")).toBeInTheDocument();
    expect(screen.getByText("[AGENT CONNECTED]")).toBeInTheDocument();
  });

  it("15. renders active browser tab with [ACTIVE TAB] badge, browser, title, and url", () => {
    const dev = mockDevice({
      is_self: true,
      active_browser_tabs: [
        {
          name: "Google Chrome: github.com",
          evidence_type: "BROWSER_ACTIVE_TAB",
          source: "browser_extension",
          browser: "Google Chrome",
          domain: "github.com",
          title: "Subhadip-Paul2006/dhristi - GitHub",
          url: "https://github.com/Subhadip-Paul2006/dhristi",
          observed_at: "2026-09-18T10:00:00Z",
        },
      ],
    });

    render(<LiveActivitySection device={dev} />);

    expect(screen.getByText(/Active Browser Tabs/i)).toBeInTheDocument();
    expect(screen.getByText("[ACTIVE TAB]")).toBeInTheDocument();
    expect(screen.getByText(/Subhadip-Paul2006\/dhristi - GitHub/i)).toBeInTheDocument();
    expect(screen.getByText("github.com")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /github.com/i })).toHaveAttribute(
      "href",
      "https://github.com/Subhadip-Paul2006/dhristi"
    );
  });

  it("16. renders process socket connections with [PROCESS SOCKET] badge", () => {
    const dev = mockDevice({
      is_self: true,
      endpoint_processes: [
        {
          name: "chrome.exe",
          evidence_type: "ENDPOINT_PROCESS",
          source: "windows_endpoint",
          category: "USER_APPLICATION",
        },
      ],
      process_connections: [
        {
          name: "chrome.exe:52341",
          evidence_type: "PROCESS_NETWORK_CONNECTION",
          source: "windows_endpoint",
          observed_at: "2026-09-18T10:00:00Z",
          details: "PID: 4210 | TCP | Local: 192.168.1.10:52341 | Remote: 142.250.190.46:443 | Status: ESTABLISHED",
        },
      ],
    });

    render(<LiveActivitySection device={dev} />);

    expect(screen.getByText(/Process Socket Connections/i)).toBeInTheDocument();
    expect(screen.getByText("[PROCESS SOCKET]")).toBeInTheDocument();
    expect(screen.getByText("chrome.exe:52341")).toBeInTheDocument();
    expect(screen.getByText(/PID: 4210/)).toBeInTheDocument();
  });

  it("17. remote device without agent shows TELEMETRY UNAVAILABLE and ENDPOINT AGENT NOT INSTALLED", () => {
    const remoteDev = mockDevice({
      is_self: false,
      capability_state: "NETWORK ONLY",
      endpoint_processes: [],
      active_browser_tabs: [],
      installed_browsers: [],
    });

    render(<LiveActivitySection device={remoteDev} />);

    expect(screen.getByText("TELEMETRY UNAVAILABLE")).toBeInTheDocument();
    expect(screen.getByText("ENDPOINT AGENT NOT INSTALLED")).toBeInTheDocument();
    expect(screen.queryByText("[WINDOWS ENDPOINT]")).not.toBeInTheDocument();
    expect(screen.queryByText("[ACTIVE TAB]")).not.toBeInTheDocument();
    expect(screen.getByText("[NETWORK ONLY]")).toBeInTheDocument();
  });

  it("18. authorized device without browser extension shows BROWSER TELEMETRY UNAVAILABLE and EXTENSION REQUIRED", () => {
    const devWithAgentOnly = mockDevice({
      is_self: true,
      capability_state: "AGENT CONNECTED",
      endpoint_processes: [
        {
          name: "code.exe",
          evidence_type: "ENDPOINT_PROCESS",
          source: "windows_endpoint",
          category: "USER_APPLICATION",
        },
      ],
      active_browser_tabs: [],
    });

    render(<LiveActivitySection device={devWithAgentOnly} />);

    expect(screen.getByText("BROWSER TELEMETRY UNAVAILABLE")).toBeInTheDocument();
    expect(screen.getByText("EXTENSION REQUIRED")).toBeInTheDocument();
  });

  it("19. CapabilityBadge renders correct style and state label", () => {
    const { rerender } = render(<CapabilityBadge state="FULL ENDPOINT TELEMETRY" />);
    expect(screen.getByText("[FULL ENDPOINT TELEMETRY]")).toBeInTheDocument();

    rerender(<CapabilityBadge state="AGENT CONNECTED" />);
    expect(screen.getByText("[AGENT CONNECTED]")).toBeInTheDocument();

    rerender(<CapabilityBadge state="BROWSER EXTENSION CONNECTED" />);
    expect(screen.getByText("[BROWSER EXTENSION CONNECTED]")).toBeInTheDocument();

    rerender(<CapabilityBadge state="NETWORK ONLY" />);
    expect(screen.getByText("[NETWORK ONLY]")).toBeInTheDocument();
  });
});
