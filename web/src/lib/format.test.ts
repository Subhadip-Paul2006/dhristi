// Drishti v0.1 — formatter unit tests | 11-Jul-2026
import { describe, expect, it } from "vitest";
import {
  cvss,
  formatCompactPresenceDuration,
  formatObservationSource,
  formatPresenceDuration,
  isLocallyAdministeredMac,
  money,
  moneyFull,
  riskBucket,
  severityBucket,
} from "./format";

describe("money", () => {
  it("compacts millions", () => {
    expect(money(3_500_000)).toBe("$3.5M");
    expect(money(2_400_000)).toBe("$2.4M");
  });
  it("compacts thousands", () => {
    expect(money(50_000)).toBe("$50K");
  });
  it("renders — for null/NaN (never NaN)", () => {
    expect(money(null)).toBe("—");
    expect(money(undefined)).toBe("—");
    expect(money(NaN)).toBe("—");
  });
  it("full form uses separators", () => {
    expect(moneyFull(2_400_000)).toBe("$2,400,000");
  });
});

describe("riskBucket thresholds (UIUX.md §2)", () => {
  it("maps score ranges", () => {
    expect(riskBucket(10)).toBe("safe");
    expect(riskBucket(39)).toBe("safe");
    expect(riskBucket(40)).toBe("medium");
    expect(riskBucket(59)).toBe("medium");
    expect(riskBucket(60)).toBe("high");
    expect(riskBucket(79)).toBe("high");
    expect(riskBucket(80)).toBe("critical");
    expect(riskBucket(100)).toBe("critical");
  });
  it("null → safe (never crash)", () => {
    expect(riskBucket(null)).toBe("safe");
    expect(riskBucket(NaN)).toBe("safe");
  });
});

describe("severityBucket", () => {
  it("maps severities case-insensitively", () => {
    expect(severityBucket("Critical")).toBe("critical");
    expect(severityBucket("HIGH")).toBe("high");
    expect(severityBucket("medium")).toBe("medium");
    expect(severityBucket("low")).toBe("safe");
    expect(severityBucket("")).toBe("safe");
  });
});

describe("cvss", () => {
  it("formats one decimal, — on null", () => {
    expect(cvss(8.8)).toBe("8.8");
    expect(cvss(null)).toBe("—");
  });
});

describe("formatPresenceDuration (Phase 4 duration format test)", () => {
  it("formats 0 seconds as < 1 min (newly observed)", () => {
    expect(formatPresenceDuration(0)).toBe("< 1 min (newly observed)");
  });

  it("formats 45 seconds as < 1 min", () => {
    expect(formatPresenceDuration(45)).toBe("< 1 min");
  });

  it("formats 17 minutes as 17 min", () => {
    expect(formatPresenceDuration(17 * 60)).toBe("17 min");
  });

  it("formats 4h 32m exactly", () => {
    expect(formatPresenceDuration(4 * 3600 + 32 * 60)).toBe("4h 32m");
  });

  it("formats 27h (1d 03h) with padded 2-digit hours", () => {
    expect(formatPresenceDuration(27 * 3600)).toBe("1d 03h");
  });

  it("handles null, undefined, NaN, and negative safely as N/A", () => {
    expect(formatPresenceDuration(null)).toBe("N/A");
    expect(formatPresenceDuration(undefined)).toBe("N/A");
    expect(formatPresenceDuration(NaN)).toBe("N/A");
    expect(formatPresenceDuration(-10)).toBe("N/A");
  });
});

describe("formatCompactPresenceDuration", () => {
  it("formats under 60 seconds as < 1 min", () => {
    expect(formatCompactPresenceDuration(0)).toBe("< 1 min");
    expect(formatCompactPresenceDuration(45)).toBe("< 1 min");
  });

  it("formats hours and days cleanly", () => {
    expect(formatCompactPresenceDuration(1020)).toBe("17 min");
    expect(formatCompactPresenceDuration(16320)).toBe("4h 32m");
    expect(formatCompactPresenceDuration(97200)).toBe("1d 03h");
  });

  it("handles null / NaN as N/A", () => {
    expect(formatCompactPresenceDuration(null)).toBe("N/A");
    expect(formatCompactPresenceDuration(NaN)).toBe("N/A");
  });
});

describe("formatObservationSource", () => {
  it("formats known discovery mechanisms to SOC labels", () => {
    expect(formatObservationSource("scapy")).toBe("SCAPY / L2");
    expect(formatObservationSource("arp")).toBe("ARP / OS CACHE");
    expect(formatObservationSource("icmp")).toBe("ICMP");
    expect(formatObservationSource("l3")).toBe("L3 / ROUTED");
  });

  it("handles null, empty, or undefined as SOURCE UNAVAILABLE", () => {
    expect(formatObservationSource(null)).toBe("SOURCE UNAVAILABLE");
    expect(formatObservationSource("")).toBe("SOURCE UNAVAILABLE");
    expect(formatObservationSource(undefined)).toBe("SOURCE UNAVAILABLE");
  });
});

describe("isLocallyAdministeredMac", () => {
  it("identifies locally administered (randomized) MACs via bit 1", () => {
    expect(isLocallyAdministeredMac("da:a1:19:64:12:00")).toBe(true);
    expect(isLocallyAdministeredMac("02:00:00:00:00:01")).toBe(true);
    expect(isLocallyAdministeredMac("f6:42:79:bb:cc:dd")).toBe(true);
  });

  it("identifies globally unique OUIs as not randomized", () => {
    expect(isLocallyAdministeredMac("00:1A:2B:3C:4D:5E")).toBe(false);
    expect(isLocallyAdministeredMac("bc:d0:74:11:22:33")).toBe(false);
  });

  it("respects vendor hints indicating private MAC", () => {
    expect(isLocallyAdministeredMac("00:11:22:33:44:55", "Private MAC")).toBe(true);
  });
});

