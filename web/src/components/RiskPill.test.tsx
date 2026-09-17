// Drishti v0.1 — risk pill rendering tests | 11-Jul-2026
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RiskPill } from "./RiskPill";

describe("RiskPill (a11y: never color-only)", () => {
  it("renders a text label for each bucket", () => {
    const { rerender } = render(<RiskPill score={85} />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
    rerender(<RiskPill score={65} />);
    expect(screen.getByText("High")).toBeInTheDocument();
    rerender(<RiskPill score={45} />);
    expect(screen.getByText("Medium")).toBeInTheDocument();
    rerender(<RiskPill score={10} />);
    expect(screen.getByText("Low")).toBeInTheDocument();
  });

  it("shows the numeric score when present", () => {
    render(<RiskPill score={87.4} />);
    expect(screen.getByText("87.4")).toBeInTheDocument();
  });

  it("renders label even when score is null", () => {
    render(<RiskPill score={null} />);
    expect(screen.getByText("Low")).toBeInTheDocument();
  });
});
