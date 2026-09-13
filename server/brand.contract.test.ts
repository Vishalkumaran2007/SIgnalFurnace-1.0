import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("Signal Furnace brand mark", () => {
  it("uses the approved Signal Furnace workspace mark rather than the retired brand-mark asset", () => {
    const home = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");

    expect(home).toContain("function SignalMark");
    expect(home).toContain("Signal Furnace intelligence mark");
    expect(home).not.toContain("origin-tracker-logo_395a06a4.png");
    expect(home).not.toContain("signal-furnace-mark_12c018f5.png");
  });
});
