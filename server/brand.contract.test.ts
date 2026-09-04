import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("Origin Tracker brand mark", () => {
  it("uses the Origin Tracker logo rather than the retired brand-mark asset", () => {
    const home = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");

    expect(home).toContain("origin-tracker-logo_395a06a4.png");
    expect(home).toContain("Origin Tracker intelligence mark");
    expect(home.match(/origin-tracker-logo_395a06a4\.png/g)).toHaveLength(4);
    expect(home).not.toContain("signal-furnace-mark_12c018f5.png");
  });
});
