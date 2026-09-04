import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("email-warning live-data contract", () => {
  it("uses protected saved analyses and keeps the dashboard empty without evidence", () => {
    const home = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");
    const css = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/index.css", "utf8");

    expect(home).not.toContain("const warningBars");
    expect(home).toContain("trpc.analysis.dashboard.useQuery()");
    expect(home).toContain("No example results are shown. Your data stays empty until you upload an .eml email.");
    expect(home).toContain("A score will appear after a real .eml file completes the structural check.");
    expect(css).toContain(".empty-data");
  });
});
