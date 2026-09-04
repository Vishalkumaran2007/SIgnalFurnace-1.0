import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("SIH26106 requirements checklist contract", () => {
  it("tracks the uploaded specification against the protected workspace", () => {
    const home = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");

    expect(home).toContain("const requirementChecklist");
    expect(home).toContain('id: "requirements"');
    expect(home).toContain("function RequirementsView");
    expect(home).toContain("Email upload (.eml and .msg)");
    expect(home).toContain("Threat heatmap");
    expect(home).toContain("Real-time alerting");
    expect(home).not.toContain('status: "missing"');
    expect(home).not.toContain('status: "waiting"');
    expect(home).toContain('status: "available"');
  });
});
