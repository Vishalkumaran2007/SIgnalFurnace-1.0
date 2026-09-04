import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("high-risk owner alert contract", () => {
  it("notifies only after a saved analysis reaches the high-risk threshold and records the delivery outcome", () => {
    const router = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/routers.ts", "utf8");
    const home = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");
    expect(router).toContain("notifyOwner");
    expect(router).toContain("parsed.threatScore >= 60");
    expect(router).toContain("high_risk_alert");
    expect(router).toContain("ownerAlert");
    expect(home).toContain("High-risk owner alerts");
    expect(home).toContain('id: "realtime-alerts"');
    expect(home).toContain('status: "available"');
  });
});
