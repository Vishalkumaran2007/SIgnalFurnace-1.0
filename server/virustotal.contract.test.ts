import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("VirusTotal case evidence contract", () => {
  it("keeps the provider server-side, analyst-approved, and separate from the pending PhishTank integration", () => {
    const router = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/routers.ts", "utf8");
    const database = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/db.ts", "utf8");
    const home = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");
    expect(router).toContain("enrichVirusTotal");
    expect(database).toContain("enrichInvestigationVirusTotal");
    expect(database).toContain("virustotal_reputation");
    expect(home).toContain('provider="VirusTotal"');
    expect(home).toContain("Approve ${provider} check");
    expect(home).toContain("PhishTank remains unconnected");
  });
});
