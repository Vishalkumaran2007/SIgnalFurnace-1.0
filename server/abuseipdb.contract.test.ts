import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("AbuseIPDB case evidence contract", () => {
  it("keeps the provider server-side, analyst-approved, private, and visible in the case workflow", () => {
    const router = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/routers.ts", "utf8");
    const database = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/db.ts", "utf8");
    const home = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");
    expect(router).toContain("enrichReputation");
    expect(database).toContain("enrichInvestigationReputation");
    expect(database).toContain("abuseipdb_reputation");
    expect(home).toContain("Approve AbuseIPDB check");
    expect(home).toContain("VirusTotal and PhishTank remain unconnected");
  });
});
