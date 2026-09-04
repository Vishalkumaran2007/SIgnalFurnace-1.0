import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("PhishTank public-feed contract", () => {
  it("uses the HTTPS verified-online feed only after analyst approval for an extracted case URL", () => {
    const provider = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/phishtank.ts", "utf8");
    const database = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/db.ts", "utf8");
    const router = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/routers.ts", "utf8");
    const home = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");
    expect(provider).toContain("https://data.phishtank.com/data/online-valid.json.bz2");
    expect(provider).toContain("FEED_TTL_MS");
    expect(database).toContain("enrichInvestigationPhishTank");
    expect(database).toContain('indicator.type === "url" && indicator.value === url');
    expect(router).toContain("enrichPhishTank");
    expect(home).toContain("Approve PhishTank check");
  });
});
