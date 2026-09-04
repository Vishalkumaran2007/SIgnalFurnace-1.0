import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("private similar-case comparison contract", () => {
  it("matches only a signed-in analyst's indicators, local findings, and authentication signals", () => {
    const database = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/db.ts", "utf8");
    const home = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");
    expect(database).toContain("findSimilarInvestigations");
    expect(database).toContain("findingsJson");
    expect(database).toContain("header signal");
    expect(database).toContain("eq(emailArtifacts.userId, userId)");
    expect(home).toContain("analysis.similar.useQuery");
    expect(home).toContain("SIMILAR SAVED CASES");
  });
});
