import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("AI guide safety contract", () => {
  it("limits the AI guide to approved screen navigation and explicitly forbids sensitive actions", () => {
    const router = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/routers.ts", "utf8");

    expect(router).toContain("ask: protectedProcedure");
    expect(router).toContain("guideViews");
    expect(router).toContain("navigationRules");
    expect(router).toContain('view: "analyzer"');
    expect(router).toContain("requestedNavigation");
    expect(router).toContain("You cannot inspect emails, cases, files, reports, accounts, or any live data.");
    expect(router).toContain("You cannot upload, download, create, edit, delete, send, block, change settings");
    expect(router).toContain("navigateTo");
    expect(router).toContain("response_format");
  });
});
