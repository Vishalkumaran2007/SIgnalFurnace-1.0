import { describe, expect, it } from "vitest";
import { buildCaseCsv } from "../client/src/lib/reportExport";

describe("case CSV export", () => {
  it("includes real case fields and protects spreadsheet formulas in evidence content", () => {
    const csv = buildCaseCsv({ investigation: { caseNumber: "INV-1", title: "Case title", status: "open", severity: "high", threatScore: 72, confidence: 80, summary: "A real summary", createdAt: new Date("2026-08-22T00:00:00Z") }, artifact: { originalFilename: "mail.eml", sha256: "abc", sender: "sender@example.test", recipient: "recipient@example.test", subject: "=unsafe formula", spf: "fail", dkim: "pass", dmarc: "fail", aiCategory: null, aiSummary: null, aiSocialEngineering: null, aiRecommendationsJson: null, aiModel: null }, iocs: [], events: [], notes: [] });
    expect(csv).toContain('"Case number","INV-1"');
    expect(csv).toContain("'=unsafe formula");
  });
});
