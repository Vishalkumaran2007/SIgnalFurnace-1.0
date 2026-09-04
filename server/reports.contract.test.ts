import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("real report workflow contract", () => {
  it("keeps CSV and PDF exports tied to saved case evidence", () => {
    const home = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");
    const exporter = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/lib/reportExport.ts", "utf8");
    expect(home).toContain('id: "reports"');
    expect(home).toContain('status: "available"');
    expect(home).toContain("downloadCaseCsv");
    expect(home).toContain("downloadCasePdf");
    expect(exporter).toContain("buildCaseCsv");
    expect(exporter).toContain("doc.save");
  });
});
