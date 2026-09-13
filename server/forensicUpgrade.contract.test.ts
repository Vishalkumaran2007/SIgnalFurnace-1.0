import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { analyzeAttachments, withVirusTotalAttachmentResult } from "./attachmentAnalysis";

describe("forensic upgrade contracts", () => {
  it("marks dangerous, double-extension, and MIME-mismatch attachment metadata without executing content", () => {
    const [dangerous, mismatch] = analyzeAttachments([
      { filename: "invoice.pdf.exe", contentType: "application/octet-stream", content: Buffer.from("safe fixture"), size: 12 },
      { filename: "statement.pdf", contentType: "image/png", content: Buffer.from("fixture") },
    ]);
    expect(dangerous.isDangerous).toBe(true);
    expect(dangerous.isDoubleExtension).toBe(true);
    expect(dangerous.attachmentVerdict).toBe("HIGH_RISK");
    expect(mismatch.isMimeMismatch).toBe(true);
    expect(withVirusTotalAttachmentResult(mismatch, { malicious: 2, suspicious: 0, harmless: 50, undetected: 10 }).vtVerdict).toBe("MALICIOUS");
  });

  it("keeps requirements assistant scope and private history controls in the protected router", () => {
    const source = readFileSync(new URL("./routers.ts", import.meta.url), "utf8");
    expect(source).toContain("requirementsScope");
    expect(source).toContain("listAssistantChatHistory(ctx.user.id)");
    expect(source).toContain("saveAssistantChatMessage(ctx.user.id");
    expect(source).toContain("Do not answer general knowledge questions");
    expect(source).toContain("You cannot inspect emails, cases, files, reports, accounts, or any live data.");
  });

  it("uses encrypted configured location sources and never references the free IP-API HTTP endpoint", () => {
    const source = readFileSync(new URL("./geolocation.ts", import.meta.url), "utf8");
    expect(source).toContain("https://ipinfo.io");
    expect(source).toContain("https://api.ipgeolocation.io");
    expect(source).not.toContain("http://ip-api.com");
    expect(source).toContain("Only a public IPv4 source address can be enriched");
  });

  it("keeps progressive investigation controls and visible location provenance in the authenticated workspace", () => {
    const workbench = readFileSync(new URL("../client/src/components/InvestigationWorkbench.tsx", import.meta.url), "utf8");
    const mapScreen = readFileSync(new URL("../client/src/components/GeoLocationScreen.tsx", import.meta.url), "utf8");
    const status = readFileSync(new URL("../client/src/components/GeoProviderStatus.tsx", import.meta.url), "utf8");
    expect(workbench).toContain("CaseProgressFooter");
    expect(workbench).toContain("workbench-timeline");
    expect(workbench).toContain("Evidence graph");
    expect(workbench).toContain("Search private cases");
    expect(workbench).toContain("CASE ACTIONS");
    expect(mapScreen).toContain("IP-API free HTTP is disabled");
    expect(status).toContain("cached results may be reused for 24 hours");
    expect(status).toContain("Approximate network location");
  });
});
