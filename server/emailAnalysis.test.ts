import { describe, expect, it } from "vitest";
import { applyAiContentAssessment, isLikelyEml, parseEml } from "./emailAnalysis";

describe(".eml analysis", () => {
  it("extracts real headers, links, indicators, and structural authentication warnings", async () => {
    const raw = [
      "From: billing@example.test",
      "To: analyst@company.test",
      "Reply-To: verify@other.test",
      "Subject: Account review",
      "Message-ID: <case-1@example.test>",
      "Authentication-Results: mx.example.test; spf=fail; dkim=pass; dmarc=fail",
      "Received: from 203.0.113.9 by mx.example.test",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Open https://secure-example.test/login to review your account.",
    ].join("\r\n");

    const result = await parseEml(Buffer.from(raw));

    expect(result.subject).toBe("Account review");
    expect(result.spf).toBe("fail");
    expect(result.dkim).toBe("pass");
    expect(result.dmarc).toBe("fail");
    expect(result.urls).toContain("https://secure-example.test/login");
    expect(result.originatingIp).toBe("203.0.113.9");
    expect(result.threatScore).toBeGreaterThan(50);
    expect(result.indicators.some((indicator) => indicator.type === "domain" && indicator.value === "secure-example.test")).toBe(true);
  });

  it("rejects a renamed non-email payload before it can be stored as evidence", () => {
    expect(isLikelyEml(Buffer.from("not an RFC822 message"))).toBe(false);
    expect(isLikelyEml(Buffer.from("From: analyst@example.test\r\nTo: soc@example.test\r\n\r\nHello"))).toBe(true);
  });

  it("adds a bounded AI review without reducing a stronger structural score", async () => {
    const email = await parseEml(Buffer.from("From: security@example.test\r\nTo: analyst@example.test\r\n\r\nReview https://example.test"));
    email.threatScore = 70;
    applyAiContentAssessment(email, { category: "phishing", riskScore: 20, confidence: 88, summary: "The message asks the recipient to follow a link.", socialEngineering: "Urgency is implied.", recommendations: ["Verify the request using a trusted channel."], model: "gpt-5-mini" });
    expect(email.threatScore).toBe(70);
    expect(email.ai?.category).toBe("phishing");
    expect(email.reasons).toContain("AI content review: phishing");
  });

  it("records local URL and attachment risk signals without claiming live reputation", async () => {
    const raw = [
      "From: sender@example.test",
      "To: analyst@example.test",
      "Subject: Review attached",
      "MIME-Version: 1.0",
      "Content-Type: multipart/mixed; boundary=boundary",
      "",
      "--boundary",
      "Content-Type: text/plain",
      "",
      "Open http://203.0.113.8:8080/login before the deadline.",
      "--boundary",
      "Content-Type: application/octet-stream; name=invoice.pdf.exe",
      "Content-Disposition: attachment; filename=invoice.pdf.exe",
      "Content-Transfer-Encoding: base64",
      "",
      "AA==",
      "--boundary--",
    ].join("\r\n");
    const result = await parseEml(Buffer.from(raw));
    expect(result.findings.some((finding) => finding.kind === "url" && finding.severity === "high")).toBe(true);
    expect(result.findings.some((finding) => finding.kind === "attachment" && finding.detail.includes("double extension"))).toBe(true);
    expect(result.summary).toContain("External reputation");
  });
});
