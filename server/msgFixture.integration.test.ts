import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseMsg } from "./emailAnalysis";

const fixturePath = "/home/ubuntu/sih26106-cyber-forensics/.test-fixtures/benign-test.msg";

describe("Outlook MSG fixture integration", () => {
  it.skipIf(!existsSync(fixturePath))("normalizes a benign MSG fixture without executing attachments", async () => {
    const parsed = await parseMsg(readFileSync(fixturePath));

    expect(parsed.subject).toBeTruthy();
    expect(parsed.bodyText.length).toBeGreaterThan(0);
    expect(parsed.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(parsed.attachmentAnalysis.length).toBeGreaterThanOrEqual(1);
  });
});
