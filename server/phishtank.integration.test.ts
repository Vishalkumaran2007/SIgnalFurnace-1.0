import { describe, expect, it } from "vitest";
import { lookupPhishTankUrl } from "./phishtank";

describe.runIf(process.env.RUN_LIVE_PHISHTANK_TESTS === "true")("PhishTank public feed", () => {
  it("retrieves the verified-online HTTPS feed and returns a structured result for a benign URL", async () => {
    const result = await lookupPhishTankUrl("https://example.org/");
    expect(result.provider).toBe("PhishTank");
    expect(result.url).toBe("https://example.org/");
    expect(typeof result.inDatabase).toBe("number");
  }, 45_000);
});
