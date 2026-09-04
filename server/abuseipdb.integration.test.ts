import { describe, expect, it } from "vitest";

describe.runIf(process.env.RUN_LIVE_INTEGRATION_TESTS === "true")("AbuseIPDB credential", () => {
  it("authorizes a minimal documented IP check", async () => {
    const key = process.env.ABUSEIPDB_API_KEY;
    expect(key).toBeTruthy();
    const response = await fetch("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=30", {
      headers: { Key: key!, Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
    expect(response.status).not.toBe(401);
    expect(response.status).not.toBe(403);
    expect(response.ok).toBe(true);
    const payload = await response.json() as { data?: { ipAddress?: string } };
    expect(payload.data?.ipAddress).toBe("8.8.8.8");
  }, 15_000);
});
