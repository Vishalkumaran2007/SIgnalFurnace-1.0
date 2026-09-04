import { describe, expect, it } from "vitest";

describe.runIf(process.env.RUN_LIVE_INTEGRATION_TESTS === "true")("VirusTotal credential", () => {
  it("authorizes a minimal public IP lookup", async () => {
    const key = process.env.VIRUSTOTAL_API_KEY;
    expect(key).toBeTruthy();
    const response = await fetch("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", {
      headers: { "x-apikey": key!, Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
    expect(response.status).not.toBe(401);
    expect(response.status).not.toBe(403);
    expect(response.ok).toBe(true);
    const payload = await response.json() as { data?: { id?: string } };
    expect(payload.data?.id).toBe("8.8.8.8");
  }, 15_000);
});
