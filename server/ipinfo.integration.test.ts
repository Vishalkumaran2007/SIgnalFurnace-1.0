import { describe, expect, it } from "vitest";

describe("IPinfo credential", () => {
  it("accepts the configured token for a lightweight public-IP lookup", async () => {
    const token = process.env.IPINFO_TOKEN;
    expect(token).toBeTruthy();

    const response = await fetch(`https://ipinfo.io/8.8.8.8/json?token=${encodeURIComponent(token!)}`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(12_000),
    });

    expect(response.ok).toBe(true);
    const body = (await response.json()) as { ip?: string; city?: string; country?: string; error?: { title?: string } };
    expect(body.error).toBeUndefined();
    expect(body.ip).toBe("8.8.8.8");
    expect(body.country).toBeTruthy();
  }, 20_000);
});
