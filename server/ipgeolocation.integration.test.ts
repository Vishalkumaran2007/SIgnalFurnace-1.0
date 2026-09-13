import { describe, expect, it } from "vitest";

describe("IPGeolocation.io credential", () => {
  it.skipIf(process.env.RUN_LIVE_PROVIDER_TESTS !== "true" || !process.env.IPGEOLOCATION_API_KEY)("accepts the configured key for a lightweight public-IP lookup", async () => {
    const key = process.env.IPGEOLOCATION_API_KEY;
    expect(key).toBeTruthy();
    const url = new URL("https://api.ipgeolocation.io/ipgeo");
    url.searchParams.set("apiKey", key!);
    url.searchParams.set("ip", "8.8.8.8");
    url.searchParams.set("fields", "geo");
    const response = await fetch(url);
    expect(response.ok).toBe(true);
    const body = await response.json() as { ip?: string; country_name?: string; latitude?: string; longitude?: string; message?: string };
    expect(body.ip).toBe("8.8.8.8");
    expect(body.message).toBeUndefined();
    expect(body.country_name).toBeTruthy();
    expect(body.latitude).toBeTruthy();
    expect(body.longitude).toBeTruthy();
  }, 20_000);
});
