import { describe, expect, it } from "vitest";

describe("IP-API Pro credential", () => {
  it.skipIf(!process.env.IPAPI_KEY)("accepts the configured HTTPS key for a lightweight public-IP lookup", async () => {
    const key = process.env.IPAPI_KEY;
    const url = new URL("https://pro.ip-api.com/json/8.8.8.8");
    url.searchParams.set("key", key!);
    url.searchParams.set("fields", "status,query,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,proxy,hosting,mobile");

    const response = await fetch(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(12_000) });
    expect(response.ok).toBe(true);
    const body = (await response.json()) as { status?: string; query?: string; message?: string };
    expect(body.status).toBe("success");
    expect(body.query).toBe("8.8.8.8");
    expect(body.message).toBeUndefined();
  }, 20_000);
});
