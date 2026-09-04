import { afterEach, describe, expect, it, vi } from "vitest";
import { lookupAbuseIpdb } from "./threatIntel";

describe("AbuseIPDB reputation lookup", () => {
  const originalKey = process.env.ABUSEIPDB_API_KEY;
  afterEach(() => { vi.unstubAllGlobals(); process.env.ABUSEIPDB_API_KEY = originalKey; });

  it("sends only a public IP and normalizes documented provider evidence", async () => {
    process.env.ABUSEIPDB_API_KEY = "test-key";
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ data: { ipAddress: "8.8.8.8", abuseConfidenceScore: 42, totalReports: 9, numDistinctUsers: 4, lastReportedAt: "2026-08-22T00:00:00Z", countryCode: "US", usageType: "Data Center/Web Hosting/Transit", isp: "Example ISP", domain: "example.test", isWhitelisted: false } }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await lookupAbuseIpdb("8.8.8.8");
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(String(fetchMock.mock.calls[0][0])).toContain("ipAddress=8.8.8.8");
    expect(result.abuseConfidenceScore).toBe(42);
    expect(result.totalReports).toBe(9);
    expect(result.countryCode).toBe("US");
    expect(result.rawJson).toContain("Example ISP");
  });

  it("does not send private source addresses to the provider", async () => {
    process.env.ABUSEIPDB_API_KEY = "test-key";
    await expect(lookupAbuseIpdb("192.168.1.1")).rejects.toThrow("public IPv4");
  });
});
