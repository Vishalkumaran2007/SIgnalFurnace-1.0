import { afterEach, describe, expect, it, vi } from "vitest";
import { lookupVirusTotalIp } from "./virustotal";

describe("VirusTotal IP lookup", () => {
  const originalKey = process.env.VIRUSTOTAL_API_KEY;
  afterEach(() => { vi.unstubAllGlobals(); process.env.VIRUSTOTAL_API_KEY = originalKey; });

  it("sends only a public source IP and keeps a concise provider evidence snapshot", async () => {
    process.env.VIRUSTOTAL_API_KEY = "test-key";
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ data: { id: "8.8.8.8", attributes: { last_analysis_stats: { malicious: 3, suspicious: 2, harmless: 18, undetected: 70 }, reputation: -12, country: "US", asn: 15169, as_owner: "Example Network", network: "8.8.8.0/24", last_analysis_date: 1_700_000_000 } } }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await lookupVirusTotalIp("8.8.8.8");
    expect(String(fetchMock.mock.calls[0][0])).toContain("ip_addresses/8.8.8.8");
    expect(result.malicious).toBe(3);
    expect(result.suspicious).toBe(2);
    expect(result.asn).toBe(15169);
    expect(result.countryCode).toBe("US");
    expect(result.rawJson).toContain("Example Network");
  });

  it("rejects private source addresses before any provider request", async () => {
    process.env.VIRUSTOTAL_API_KEY = "test-key";
    await expect(lookupVirusTotalIp("10.1.1.1")).rejects.toThrow("public IPv4");
  });
});
