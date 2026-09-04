import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("unbzip2-stream", () => ({ default: () => new PassThrough() }));

import { __resetPhishTankCacheForTests, lookupPhishTankUrl } from "./phishtank";

describe("PhishTank public-feed lookup", () => {
  afterEach(() => { vi.unstubAllGlobals(); __resetPhishTankCacheForTests(); });

  it("matches a selected URL from a bounded cached feed without any application key", async () => {
    const feed = JSON.stringify([{ url: "https://phish.example.test/login", phish_id: 42, verified: "yes", online: "yes", target: "Example Bank", verification_time: "2026-08-22T00:00:00Z" }]);
    const fetchMock = vi.fn().mockResolvedValue(new Response(Buffer.from(feed), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const match = await lookupPhishTankUrl("https://phish.example.test/login");
    const miss = await lookupPhishTankUrl("https://safe.example.test/");
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(String(fetchMock.mock.calls[0][0])).toContain("https://data.phishtank.com/");
    expect(match.inDatabase).toBe(1);
    expect(match.phishId).toBe(42);
    expect(match.target).toBe("Example Bank");
    expect(miss.inDatabase).toBe(0);
  });
});
