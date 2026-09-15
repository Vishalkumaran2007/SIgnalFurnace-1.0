import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

const home = readFileSync(new URL("../client/src/pages/Home.tsx", import.meta.url), "utf8");
const map = readFileSync(new URL("../client/src/components/GeoLocationScreen.tsx", import.meta.url), "utf8");

describe("team links and map presentation", () => {
  it("exposes each supplied portfolio link from the public team section", () => {
    for (const url of [
      "https://srinidhi-ai-gwygmuea.manus.space/",
      "https://suryavijay0107-star.github.io/playful-geometric-studio/#experience",
      "https://sankarfolio-rydjgeka.manus.space/",
      "https://rohinifolio-mmckdlnu.manus.space/",
      "https://sayasree-eee-mk93ir2n.manus.space/?code=3keuGTTM4i7Lav9Cwts4TL",
    ]) {
      expect(home).toContain(url);
    }
    expect(home).toContain('target="_blank" rel="noreferrer"');
  });

  it("keeps the map presentation simple while retaining real-data safeguards", () => {
    expect(map).toContain("Saved approximate locations");
    expect(map).toContain("Approve approximate location");
    expect(map).toContain("Private, loopback, and documentation-only IPs are blocked");
    expect(map).toContain("new maps.Marker");
    expect(map).not.toContain("GeoProviderStatus");
  });
});

// This contract intentionally checks source-level wiring only; provider calls and
// map rendering remain protected by the existing server and MapView tests.
