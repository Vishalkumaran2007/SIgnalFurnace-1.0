import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("external IP eligibility contract", () => {
  it("keeps RFC 5737 documentation ranges out of provider and map approval controls", () => {
    const serverGuard = readFileSync(new URL("./geolocation.ts", import.meta.url), "utf8");
    const workspace = readFileSync(new URL("../client/src/pages/Home.tsx", import.meta.url), "utf8");

    expect(serverGuard).toContain("first === 192 && second === 0 && parts[2] === 2");
    expect(serverGuard).toContain("first === 198 && second === 51 && parts[2] === 100");
    expect(serverGuard).toContain("first === 203 && second === 0 && parts[2] === 113");
    expect(workspace).toContain("function isExternallyEnrichableIpv4");
    expect(workspace).toContain("Source IP is not eligible for lookup");
    expect(workspace).toContain("const sourceIp = isExternallyEnrichableIpv4(extractedSourceIp) ? extractedSourceIp : null;");
  });
});
