import { describe, expect, it } from "vitest";
import { isPublicIpv4 } from "./geolocation";

describe("IP geolocation guard", () => {
  it("allows public IPv4 addresses and rejects private, loopback, link-local, and invalid values", () => {
    expect(isPublicIpv4("8.8.8.8")).toBe(true);
    expect(isPublicIpv4("10.1.2.3")).toBe(false);
    expect(isPublicIpv4("127.0.0.1")).toBe(false);
    expect(isPublicIpv4("169.254.1.1")).toBe(false);
    expect(isPublicIpv4("172.16.1.1")).toBe(false);
    expect(isPublicIpv4("192.168.1.1")).toBe(false);
    expect(isPublicIpv4("192.0.2.124")).toBe(false);
    expect(isPublicIpv4("198.51.100.87")).toBe(false);
    expect(isPublicIpv4("203.0.113.45")).toBe(false);
    expect(isPublicIpv4("not-an-ip")).toBe(false);
  });
});
