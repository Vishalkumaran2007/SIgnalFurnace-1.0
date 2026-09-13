import { describe, expect, it } from "vitest";
import { getSessionCookieOptions } from "./_core/cookies";

describe("session cookie security contract", () => {
  it("uses HttpOnly, host-rooted, cross-site OAuth-safe cookies", () => {
    const options = getSessionCookieOptions({
      protocol: "https",
      headers: {},
    } as never);

    expect(options.httpOnly).toBe(true);
    expect(options.path).toBe("/");
    expect(options.sameSite).toBe("none");
    expect(options.secure).toBe(true);
  });

  it("recognizes forwarded HTTPS at the hosted proxy boundary", () => {
    const options = getSessionCookieOptions({
      protocol: "http",
      headers: { "x-forwarded-proto": "https, http" },
    } as never);

    expect(options.secure).toBe(true);
  });

  it("does not mark local HTTP development cookies Secure", () => {
    const options = getSessionCookieOptions({
      protocol: "http",
      headers: {},
    } as never);

    expect(options.secure).toBe(false);
  });
});
