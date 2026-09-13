import { describe, expect, it } from "vitest";
import {
  nextMobileOpenState,
  reportSuccessMessage,
  requirementTarget,
  signedOutMode,
} from "../client/src/lib/workspaceActions";

describe("workspace action behavior", () => {
  it("routes requirement actions to their requested view and falls back to settings", () => {
    expect(requirementTarget("reports")).toBe("reports");
    expect(requirementTarget("geolocation")).toBe("geolocation");
    expect(requirementTarget()).toBe("settings");
  });

  it("returns truthful report download feedback for both formats", () => {
    expect(reportSuccessMessage("csv")).toBe("CSV report downloaded from saved case evidence.");
    expect(reportSuccessMessage("pdf")).toBe("PDF report downloaded from saved case evidence.");
  });

  it("returns the public landing state after sign-out", () => {
    expect(signedOutMode()).toBe("landing");
  });

  it("toggles mobile navigation state predictably", () => {
    expect(nextMobileOpenState(false)).toBe(true);
    expect(nextMobileOpenState(true)).toBe(false);
  });
});
