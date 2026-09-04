import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("Material You workspace contract", () => {
  it("scopes the redesign to authenticated workspace views while preserving paired theme hooks", () => {
    const workspaceCss = readFileSync(new URL("../client/src/material-workspace.css", import.meta.url), "utf8");
    const home = readFileSync(new URL("../client/src/pages/Home.tsx", import.meta.url), "utf8");

    expect(workspaceCss).toContain("Material You workspace layer");
    expect(workspaceCss).toContain(".workspace-shell");
    expect(workspaceCss).toContain(".dark .workspace-shell");
    expect(workspaceCss).toContain("@media (max-width: 800px)");
    expect(workspaceCss).not.toContain(".landing-shell");
    expect(home).toContain("Origin Tracker");
    expect(home).toContain("function Workspace");
  });
});
