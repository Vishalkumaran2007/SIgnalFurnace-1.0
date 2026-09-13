import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const root = "/home/ubuntu/sih26106-cyber-forensics";

describe("Signal Furnace visual redesign", () => {
  it("mounts the verified Matrix Junction source through an isolated decorative frame", () => {
    const frame = readFileSync(`${root}/client/src/components/LaserCollectionFrame.tsx`, "utf8");
    const home = readFileSync(`${root}/client/src/pages/Home.tsx`, "utf8");

    expect(existsSync(`${root}/client/src/threeui/shaders/neuform-isolated/sources/matrix-field.html`)).toBe(true);
    expect(frame).toContain("matrix-field.html?raw");
    expect(frame).toContain("Decorative Matrix Junction background");
    expect(home).toContain('variant="matrix-field"');
    expect(home).toContain('className="hero-matrix"');
  });

  it("uses the verified ThreeUI dock controller with accessible real workspace controls", () => {
    const home = readFileSync(`${root}/client/src/pages/Home.tsx`, "utf8");
    const controller = readFileSync(`${root}/client/src/threeui/shaders/animated-top-dock/topDockController.ts`, "utf8");

    expect(home).toContain('from "@/threeui/shaders/animated-top-dock/topDockController"');
    expect(home).toContain("function WorkspaceTopDock");
    expect(home).toContain("createTopDockController");
    expect(home).toContain('aria-label="Workspace sections"');
    expect(home).toContain('data-dock-item');
    expect(home).toContain('workspace-shell--top-dock');
    expect(controller).toContain("prefers-reduced-motion: reduce");
    expect(controller).toContain("onFocusIn");
  });

  it("loads the scoped redesign layer after existing public and workspace styles", () => {
    const main = readFileSync(`${root}/client/src/main.tsx`, "utf8");
    const css = readFileSync(`${root}/client/src/signal-redesign.css`, "utf8");

    expect(main).toContain('import "./signal-redesign.css"');
    expect(css).toContain(".landing-shell .nav-cta");
    expect(css).toContain(".workspace-top-dock");
    expect(css).toContain("html.light-theme .landing-shell");
    expect(css).toContain("@media (max-width: 800px)");
  });
});
