import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const root = "/home/ubuntu/sih26106-cyber-forensics";

describe("theme system contract", () => {
  it("keeps a persistent switchable paired theme and visible controls", () => {
    const context = readFileSync(`${root}/client/src/contexts/ThemeContext.tsx`, "utf8");
    const app = readFileSync(`${root}/client/src/App.tsx`, "utf8");
    const home = readFileSync(`${root}/client/src/pages/Home.tsx`, "utf8");
    const css = readFileSync(`${root}/client/src/index.css`, "utf8");

    expect(context).toContain('localStorage.setItem("theme", theme)');
    expect(context).toContain('root.classList.add("light-theme")');
    expect(app).toContain('ThemeProvider defaultTheme="dark" switchable');
    expect(home).toContain("function ThemeToggle");
    expect(home).toContain("<ThemeToggle />");
    expect(home).toContain("<ThemeToggle compact />");
    expect(css).toContain("html.light-theme .landing-shell");
    expect(css).toContain("html.light-theme .workspace-shell");
  });
});
