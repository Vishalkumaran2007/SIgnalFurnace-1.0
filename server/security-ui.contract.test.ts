import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

const server = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/_core/index.ts", "utf8");
const app = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/App.tsx", "utf8");
const home = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");
const docs = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Documentation.tsx", "utf8");

describe("security and requested UI changes", () => {
  it("declares browser security headers and a bounded API rate guard", () => {
    expect(server).toContain("Strict-Transport-Security");
    expect(server).toContain("Content-Security-Policy");
    expect(server).toContain("X-Frame-Options");
    expect(server).toContain("RATE_LIMIT");
    expect(server).toContain("Too many requests");
  });

  it("registers documentation and the requested Signal Furnace roster", () => {
    expect(app).toContain('path="/docs"');
    expect(docs).toContain("IP location boundaries");
    expect(home).toContain("Signal Furnace");
    expect(home).toContain("Srinidhi H");
    expect(home).toContain("Sayasree T K");
    expect(home).toContain("Sankarprasath S");
    expect(home).not.toContain("Radhi Devi");
  });

  it("keeps critical controls wired to real routes or truthful feedback", () => {
    expect(home).toContain('href="/docs"');
    expect(home).toContain("Analyze an email");
    expect(home).toContain("Filters need live data");
    expect(home).toContain("There are no live notifications yet");
    expect(home).toContain("New case");
    expect(home).toContain("CSV");
    expect(home).toContain("PDF");
    expect(home).toContain("Choose .eml file");
    expect(home).toContain("Start secure check");
  });

  it("keeps protected navigation and AI Guide boundaries explicit", () => {
    expect(home).toContain("Dashboard");
    expect(home).toContain("Known threats");
    expect(home).toContain("Location map");
    expect(home).toContain("Case details");
    expect(home).toContain("Requirements");
    expect(home).toContain("The Guide can explain pages and open approved screens only");
    expect(home).toContain("Sign out");
  });

  it("maps requirement actions to real workspace views", () => {
    expect(home).toContain('title: "IP geolocation and threat map"');
    expect(home).toContain('title: "AbuseIPDB, VirusTotal, and PhishTank"');
    expect(home).toContain('title: "Reports, PDF, and CSV export"');
    expect(home).toContain('title: "Admin panel"');
    expect(home).toContain('action: "geolocation"');
    expect(home).toContain('action: "intelligence"');
    expect(home).toContain('action: "reports"');
    expect(home).toContain('action: "settings"');
    expect(home).toContain('navigate(requirementTarget(item.action))');
  });

  it("wires export, mobile navigation, and sign-out state transitions", () => {
    expect(home).toContain('downloadCaseCsv(detail.data)');
    expect(home).toContain('downloadCasePdf(detail.data)');
    expect(home).toContain('setMobileOpen(false)');
    expect(home).toContain('setActiveView(id)');
    expect(home).toContain('onClick={signOut}');
    expect(home).toContain('toast.success("You have signed out.")');
  });
});
