import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("MapView lifecycle contract", () => {
  it("guards asynchronous initialization against unmounted containers", () => {
    const mapComponent = readFileSync(new URL("../client/src/components/Map.tsx", import.meta.url), "utf8");

    expect(mapComponent).toContain("let mapScriptPromise: Promise<void> | null = null;");
    expect(mapComponent).toContain("if (mapScriptPromise) return mapScriptPromise;");
    expect(mapComponent).toContain("const container = mapContainer.current;");
    expect(mapComponent).toContain("if (isCancelled() || !container?.isConnected || !maps) return;");
    expect(mapComponent).toContain("let cancelled = false;");
    expect(mapComponent).toContain("cancelled = true;");
    expect(mapComponent).not.toContain('console.error("Map container not found")');
    expect(mapComponent).not.toContain("Failed to initialize Google Maps");
    expect(mapComponent).toContain("setMapError(true)");
    expect(mapComponent).toContain("Map temporarily unavailable");
    expect(mapComponent).toContain("Saved approximate locations remain listed below.");
    expect(mapComponent).not.toContain("visualization");
    expect(mapComponent).not.toContain("HeatmapLayer");
  });

  it("refreshes saved locations without implying live device tracking", () => {
    const workspace = readFileSync(new URL("../client/src/pages/Home.tsx", import.meta.url), "utf8");

    expect(workspace).toContain("refetchInterval: 30_000");
    expect(workspace).toContain("Live refresh checks your saved approved results every 30 seconds.");
    expect(workspace).toContain("It does not track a device or request a new provider lookup.");
    expect(workspace).toContain("locations.refetch()");
    expect(workspace).not.toContain("HeatmapLayer");
    expect(workspace).toContain("Supported marker pins plus bounds fitting remain evidence-backed and accessible.");
  });
});
