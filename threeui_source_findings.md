# ThreeUI source retrieval findings

## Matrix Junction / LaserCollection
The exact registered source bundle at https://threeui.com/source-code/matrix-field.json was reachable. It contains the registered `src/shaders/laser/LaserCollection.tsx` implementation and dependent source files, including the stated SHA-256 metadata. The bundle is source text, not an embedded documentation page.

## Dark Glass / RectangleButtons
The exact registered source bundle at https://threeui.com/source-code/rectangle-buttons.json was reachable. It contains the registered `src/shaders/rectangle-buttons/RectangleButtons.tsx` implementation and dependent source/style metadata, including the stated SHA-256 metadata. The source is large and includes many variants; implementation should preserve only the requested `dark-pill` path unless the complete dependency graph is needed.

## Decision boundary
The remaining `AnimatedTopDock` source bundle and the IPGeolocation provider behavior still need inspection. No source should be approximated if the registered bundle cannot be retrieved. Any supplied provider key must be stored through project secrets, never committed or hardcoded.

## Sable / AnimatedTopDock
The exact registered source bundle at https://threeui.com/source-code/animated-top-dock.json was reachable. It contains the registered `AnimatedTopDock.tsx`, controller, shader, particle-field dependencies, and metadata. It can be evaluated for integration, but it is a sizable WebGL navigation component and must be adapted without replacing the existing accessible navigation semantics.

## IPGeolocation.io
Opening https://app.ipgeolocation.io/ redirected to its login page. The provider advertises IP geolocation and threat intelligence, but no public API contract was verified from the login page alone. The supplied key must not be hardcoded; it requires secure project-secret configuration and a provider endpoint/documentation check before any production integration. Existing approved geolocation flows already use a server-side provider boundary and should not be replaced blindly.
