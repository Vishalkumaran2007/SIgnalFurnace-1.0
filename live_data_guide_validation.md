# Live Data and AI Guide Validation

- The workspace dashboard now uses blank values and explicit no-data states instead of cases, warning totals, locations, alert types, or activity examples.
- The separate AI Guide opens from the top bar and clearly states that it has navigation-only access with no data, file, account, or settings access.
- The guide panel exposes only approved website-navigation prompts and a question input.
- An initial submitted navigation question did not return a visible response in the development-preview session, so the approved navigation action will be retried using the visible guide controls and then checked against the authenticated flow.
- The live guide answered the first request but did not select a navigation action. Direct requests that match an approved screen are now handled by a deterministic allowlist before the language model is consulted, ensuring that only the requested approved screen can be opened.
- After the bounded-navigation update, the refreshed dark workspace retained the clear no-data panels and the separate AI Guide trigger and scope notice.
- The approved email-check prompt correctly populated the AI Guide input for the bounded navigation test.
- The allowlisted request successfully opened the email-check screen and returned a response confirming that the guide can only navigate within the website.
- The no-data dashboard and AI Guide presentation were checked at desktop size in light and dark themes and at a mobile width in light mode; all empty-state copy remained readable after the light-theme contrast correction.
- The desktop known-threats screen was directly checked and contained only a not-connected message with no sample indicators, websites, files, or IP addresses.
- The desktop case-details screen was directly checked and contained only a no-case-data message with no sample evidence, timeline, or case values. Its AI Guide panel repeated the navigation-only boundary and prohibited data, file, account, and settings changes.
- The mobile light-theme AI Guide drawer was inspected in its visible viewport. Its scope notice, approved navigation prompts, and question form all remained readable and accessible within the full-width drawer.
