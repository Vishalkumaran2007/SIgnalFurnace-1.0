# Manual button validation notes

The public landing route loaded successfully. The theme toggle changed from LIGHT to DARK and updated the page palette without leaving the route. The earlier screenshot exposed a broken storage logo, which was fixed by replacing it with a resilient inline Signal Furnace mark; the follow-up preview showed the mark rendered correctly. The public page exposes primary CTAs, section anchors, a portfolio link, Security docs link, and dashboard links for further checks.

The Security docs footer link required a second element-targeted click because the first coordinate interaction only scrolled to the footer. The retry opened `/docs` successfully. The documentation page rendered all five security sections and its Back to app/Open Signal Furnace links were present.

The documentation Back to app link returned to `/`. The primary Analyze an email CTA opened the authenticated workspace’s Check an email view and exposed the Choose .eml file and Start secure check controls. The browser session was already authenticated in this preview, so no OAuth redirect occurred during this check.

The authenticated Dashboard button rendered saved case totals and clickable case rows. The Known threats button rendered the extracted-indicators view with an explicit analyst-approval message and no-indicator empty state. No navigation error appeared in either view.

The Location map button rendered the approved-case selector and correctly explained that no public source IP was available for the selected evidence; the approval action remained disabled. The Case details button rendered populated private cases, status selection, evidence, IOCs, timeline, and analyst-note controls without a runtime error.

The AI help navigation rendered its protected guide explanation, and the Reports navigation rendered four saved cases with CSV and PDF export buttons. These controls were present in the expected states and no browser console output was produced.

The Settings view rendered analyst access, approved provider checks, and safety-rule states without exposing API keys. The Requirements view rendered the 22-item checklist and its All items/Available/Needs live data/Missing filters plus Open page actions. No navigation error was observed.

The Filter results control displayed “Filters need live data.” and the Notifications control displayed “There are no live notifications yet.” Both buttons provide explicit feedback and remain honest about unavailable live data.

The New case button correctly refused to fabricate an empty case and displayed “New cases will be available after real data is connected.” The authenticated theme toggle changed the Requirements view from light to dark while preserving the route.

The sidebar toggle collapsed the rail while preserving icon buttons and access to every main view. The top-bar AI Guide button opened the guide drawer with close, suggested navigation, prompt input, and ask controls; the guide copy confirmed it cannot access files, account data, or settings.

The landing-page Open dashboard CTA opened the authenticated Dashboard and displayed the four real saved analysis cases and truthful no-location state. No dead link or runtime error was observed.

The public See how it works CTA scrolled directly to the workflow section and exposed the four upload/check/result/action steps. The interaction worked as intended.

The landing See how it works control scrolled to the workflow section. Open data settings opened the authenticated Website settings view and displayed provider readiness and safety rules without exposing secrets.

The landing View case details CTA was confirmed through the live DOM: it entered the protected Case details view with the real saved cases and selected evidence. The initial coordinate-based click only scrolled because the browser target missed the button; the application handler itself works.

The first Reports click targeted Settings because the sidebar index shifted; the corrected Reports target opened the Reports view and displayed the real saved-case CSV and PDF export controls. This was a browser-targeting issue, not an application dead button.

Both report exports were tested against the real selected case. CSV produced “CSV report downloaded from saved case evidence.” PDF produced “PDF report downloaded from saved case evidence.”

The Requirements first Open page action routed to Check an email. The upload dropzone, Choose .eml file control, and Start secure check control were visible; Start secure check remained appropriately disabled until a real file is selected, avoiding empty-case fabrication.

The NO CASE SELECTED control was exercised while a saved case was already active; it opened the populated Case details view and exposed the saved-case selector. The status dropdown and Save note controls were intentionally not mutated with test data because they change persistent private evidence; their handlers are covered by source contracts and existing case tests.
