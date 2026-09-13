# Origin Tracker

> **SIH26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=0B1020)](https://react.dev/)
[![License](https://img.shields.io/badge/License-MIT-0B7285)](LICENSE)
[![Evidence model](https://img.shields.io/badge/Analysis-Evidence--only-0F766E)](#responsible-analysis-and-data-boundaries)

**Origin Tracker** is a private security-operations workspace for examining authenticated `.eml` evidence. It combines structural email parsing, bounded server-side AI review, analyst-approved intelligence checks, approximate source-IP mapping, timelines, notes, and case exports in one clear workflow. The platform is designed to help analysts decide what to review next; it does **not** send email, execute attachments, or present reputation results that it has not actually retrieved.

**Live workspace:** [Open Origin Tracker](https://sih26106cybe-8m79cqnn.manus.space) · **Repository:** [Vishalkumaran2007/SIH2K26](https://github.com/Vishalkumaran2007/SIH2K26)

---

## The investigation flow

```text
Private .eml evidence
        │
        ▼
RFC 822 parsing + local structural signals
        │
        ├── Headers, authentication results, links, IPs, attachment names
        ├── SHA-256 evidence identity and timeline events
        └── Bounded, evidence-only AI review
        │
        ▼
Private case workspace
        │
        ├── Analyst notes, status, similar-case comparison, CSV/PDF exports
        └── Explicit analyst approval for permitted provider checks
        │
        ▼
Evidence-backed decision support
```

The interface deliberately separates the navigation-only **AI Guide** from case analysis. The guide can explain pages and open approved screens, whereas the case reviewer runs on the server with only the selected email evidence and saves its provenance to the private case timeline.

## What the platform delivers

| Area | Delivered capability | Important boundary |
|---|---|---|
| **Protected evidence ingestion** | Signed-in analysts upload an `.eml` file, which is validated as RFC 822 evidence, stored privately, hashed, and linked to a new case. | `.msg` parsing is intentionally not connected yet. |
| **Email forensics** | Sender/recipient metadata, headers, SPF/DKIM/DMARC result text, reply-to, return-path, received IPs, URLs, email indicators, and attachment names are extracted when structurally present. | Header-like text after the RFC body boundary is treated as body content, not trusted metadata. |
| **Local risk signals** | The platform flags risky URL forms and attachment-name patterns, including raw-IP links, URL shorteners, non-standard ports, executable extensions, archives, macro-enabled files, and double extensions. | Local signals are not malware execution or external reputation claims. |
| **Bounded AI review** | A server-only Gemini structured assessment classifies supplied email evidence, summarizes observed social-engineering cues, and records a bounded recommendation set. | The review does not browse links, execute files, validate DNS, or invent external intelligence. |
| **Threat intelligence** | Analysts may approve distinct AbuseIPDB and VirusTotal public-IP checks, or match one extracted URL against the PhishTank verified-online feed. Provider evidence is saved privately with the case. | The selected indicator—not the email body, attachments, or account data—is the only intended provider input. |
| **Location and map** | An analyst-approved approximate source-IP lookup can be persisted and displayed on a private map with supported marker pins and automatic viewport fitting when more than one location exists. | Private, loopback, link-local, invalid, and RFC 5737 documentation-only IPs are blocked before external lookup; IP results are not exact device tracking. |
| **Forensic workflow** | Private cases include severity, score, confidence, evidence metadata, IOCs, events, notes, status, similar-case signals, CSV, and PDF exports. | Saved cases are scoped to the signed-in analyst. |
| **Operations controls** | OAuth protection, light/dark themes, administrator role controls, a requirements checklist, and a project-owner notification path for completed high-risk cases are included. | The owner alert is non-blocking and activates only when a completed case reaches the configured score threshold. |

## Responsible analysis and data boundaries

Origin Tracker is built around **evidence discipline**. The application only shows records saved from uploaded or connected evidence; it does not seed demonstration cases, reputation responses, ratings, or location records.

> **Analyst approval is required before every external enrichment.** AbuseIPDB and VirusTotal operate only on an extracted, eligible public source IP. PhishTank compares one selected extracted URL with a bounded cached verified-online feed. The email body, attachments, and account details are not sent through these provider paths.

The external-IP guard also rejects documentation-only RFC 5737 ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`. This is important for safe test-email handling: test addresses remain case evidence but cannot accidentally trigger a real map or reputation request.

The AI review is intentionally bounded. It receives only saved email fields, treats content instructions as untrusted, requests strict JSON, applies size limits to persisted fields, and records the model name in the evidence artifact and timeline. If a previous saved case is missing a complete AI result, its owner can re-run that bounded assessment without uploading duplicate evidence.

## Architecture

| Layer | Technology | Responsibility |
|---|---|---|
| **Client** | React 19, TypeScript, Tailwind CSS, TanStack Query, tRPC client | Analyst workspace, responsive light/dark interface, approval controls, maps, and exports. |
| **Server** | Express, tRPC, Zod | Protected procedures, authorization checks, bounded AI calls, case workflow, and provider gates. |
| **Database** | MySQL/TiDB with Drizzle ORM | Users, investigations, artifacts, indicators, events, notes, locations, and provider evidence. |
| **Evidence storage** | Platform S3-style storage | Original `.eml` bytes are kept outside relational records; the database holds metadata and a storage reference. |
| **Identity** | Manus OAuth | Signed-in, per-user workspace and role-aware administrative procedures. |
| **AI and map services** | Server-side built-in LLM proxy and Maps integration | Structured evidence review and private saved-location visualization. |

## Run locally

The production project is configured for the Manus full-stack environment, which injects OAuth, storage, database, and built-in service settings. A local deployment needs equivalent values before the protected flows can work.

```bash
git clone https://github.com/Vishalkumaran2007/SIH2K26.git
cd SIH2K26
pnpm install
pnpm dev
```

Use the following commands during development:

```bash
pnpm test       # deterministic Vitest suite
pnpm check      # TypeScript validation
pnpm build      # production client and server build
pnpm db:push    # generate and apply schema migration in a configured environment
```

| Configuration group | Required for | Examples of keys to configure |
|---|---|---|
| Database and sessions | Cases, users, evidence metadata, and login sessions | `DATABASE_URL`, `JWT_SECRET` |
| OAuth | Protected workspace sign-in | `VITE_APP_ID`, `OAUTH_SERVER_URL`, `VITE_OAUTH_PORTAL_URL` |
| Built-in services | Server-side AI, storage, and notifications | `BUILT_IN_FORGE_API_URL`, `BUILT_IN_FORGE_API_KEY` |
| Provider enrichment | Optional, analyst-approved IP intelligence | `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY` |

Never commit `.env` files, credentials, uploaded email evidence, or provider responses outside the intended private storage and database paths.

## Validation snapshot

The current validation record is maintained in [`functional_mvp_validation.md`](functional_mvp_validation.md). The latest deterministic run completed with **22 passing test files and 27 passing tests**; three opt-in live-provider tests are skipped in the ordinary suite. TypeScript checking and the production build also pass.

Two user-authorized `.eml` files have been processed through the protected browser workflow. One routine project-update email confirmed benign/uncertain low-risk case persistence and the bounded-AI retry repair. A second test email confirmed phishing-oriented AI review, private evidence/timeline storage, URL extraction, PhishTank feed persistence, and blocking of documentation-only IPs. The second file did **not** exercise a high-risk alert or IP-provider/map happy path because its RFC 5737 test addresses are deliberately non-routable and its structural score remained below the alert threshold.

| Verified in the current build | Still requires separately authorized real evidence |
|---|---|
| `.eml` ingestion, private evidence storage, forensic timeline, notes, scoring, bounded AI, provider gates, documentation-IP blocking, PhishTank URL comparison, reports, dashboard, and requirements status | A correctly formatted email with a real public source IP and a score of at least `60` is needed to exercise the geolocation/AbuseIPDB/VirusTotal happy paths and high-risk owner-alert timeline. |

## Repository guide

```text
client/                 React workspace, pages, components, styles, exports
server/                 tRPC procedures, email parsing, case persistence, integrations
drizzle/                Schema and database migrations
functional_mvp_validation.md
                        Evidence-based validation record
integration_sources.md  Official provider references and implementation notes
todo.md                 Transparent implementation and validation tracker
```

## Team

The project carries the **Origin Tracker** identity: a location pin, radar sweep, connected intelligence nodes, and an AI core represent the journey from source to detection, investigation, and intelligence.

**Vishalkumaran V** — engineering, AI, software, and electronics contributor. View the public portfolio at [vishalkumaran2007.github.io/Portfolio](https://vishalkumaran2007.github.io/Portfolio/).

## Provider references

The platform uses provider capabilities only within the approval boundaries described above. Consult the official documentation before modifying an integration or its rate-limit behavior. [1] [2] [3] [4]

[1]: https://docs.abuseipdb.com/#introduction "AbuseIPDB API documentation"
[2]: https://docs.virustotal.com/reference/ip-info "VirusTotal IP object API documentation"
[3]: https://www.phishtank.net/developer_info.php "PhishTank developer information"
[4]: https://ipwhois.io/documentation "IPWHOIS API documentation"

---

<p align="center"><strong>Built for evidence-led email investigations, not synthetic threat claims.</strong></p>
