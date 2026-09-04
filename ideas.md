# SIH26106 Cyber Forensics Command Center — Design Directions

## Three Initial Approaches

### 1. Evidence Ledger
**Very Brief Intro:** A restrained institutional forensics system inspired by archival folders, official chain-of-custody forms, and secure evidence rooms. It builds trust through quiet precision rather than spectacle.

**Probability:** 0.07

### 2. Signal Furnace
**Very Brief Intro:** A high-contrast security operations environment where critical intelligence emerges from an ember-orange data field. It feels alert, technical, and ready for a live investigation.

**Probability:** 0.04

### 3. Cartographic Quiet
**Very Brief Intro:** A light, map-forward intelligence product with ink-like contours and measured red flags. It emphasizes investigative clarity and geographic story-telling.

**Probability:** 0.09

## Chosen Direction — Signal Furnace

### Design Movement
**Technical neo-brutalism meets data-terminal editorial design.** The product frames cyber intelligence as an active operational discipline, mixing crisp information density with a disciplined forensic palette.

### Core Principles
1. **Evidence before decoration:** every visual device must communicate status, provenance, movement, or severity.
2. **Controlled heat:** glowing orange is reserved for priority actions, selected objects, and active risk; it is never a background wash.
3. **Layered intelligence:** black graphite surfaces, faint grids, scanning lines, and translucent cards create a sense of depth without reducing legibility.
4. **Asymmetric command flow:** the interface directs attention from incident context to evidence and response, instead of relying on generic centered blocks.

### Color Philosophy
Near-black graphite gives the workspace the quiet of a command room. **Furnace Orange (#F97316)** acts as the signature evidence signal—energetic but finite—while cyan carries passive telemetry, acid-lime confirms benign states, and restrained crimson marks critical exposure. Fine warm-gray type keeps large technical pages readable without a clinical white-on-black glare.

### Layout Paradigm
An **operations rail + investigation canvas** creates the main structure. The landing page uses a staggered intelligence ribbon and a large, offset dashboard specimen; product views preserve a persistent vertical control rail and distributed evidence panels rather than stacking symmetric cards.

### Signature Elements
1. **Threat beacon:** a concentric radar-like orange node used in the brand mark and active-score components.
2. **Data rails:** fine horizontal and vertical measuring marks which anchor sections, labels, and tables.
3. **Classified tabs:** angular corner notches and clipped panel edges that distinguish selected investigation material.

### Interaction Philosophy
Interactions should feel operational: selected items gain a precise orange edge, controls depress subtly, and information panels expand only when requested. The UI uses toast confirmations to label prototype-only actions honestly, without pretending that external intelligence services are connected.

### Animation
Use 140–220ms `cubic-bezier(0.23, 1, 0.32, 1)` transitions for tabs, controls, and surfaces. The threat beacon may breathe slowly, the global map may pulse low-opacity markers, and section content can enter with 40ms staggered opacity/translate transitions. Motion must respect `prefers-reduced-motion` and must never delay urgent information.

### Typography System
**Space Grotesk** drives hierarchy with bold, compact uppercase headings. **IBM Plex Mono** carries telemetry, labels, timestamps, and evidence strings. **Manrope** supports long-form explanations and readable product copy. Headlines favor large, tight leading; labels stay uppercase, tracked, and deliberately small.

### Brand Essence
**Signal Furnace is an AI-assisted email investigation command center for analysts who need to turn a suspicious message into defensible intelligence quickly.**

**Personality:** exacting, watchful, decisive.

### Brand Voice
Headlines are direct and evidence-led; CTAs use investigator language rather than growth-product language. Microcopy tells analysts what happened, what matters, and what to inspect next.

> “Turn suspicious mail into a documented lead.”

> “Trace the signal. Preserve the evidence.”

### Wordmark & Logo
The wordmark uses a wide, tracked **SIGNAL FURNACE** lockup beside a graphic beacon: three broken orbital arcs surrounding a square evidence core. It has no letterform shortcut and remains recognizable at favicon scale.

### Signature Brand Color
**Furnace Orange — #F97316**

## Style Decisions

The authenticated application now follows the requested **blue terminal Cyber Intelligence OS** specification rather than the public landing palette. Within that boundary, its dashboard uses an asymmetric operations rail and investigation canvas, while classified panel notches, indexed data rails, and selected-case edges preserve the Signal Furnace evidence-first structure. Cyan blue remains the active terminal signal because the later specification explicitly defines it as the product’s primary color.
