# Lluma Website v2 — "Spice it up" (redesign brief)

Upgrade the existing Lluma landing page from a clean-but-flat look to a **polished,
product-grade** design with depth, a crafted hero centerpiece, and rich information cards —
inspired by the polish of anythingllm.com, but keeping Lluma's own identity. **Keep the
existing copy and the 9-section flow** (they tested well); this is a *visual* overhaul.

**Base file to edit:** `apps/lluma-web/index.html` (single self-contained page).
**New asset (already created — do not redesign it):** `apps/lluma-web/icon.svg` — the Lluma
mark: host nodes around a dark "anonymous void", one aqua (content) + one amber (identity) on
opposite sides, links dissolving into the void. Use it as favicon, nav glyph, and the seed of
the hero centerpiece.

Deliverable stays: `apps/lluma-web/index.html` self-contained (inline CSS/JS, no external
requests). It MAY reference the sibling `icon.svg` file (served alongside) for the favicon and
`<img>` uses. No CDNs, fonts, or remote images otherwise.

## What "cookie-cutter" means here — fix these specifically
1. Flat sections with no depth → introduce **elevated cards** (subtle fill, 1px border, soft
   shadow, hover glow/lift).
2. A faint background canvas as the only graphic → make a **deliberate hero centerpiece** that
   is the focal point (see "The anonymous void" below), the way anythingllm centers an
   illustration.
3. Plain labels → **pill eyebrows** (mono, small caps, on a faint accent-tinted background).
4. Sparse sections → each concept becomes a **card with information details**: a custom line
   icon, a title, a short description, and a small **mono data line** (a stat, latency, hash,
   or tag) that makes it feel concrete.

## Design tokens (v2)

```
--void:      #06070D   /* near-black base with a blue-black tint (deeper than v1) */
--surface:   #0E1120   /* section backgrounds where used */
--card:      #10142290 /* card fill (semi-translucent over void); pair with border+blur */
--card-2:    #141A2E   /* raised/hover card fill */
--line:      #222A42   /* 1px borders / hairlines */
--ink:       #EDEFF7   /* primary text */
--muted:     #939CB8   /* secondary text (meets AA on --void/--surface — keep it >=this light) */
--signal:    #46E6C4   /* aqua — CONTENT/prompt path + primary accent (buttons, focus, glyph) */
--identity:  #FF9E64   /* amber — IDENTITY/who-you-are; reserve strictly for identity semantics */
```
Depth kit: cards use `background: var(--card); border:1px solid var(--line);
backdrop-filter: blur(6px); border-radius:16px;` with a soft shadow and, on hover, a subtle
`--signal` border/glow + 2–4px lift. A low-opacity radial `--signal` glow sits behind the hero
centerpiece. Keep the two accents **semantic and unblended** (aqua=content, amber=identity).

Type: keep the system stacks from v1 (`--sans` display/body, `--mono` network voice). Push the
scale bolder and more generous (hero `clamp(2.8rem, 6.5vw, 5.8rem)`, section headers ~clamp(2rem,
4vw, 3rem), weight 800, tracking -0.03em). Period-separated headlines are on-brand
("Ask anything. Leave no trace."). Mono for eyebrows, data lines, hashes, latency, peer ids.

## The anonymous void (hero centerpiece — the signature)

Replace v1's faint full-bleed background mesh with a **contained, crafted centerpiece** that is
the hero's focal graphic (roughly 520–640px wide, centered below the headline/CTAs, like
anythingllm's illustration). Build it as inline SVG + a small Canvas/JS layer, or pure SVG+CSS:

- A central **void**: a dark disc with a radial vignette and a faint aqua event-horizon ring
  (reuse the icon's language, larger).
- **Host nodes** arranged around the void — render them as small **rounded "host" chips**
  (not just dots): each a rounded rect with a status dot and a tiny mono label (`host·7f3a`,
  `seed·b91c`, `24ms`, `blake3:9f…`). 5–7 of them.
- **Beaded links** from hosts toward the void that **flow inward and dissolve** before crossing
  (animated dashes/beads traveling toward center, fading to 0 opacity at the rim). This is the
  anonymity: paths enter the void and cannot be traced out the other side.
- The **content host** (aqua) and the **identity host** (amber) sit on opposite sides and are
  **never linked** to each other — visibly separated by the void.
- Motion: gentle bead flow + a periodic beacon ring. Cap DPR, pause when `document.hidden`,
  and honor `prefers-reduced-motion` (static composed scene, no animation).

## Cards, section by section (keep copy; re-skin into cards)

Use a consistent **custom line-icon set** (inline SVG, 1.6–2px stroke, ~22px, currentColor):
give each card an icon that fits (shield, relay/arrows, broker/switch, host/cpu, lock, key,
seed/share, beacon/radar, stars for tiers). Each card: icon → title → description → a mono
data line.

1. **Hero** — pill eyebrow `BODEGGA · ANONYMOUS INFERENCE`; big headline "Ask anything. Leave
   no trace."; subhead; primary "Run a node" + secondary "See how it works ↓"; the anonymous-void
   centerpiece; the mono telemetry ticker (`peers·1,204 · median·31ms · requests·anon`).
2. **Problem** — 2–3 compact cards (e.g. "Tied to your identity", "Logged & profiled",
   "One party sees all"), each icon + line + a mono stat.
3. **Split of knowledge** — the thesis headline ("No single party ever holds both **who you are**
   and **what you asked**", amber+aqua words). Then **three premium cards** Relay / Broker / Host,
   each: icon, "Sees:" (color-coded dot) and "Never sees:" rows, and a mono tag
   (`sees: ip`, `sees: ciphertext`, `sees: prompt`). Keep the honest Open-vs-Confidential caveat
   line beneath.
4. **How it works** — four **numbered step cards** (mono `01`–`04`) in a row/grid, each with the
   step title + description from v1.
5. **Network** — headline "Torrent for intelligence."; keep the tracker/seed/peer SVG diagram but
   restyle it to match (nodes as chips, mono ids); add 2–3 feature cards (content-addressed
   weights, whole-model per host, self-healing + latency beaconing) with mono data lines
   (`blake3`, `1 host / request`, `heartbeat·5s`).
6. **Contribute** — headline "Contribute before you consume."; three tier cards
   (★★★ Host a model, ★★ Seed + relay, ★★ Donate an API key) with icon, description, and a mono
   reward tag (`earns ★★★`). Keep the anti-leech line.
7. **Trust tiers** — two large side-by-side cards: **Open** (any GPU · unlinkable · signed no-log
   software) and **Confidential** (TEE-attested · operator-blind), each with a small feature list
   and a mono tag (`tier: open` / `tier: tee`). Honest — do NOT call Open "zero-knowledge".
8. **CTA** — "Join the mesh." primary "Run a node" + the mono install hint
   (`$ lluma run-node — coming in the app`). Consider a faint repeat of the void motif behind it.
9. **Footer** — name story (Lluma = double-L for LLM, play on Peta**luma**; under **Bodegga**),
   status line (Phase 0 shipped; network in progress), quiet links (GitHub → the repo, Docs).
   Use the icon.svg next to the wordmark.

Nav: slim, translucent over hero → solid on scroll; `icon.svg` + "Lluma" wordmark left; anchor
links + primary "Run a node" right; hamburger on mobile (keep the v1 a11y fix: collapsed menu
links must be removed from the tab order via `visibility:hidden`/`inert`).

Favicon: `<link rel="icon" type="image/svg+xml" href="icon.svg">`.

## Quality floor (unchanged, non-negotiable)
- Fully responsive; cards reflow to 1 column on mobile; nav collapses; wide diagrams scroll in
  their own `overflow-x:auto` container; body never scrolls horizontally at 360/390/768/1440.
- `prefers-reduced-motion` respected (centerpiece static, reveals instant).
- Visible `:focus-visible` outlines; WCAG AA text contrast on the dark base; canvas `aria-hidden`;
  hamburger has aria-label/aria-expanded; semantic landmarks.
- No console errors (favicon 404 won't happen now); no external network requests; clean up rAF on
  visibilitychange; cap DPR.
- Reveal-on-scroll must degrade to visible if JS/observer fails (base `.reveal { opacity:1 }`).

## Out of scope
No frameworks/build tools. Keep it `index.html` + `icon.svg`. Deployment handled separately.
