# Lluma Website — Design Brief (build to this exactly)

A single, self-contained marketing/vision landing page for **Lluma** (a **Bodegga** project):
anonymous, contribution-based, peer-to-peer LLM inference. Deep, techy, atmospheric — in the
spirit of a high-craft privacy-tech site — but with an easy, legible top-to-bottom flow.

**Deliverable:** ONE self-contained file `apps/lluma-web/index.html` — inline `<style>` and
inline `<script>`, no external requests (no CDN, no web fonts, no remote images). It must work
opened directly in a browser and be deployable as a static file. All visuals are CSS/SVG/Canvas
drawn in-page. This keeps it CSP-safe and instantly hostable.

## Thesis (the one idea everything serves)

**"No single party ever holds both who you are and what you asked."** The page must make this
visceral, not just stated.

## Design tokens (use these exact values)

Color — "deep signal-space" (NOT pure black; NOT a warm cream):
```
--void:      #0A0D18   /* page base, deep indigo-black */
--surface:   #121728   /* sections / cards */
--surface-2: #1B2238   /* raised cards, insets */
--ink:       #EAECF5   /* primary text */
--muted:     #8C95B2   /* secondary text, captions */
--line:      #262E47   /* hairline dividers, 1px */
--signal:    #46E6C4   /* aqua — the CONTENT/prompt path + the beacon pulse */
--identity:  #FF9E64   /* amber — the IDENTITY/IP path */
```
Rules: `--signal` and `--identity` are semantic — signal = content, identity = who-you-are.
They may appear near each other but must **never blend into one gradient or share one element**;
their separation IS the message. Ambient glow = low-opacity radial of `--signal` only.
Everything not the signature stays quiet: hairlines, generous negative space, restraint.

Type (self-hosted-free; distinctive via treatment, not exotic faces):
```
--sans: "Inter Tight", system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
--mono: ui-monospace, "Cascadia Code", "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
```
- Display headlines: `--sans`, weight 700–800, tight tracking (-0.02 to -0.03em), large
  `clamp()` scale (hero ~clamp(2.6rem, 6vw, 5.5rem)).
- Body: `--sans`, weight 400, ~1.6 line-height, `--muted` for secondary.
- **Mono is the "network voice":** eyebrows/kickers (UPPERCASE, letter-spacing .18em, small),
  data labels, latency values ("24ms"), hashes ("blake3:9f3a…"), peer ids ("peer·7f3a2c"),
  step numbers. Mono appears wherever the network "speaks." Use tabular figures for data.

Motion: purposeful, not scattered. One orchestrated hero moment (the mesh) + restrained
scroll reveals + hover micro-interactions. **Respect `prefers-reduced-motion`** — render a
static constellation and disable pulsing/looping.

## Signature element (the thing the page is remembered by)

**"The Mesh" hero canvas** (HTML5 Canvas, full-bleed behind the hero, `pointer-events:none`):
- 30–60 **anonymous nodes** (small dots) scattered across the viewport, faint `--line` links
  between nearby ones. Nodes have NO labels/IPs (anonymity is the point). Subtle ambient drift.
- A periodic **latency beacon**: every few seconds a pulse ripples outward from a moving origin;
  nodes within the expanding ring briefly light up in `--signal` (nearest = brightest), visualizing
  "probe for the closest fast peer." A tiny mono label near a lit node reads e.g. `24ms`.
- The **split path**: occasionally animate a request traveling origin → relay → broker → host.
  The hop segment carrying **content** glows `--signal`; a separate marker/segment representing
  **identity** glows `--identity`; the two are visibly on different hops and never coincide.
- Reduced-motion: draw the constellation + one static split-path, no animation loop.
- Performance: cap DPR, cancel rAF when tab hidden, keep it lightweight.

A second, quieter signature: the **"Split of knowledge" diagram** (section 3) — three columns
Relay / Broker / Host, each a card listing what it *sees* vs *never sees*, color-coded
(`--identity` for IP/who, `--signal` for prompt/content), making clear no column has both.

## Page flow (top to bottom — keep it easy to follow)

Fixed slim top nav: left = "Lluma" wordmark (the double-L is intrinsic; optionally a tiny
2-dot beacon glyph). Right = anchor links (How it works · Network · Contribute) + a primary
button "Run a node". Nav is translucent over the hero, solidifies (`--surface`) on scroll.

1. **Hero** — the Mesh canvas behind. Mono eyebrow: `BODEGGA · ANONYMOUS INFERENCE`.
   Headline (pick/refine): **"Ask anything. Leave no trace."** Subhead (1–2 lines): anonymous,
   peer-to-peer LLM inference where no one can link your question to you. Two CTAs:
   primary "Run a node", secondary "See how it works ↓". A small mono ticker line underneath
   showing live-feel telemetry, e.g. `peers·1,204   median·31ms   requests·anon`.
2. **The problem** — short, sharp: your AI chats aren't private — prompts are tied to your
   identity, logged, and profiled. 2–3 tight lines + maybe 3 small stat/observation chips.
   Don't fearmonger; state it plainly.
3. **The guarantee / Split of knowledge** — the thesis sentence as a big statement, then the
   three-column Relay/Broker/Host diagram (the quiet signature above). Honest caveat line about
   the Open tier vs the Confidential (TEE) tier — do NOT overclaim "zero-knowledge" for volunteer
   hosts; say the host can't link the prompt to *you*, and a TEE tier adds content-blindness.
4. **How it works** — a real 4-step sequence (numbered in mono, because it IS an ordered process):
   `01` blind-signed token proves you're allowed without revealing who →
   `02` your request goes through a relay (sees your IP, not your prompt) →
   `03` the broker matchmakes to the nearest fast host by latency (sees ciphertext, not you) →
   `04` a peer runs the model and streams the answer back (sees the prompt, never you).
5. **The network (torrent for intelligence)** — peers, seeds, trackers; model *weights* are
   distributed like torrents (BLAKE3-addressed), each request runs whole-model on one host.
   A compact visual of seeds/peers is welcome. One line on self-healing + latency beaconing.
6. **Contribute / earn** — skin in the game, tiered to your device: host a model (★★★),
   seed + relay (★★), or donate an API key (★★). Contribute before you consume; no leeching.
   A small 3-tier card row.
7. **Trust tiers** — Open (any GPU, unlinkable, signed no-log software) vs Confidential (TEE-
   attested, operator-blind) — requester chooses per request. Honest, side-by-side.
8. **Call to action** — "Join the mesh." Primary "Run a node" + a mono install-style line
   (a plausible placeholder command is fine, e.g. a one-line install hint) — but do NOT invent
   a fake download URL; use a neutral placeholder and a "Coming in the app" note.
9. **Footer** — the name story (Lluma: double-L for LLM, a play on Peta**luma**; under the
   **Bodegga** umbrella), a status line (Phase 0 — local host app + runtime shipped; network in
   progress), and quiet links (GitHub placeholder, docs). Small print, hairline top border.

## Copy guidance

Confident, plain, a little bold; sentence case; active voice; specific over clever. The product
name is always "Lluma", umbrella "Bodegga" — capitalized. Buttons say what happens ("Run a node").
Be honest about what's real (see the tier caveat) — the design's credibility depends on not
overclaiming. Write all copy fresh; do not leave lorem ipsum.

## Quality floor (non-negotiable)

- Fully responsive to mobile (hero readable, nav collapses sensibly, diagram stacks).
- Visible keyboard focus states; sufficient color contrast on `--void`.
- `prefers-reduced-motion` respected (mesh static, reveals instant).
- Body must never scroll horizontally; wide diagrams scroll inside their own container.
- No console errors; canvas cleaned up on visibility change.
- Semantic HTML (header/nav/main/section/footer), meaningful alt/aria where relevant.

## Out of scope
No build tooling, no frameworks, no external assets. One file. Deployment config is handled
separately by the controller.
