# LLUMA — Website Design
Applies to: lluma-web · Supersedes all prior visual direction.

## Concept
The website presents a public protocol overview using the visual language of an
engineering document: numbered sections, ruled tables, captioned figures, and a
revision footer. It is not the canonical protocol specification.
References: usgraphics.com (document apparatus), owickstrom.github.io/the-monospace-web
(typographic discipline), oxide.computer (dark restraint + usability).
The tech speaks. Nothing decorates.

## Hard rules (never break)
1. ONE typeface family, self-hosted, monospace: "Ioskeley Mono" 400/500/600
   (OFL Iosevka build matched to Berkeley Mono; embedded or same-origin — never
   a CDN). Stack: "Ioskeley Mono","Berkeley Mono",system monos — so licensed
   desktop installs of the real face take over automatically. Hierarchy comes
   from weight, size, case, and tracking — never from a second family.
   Register: cold, corporate, engineering-document. If the Berkeley Mono web
   license is confirmed, the real woff2s replace Ioskeley 1:1, same weights.
   Banned registers: pixel/retro-game fonts, handwriting, anything playful.
2. `border-radius: 0` everywhere. No blurred shadows and no gradients, ever.
   The ONLY shadow allowed is the hard offset ink shadow (`box-shadow: Npx Npx 0
   var(--ink)`, no blur) on buttons and figures — the USGC pressed-plate look.
   Hover = translate(1px,1px) + shadow shrinks by 1px.
3. Rules are 1px solid var(--ink). Section separators are 1px DASHED ink.
   Masthead and footer close with 2px solid ink. No gray hairlines on paper.
4. Two accents: red (primary/links/content-host) and orange (identity-host/
   caution). Orange text on paper only as --orange-ink; bright orange is for
   fills, strokes, and swatches. Orange appears ONLY in figures, the trust
   table, and the calibration bar.
5. No component-library idioms: no cards with padding-and-radius, no pill buttons,
   no icon grids, no emoji. Data lives in ruled tables. Actions look like commands.
6. Exactly one illustration concept: the void figure (hosts wired into an
   untraceable core). Everything else is tables, section registers, and type.
7. All measurements in `ch` and `rem`. Max content width: 104ch. Layout snaps to
   the character grid wherever the browser allows.
8. Section headers are registers: `§ NN — TITLE`, with a hairline above and below.
   Numbering is real document structure. Internal document IDs do not appear in
   public-facing copy.
9. Copy is honest and specific. The Open tier is NEVER called "zero-knowledge."
   Say what each party sees (`sees: ciphertext`). Plain verbs. Sentence case in
   prose; uppercase + tracking reserved for labels and registers.
10. Quality floor, unannounced: no horizontal overflow 360–1440 (tables get
    `overflow-x:auto` wrappers), WCAG AA contrast, `:focus-visible` outlines,
    `prefers-reduced-motion` = fully static, zero external requests (fonts
    included — system mono stack only unless Berkeley Mono is self-hosted).

## Tokens (paper theme — USGC register)
--paper:      #FFFFFF   page background
--field:      #F1F1ED   table-header fills, swatch
--ink:        #0A0A0A   text, ALL rules and borders (no gray hairlines)
--dim:        #5C5C57   secondary text, captions
--faint:      #8A8A85   disabled, stipple dots
--red:        #C41E14   primary accent: links, §-numbers, content host, primary button fill
--orange:     #E8871E   identity host, caution — FILLS AND STROKES ONLY
--orange-ink: #A85A00   the only orange permitted as text on paper (AA contrast)

Type scale (Ioskeley Mono, single family):
--t-display: 500, clamp(1.9rem, 5vw, 3.1rem) / 1.14, tracking -0.015em
--t-section: 600, 0.95rem, uppercase, tracking 0.14em
--t-body:    400, 0.92rem / 1.65
--t-data:    400, 0.82rem / 1.6   (tables)
--t-micro:   500, 0.7rem, uppercase, tracking 0.12em  (registers, captions)

## Apparatus (what makes it USGC, not generic brutalism)
- Calibration bar in the masthead: flat swatch row ink/red/orange + gray ramp.
  Decorative-but-canonical; hidden under 560px.
- Inverted chips: solid ink (or red) boxes with paper text — `REV 2`, `FIG. 01`,
  tier names. Never outlined pills; always solid fills, zero radius.
- Stipple shading: `radial-gradient(var(--faint) 0.8px, transparent 0.9px)` on a
  6px grid, used as the field behind figures (halftone paper texture). Never on
  text containers.
- Masthead: wordmark left; calibration bar; document-section navigation right.
- Figures: captioned `FIG. NN — TITLE`, registration marks (+) at corners,
  hairline frame, labels set in --t-data.
- Footer: one public revision marker plus the colophon line
  (`zero external requests · no analytics · view source`).
- Optional debug: `?grid` query param overlays the character grid.

## Motion policy
At most two animations sitewide, both in FIG. 01: beads drifting from hosts into
the void (dissolve before center), and a slow beacon pulse on the void ring.
Duration ≥ 6s, opacity ≤ 0.9, removed entirely under prefers-reduced-motion.
Nothing animates on scroll. Hover states change color/underline only.

## Writing register
Labels: `SEES`, `TIER`, `EARNS` — uppercase micro. Prose: short declarative
sentences, first-person plural avoided, no marketing adjectives ("blazing,"
"seamless" banned). Claims must be verifiable from the protocol. Buttons name
the action: `Read the protocol`, `Run a host`.

## Self-critique checklist before shipping any page
[ ] Could any block be mistaken for a SaaS template? Kill it.
[ ] Is amber anywhere outside figures/trust table? Remove it.
[ ] Does every rule/number encode real structure? If decorative, remove.
[ ] Screenshot at 360 / 768 / 1440. No overflow, tables scroll internally.
[ ] Reduced-motion pass: page fully static, figure still legible.
