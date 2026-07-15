# Lluma website

The Lluma landing page — a single, self-contained `index.html` (inline CSS + JS,
embedded fonts, no external requests, no build step). The page reads as the
protocol specification itself: numbered sections, ruled tables, the void figure,
and a revision footer. Canonical design spec: [`DESIGN.md`](DESIGN.md)
(`LLUMA-DESIGN-001`), which supersedes all prior visual direction.

## Preview locally

Open `index.html` directly in a browser, or serve it:

```bash
cd apps/lluma-web
python -m http.server 8791   # then visit http://127.0.0.1:8791
```

## Deploy to DigitalOcean

`doctl` is the DigitalOcean CLI (already installed on the dev machine). Two options:

### Option A — App Platform static site (recommended, cheapest)

1. Push this repo to GitHub and set `repo:` in [`.do/app.yaml`](.do/app.yaml).
2. Create the app:
   ```bash
   doctl apps create --spec apps/lluma-web/.do/app.yaml
   ```
3. Subsequent pushes to `main` auto-deploy (`deploy_on_push: true`). To update the
   spec later: `doctl apps update <APP_ID> --spec apps/lluma-web/.do/app.yaml`.

### Option B — Container (Droplet / App Platform via Dockerfile)

```bash
docker build -t lluma-web apps/lluma-web
docker run -p 80:80 lluma-web
```

Or point an existing Droplet's nginx `root` at this folder — it's just static files.

## Notes

- Fully self-contained: zero external requests. The monospace face (Ioskeley Mono,
  400/500/600) is embedded as `woff2` data URIs and the Bodegga egg mark is an inline
  SVG — so it works behind a strict CSP and offline. Never add an external font/asset CDN;
  if the Berkeley Mono web license is confirmed, swap the embedded `woff2`s 1:1 (the stack
  already falls through to `"Berkeley Mono"` and system monos).
- Respects `prefers-reduced-motion` (page fully static, only FIG. 01 animates otherwise);
  responsive down to 360px with internally-scrolling tables; WCAG AA text contrast.
- Copy is deliberately honest about the trust model (Open tier vs Confidential/TEE tier) —
  keep it that way if you edit; do not market the Open tier as "zero-knowledge".
