# Lluma website

The Lluma marketing / vision landing page. A single, self-contained `index.html`
(inline CSS + JS, no external requests, no build step). Design brief:
[`docs/website-design-brief.md`](../../docs/website-design-brief.md).

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

- Fully self-contained: no CDN, fonts, or remote images, so it works behind a strict CSP
  and offline. The design relies on a distinctive system-font treatment; if you later want
  a custom display face, self-host it (do not add an external font CDN) to keep the CSP tight.
- Respects `prefers-reduced-motion`; responsive to mobile; WCAG AA text contrast.
- Copy is deliberately honest about the trust model (Open tier vs Confidential/TEE tier) —
  keep it that way if you edit; do not market the Open tier as "zero-knowledge".
