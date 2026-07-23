# Handoff — desktop tunnel + managed auto-host (2026-07-21)

Read this first, then the design spec:
[`docs/superpowers/specs/2026-07-21-tunnel-autohost-restyle-design.md`](superpowers/specs/2026-07-21-tunnel-autohost-restyle-design.md).
Prior context: [`docs/BOOTSTRAP-DEPLOY.md`](BOOTSTRAP-DEPLOY.md), [`docs/INFRA.md`](INFRA.md),
memory `desktop-client-built.md`. `main` is at the tip of the commits listed below; all pushed.

## What this session shipped (done, tested, committed)

1. **Signed-bootstrap zero-config auto-connect — LIVE in prod & verified.** App pins the registry
   pubkey, fetches `GET /v1/bootstrap` (registry-signed), verifies, connects. No manual endpoints.
2. **Auto-host detection.** "Start serving" probes Ollama :11434 / LM Studio :1234 / llama.cpp :8080
   and auto-wires the upstream. `host::detect_local_openai` + `first_model_id` in
   `apps/lluma-desktop/src-tauri/src/host.rs`; wired in `host_start` (lib.rs).
3. **Restyle to match the website.** Light paper / near-black ink / red (#C41E14) + orange, embedded
   Ioskeley Mono. `apps/lluma-desktop/dist/styles.css`. CSP allows `data:` fonts.
4. **Tunnel foundation (design approved + reviewed).** Auth crypto `tunnel_auth_sign/verify`
   (`TUNNEL_AUTH_DOMAIN=lluma-host-tunnel-v1`) in `crates/lluma-crypto/src/account.rs`; wire frames
   `TunnelFrame` + `MAX_SEALED_LEN` caps in `crates/lluma-core/src/proto.rs`.

## Remaining work (in priority order)

### A. Managed auto-host: provision Ollama + pull a model if none running (USER DIRECTIVE)

When `host::detect_local_openai()` returns `None`, instead of erroring, the app should provision
Ollama and host a model. Spec §Track 2 step 2 has the full requirement. Concretely:

- New submodule (e.g. `apps/lluma-desktop/src-tauri/src/ollama.rs`):
  - `is_installed()` — locate the `ollama` binary (PATH; Windows `%LOCALAPPDATA%\Programs\Ollama`).
  - `install()` — Windows: `winget install Ollama.Ollama` or the official installer download;
    macOS/Linux: the official install script or a bundled binary. **First-run consent prompt.**
  - `ensure_serving()` — probe :11434; if down, spawn `ollama serve`, wait until ready; track the
    child so "Stop serving" can stop it if the app started it.
  - `ensure_model(tag)` — `ollama pull <tag>` (default `qwen2.5:0.5b`) with progress → UI events.
  - Wire upstream to `http://localhost:11434/v1` and continue into the host serve loop.
- Emit Tauri events for install/pull progress; the Contribute tab shows them.
- Tests: `is_installed` path logic; a state-machine unit test. Live path is manual (needs a box
  without Ollama).
- This is largely mechanical process-management → good candidate for GLM 5.2 via opencode, with the
  controller reviewing the subprocess lifecycle + consent UX. (Do NOT let GLM run workspace
  `cargo fmt`.)

### B. Tunnel WebSocket implementation (broker server + host client) + local test

Design + crypto-architect must-haves are in the spec (§Track 1). Build to that exactly. Key files:
- `crates/lluma-broker/Cargo.toml` — add `axum = { features = ["ws"] }`; add `futures-util`/`tokio`.
- `crates/lluma-broker/src/tunnel.rs` (new) — `wss` endpoint `/v1/host/tunnel` on the **ingress**
  router; per-host socket registry (`Arc<Mutex<HashMap<[u8;32], HostSocket>>>` on `BrokerState`);
  auth handshake (Hello→Challenge(32B OsRng, 5s deadline)→Auth(verify `tunnel_auth_verify` with
  broker_key_id = registry pubkey)); job push + `request_id` oneshot correlation; **all bounds from
  the review** (1 socket/account atomic swap w/ generation, in-flight cap → `no_host` BEFORE spend,
  30s timeout, ping 20s, frame length caps, per-IP handshake token-bucket).
- `crates/lluma-broker/src/service.rs` — `resolve_active_host` / exec: add a tunnel arm that routes
  to a live socket (checked BEFORE the spend txn ~L135–176) instead of `POST {ingress_addr}` (~L186).
- `crates/lluma-broker/src/registry.rs` + `store.rs` — a "tunnel mode" host flag (host advertises
  tunnel reachability instead of a public `ingress_addr`).
- `crates/lluma-host/src/tunnel.rs` (new) — outbound WS client: dial `wss://<broker>/v1/host/tunnel`,
  do the auth handshake (`tunnel_auth_sign`), loop receiving `Job` frames → existing serve logic
  (HPKE open → upstream → seal) → `Done`/`Fail`; jittered reconnect.
- **Local loopback test** (mirror the existing serving round-trip): host WS-connects to an in-process
  broker, broker pushes a sealed `Job`, host returns `Done`, client opens it. This is the correctness
  gate before any deploy.
- Then a **crypto-architect impl review** (same gate as bootstrap) BEFORE deploying.

### C. Tunnel deploy (TLS + DNS) — do NOT ship tunnel without TLS

Per the review, plain `ws://` is hijackable after the handshake, so:
- **DNS (ZoneEdit):** add `tunnel.n.lluma.bodegga.net` → broker box `159.65.35.137`.
- **TLS (Caddy on the broker box):** reverse-proxy `tunnel.n.lluma.bodegga.net` (443) → the broker
  ingress WS. (Caddy already fronts the relay on the Vultr box; replicate on DO.)
- **Bootstrap:** extend `BootstrapDoc` with `tunnel_url`; re-sign with `lluma-bootstrap` and
  redeploy the blob (see BOOTSTRAP-DEPLOY.md); host verifies the TLS cert via WebPKI against that
  signed hostname.
- Redeploy broker + host binaries; keep dial-in as fallback. Live-verify a full tunnel exec.

## Access & environment (confirmed this session)

- **doctl** authenticated (DigitalOcean, shake707@gmail.com). Vultr: `VULTR_API_KEY` in
  `~/.lluma-deploy.env`.
- **SSH root** works to both: relay `64.177.112.245` (lluma-relay; Caddy TLS for
  relay.n.lluma.bodegga.net), broker/gateway `159.65.35.137` (lluma-gateway + lluma-broker; repo at
  `/opt/lluma`; **cargo at `/root/.cargo/bin` — `export PATH=$HOME/.cargo/bin:$PATH`**; keys in
  `/etc/lluma/keys`; the Linux **build host**).
- **Pinned registry pubkey** (bake into app): `rMOAQi7L8f8R4bW6tNWm8QN5fYIh3RDXWU1WL6aopPw=`.
- Config backups on both boxes: `/etc/lluma/*.bak.*`; relay binary `lluma-relay.bak.*`.

## Build / verify / gotchas

- Desktop app is its **own workspace** — build from `apps/lluma-desktop/src-tauri` (running `cargo`
  from repo root pulls in `lluma-runtime`/llama.cpp → needs a C toolchain, fails). Default build is
  pure Rust.
- Anchored release: `$env:LLUMA_REGISTRY_PK_B64="rMOAQi7L8f8R4bW6tNWm8QN5fYIh3RDXWU1WL6aopPw="; cargo build --release` in `src-tauri`. `build.rs` fails the build if the key is malformed (M3).
- The app **exe is locked while the app is running** — close the window before `cargo build --release`,
  or build to a separate `CARGO_TARGET_DIR` (this session used `target-anchored/`).
- **WDAC / Application Control** intermittently blocks freshly-built *debug* test exes
  (`os error 4551`) — re-run with `--release` (different binary), which is not blocked.
- Gates before "done": `cargo test` + `cargo clippy --all-targets -- -D warnings`; no
  `unwrap`/`expect` in library crates; privacy invariant preserved; crypto/protocol changes get a
  `protocol-crypto-architect` review before deploy.
- Model split: controller writes security-critical crypto/protocol; GLM 5.2 (`opencode run --model
  opencode-go/glm-5.2`) for small mechanical files only (Kimi noted net-negative). Briefs must
  forbid workspace `cargo fmt` + out-of-crate edits.

## Suggested first prompt for the next session

> Continue the Lluma desktop work per `docs/HANDOFF.md` and the design spec. Do item A (managed
> Ollama auto-host: install/serve/pull a model when none is running) first — it's the user's active
> request — then B (tunnel WebSocket impl + local loopback test + crypto-architect impl review),
> then C (tunnel TLS/DNS deploy + live verify). Use subagents/opencode GLM 5.2 for mechanical parts;
> keep the security-critical code yourself; review before any prod deploy.
