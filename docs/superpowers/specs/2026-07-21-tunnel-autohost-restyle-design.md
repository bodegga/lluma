# Tunnel + Auto-host + Restyle — Design

- **Date:** 2026-07-21
- **Status:** Approved for planning (tunnel protocol pending crypto-architect design review)
- **Scope:** Three related improvements to the desktop hosting experience:
  1. **Secure tunnel** — hosts serve without a public IP (NAT-free).
  2. **Auto-host** — "Start serving" brings up the model itself.
  3. **Restyle** — desktop app matches the website's visual identity.

These are independent tracks; each can ship on its own. Build order: Restyle → Auto-host
→ Tunnel (tunnel last: protocol change + review + prod redeploy).

## On the DNS idea (dropped, with rationale)

A DNS record does not hide an IP — it resolves a *name* to an IP, so whoever connects still
learns the address. IP privacy comes from: OHTTP for clients (relay sees IP, never prompt —
already live) and, for hosts, **not accepting inbound connections at all** — which the tunnel
(Track 1) provides. With the tunnel a host exposes no address, port, or DNS record; the broker
sees only the host's outbound source IP (as it already does for register/heartbeat). So a DNS
registry is unnecessary and is not built. Human-friendly host *names* / decentralized naming are
possible future work, unrelated to IP privacy.

## Track 1 — Secure tunnel (reverse WebSocket)

**Problem.** Today the broker dials *into* the host's public `ingress_addr`
(`crates/lluma-broker/src/service.rs`), so hosts behind NAT can't serve.

**Design.** The host holds an **outbound** WebSocket to the broker; the broker pushes exec jobs
down it and reads sealed responses back. No inbound port on the host.

- **Registration:** a "tunnel" mode — the host registers (PoW + Ed25519-signed body as today)
  advertising tunnel reachability instead of a public `ingress_addr`. Broker marks it tunnel-mode.
- **Connect + auth:** host dials `wss://<broker>/v1/host/tunnel`. Broker sends a random 32-byte
  challenge; host returns an Ed25519 signature over a domain-separated challenge with its account
  key; broker verifies against the registered `host_account` and binds the socket to it. One live
  socket per host_account (reconnect replaces).
- **Routing:** on exec, if the resolved host is tunnel-mode with a live socket, the broker frames
  `HostExecRequest{spend_id, sealed}` with a `request_id`, pushes it, and awaits
  `ExecResponse{request_id, ...}` (timeout → `BAD_GATEWAY`); jobs multiplexed by `request_id`.
- **Unchanged:** sealed envelope (aad=spend_id, HPKE to host key), spend-before-forward, receipts.
- **Privacy:** broker still never sees plaintext (sealed to host key); host still never sees the
  client IP (jobs arrive via the broker). The final threat model, framing, auth domain string,
  and DoS bounds are set by the crypto-architect design review and folded in before implementation.

**Components:** `lluma-core` (tunnel frame DTOs + `request_id`), `lluma-broker` (WS endpoint,
per-host socket registry, exec routing switch, timeouts/bounds), `lluma-host` (outbound WS client,
auth handshake, job loop over the existing serving logic), registration mode plumbing.

**Deploy:** broker + host redeploy on the DO box (broker) / wherever hosts run. Crypto-architect
reviews the implementation before deploy, same gate as the bootstrap feature.

## Track 2 — Auto-host on "Start serving"

**Problem.** Contribute demands a pasted OpenAI base URL; "Start serving" errors with none.

**Design.** "Start serving" brings up inference automatically:
1. **Detect** a running local OpenAI-compatible server — Ollama (`http://localhost:11434/v1`) or
   LM Studio (`http://localhost:1234/v1`) — by probing `/v1/models`. If found, use it (zero config).
2. **Managed fallback:** if none found, download + launch a managed llama.cpp server
   (`llama-server`, OpenAI-compatible) + a small GGUF via `lluma-registry`'s content-addressed
   verified download, supervise the subprocess, and wire the upstream to it. No C toolchain in the
   app (the server is a separate prebuilt binary).
3. Then start the host serving loop against that upstream.

The UI shows which upstream was chosen and download/launch progress. Manual base-URL entry stays
as an override. In-process llama.cpp (`lluma-runtime`) remains the feature-gated option for
C-toolchain builds, not the default.

**Components:** desktop `host.rs`/`client.rs` (probe + managed-process manager + upstream wiring),
`lluma-registry` (already does verified GGUF download; add the server-binary fetch), UI copy/state.

## Track 3 — Restyle to match the website

Adopt the site's identity (`apps/lluma-web/lluma.css`):
- **Light theme:** `--paper:#FFFFFF`, `--field:#F1F1ED`, `--ink:#0A0A0A`, `--dim:#5C5C57`,
  `--faint:#8A8A85`; accents `--red:#C41E14`, `--orange:#E8871E`, `--orange-ink:#A85A00`.
- **Type:** "Ioskeley Mono" (embedded base64 woff2 from the site) with the site's mono stack
  fallback; monospace-forward, matching the site.
- Rework `apps/lluma-desktop/dist/styles.css` from dark-indigo to this light/mono/red-orange
  system across all four tabs (nav, cards, dots, buttons, chat bubbles, hop-chain, modal, toast).
- **CSP:** add `font-src 'self' data:` in `tauri.conf.json` so the embedded data: font loads.
- Keep the existing DOM ids/classes so `main.js` is untouched. GLM 5.2 (opencode) drafts the CSS
  to this token spec; controller reviews + wires + fixes the CSP.

## Testing & verification

- **Tunnel:** unit tests for the WS auth handshake (accept genuine / reject wrong-key / replay) and
  request_id correlation; a local loopback test: host WS-connects to an in-process broker, broker
  pushes a sealed job, host returns a sealed response, client opens it (mirrors the existing
  serving round-trip). Crypto-architect review before deploy; live verify after.
- **Auto-host:** unit tests for upstream detection (probe parsing) and the process-manager state;
  a local end-to-end against Ollama if present, else the managed path with a tiny GGUF.
- **Restyle:** static (JS untouched: ids/classes stable), build the app, visual check by the user.
- Global: `cargo test` + `cargo clippy --all-targets -- -D warnings`; no `unwrap`/`expect` in
  library crates; privacy invariant preserved.

## Hard stops / dependencies
- Tunnel deploy needs the broker (DO box) redeploy; verified live after review.
- Auto-host managed download needs a hosted `llama-server` binary + GGUF (via lluma-registry
  catalog); detection path works immediately with Ollama/LM Studio.
- GUI window rendering is the user's launch (headless can't render).
