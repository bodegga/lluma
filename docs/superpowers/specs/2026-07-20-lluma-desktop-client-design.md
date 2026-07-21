# Lluma Desktop Client — Design

- **Date:** 2026-07-20
- **Status:** Approved for planning
- **Scope:** A launchable desktop application (Tauri v2) that lets an end user run
  anonymous inference over the live Lluma network (the *client* role), see rich
  network/account/privacy status, and — on a reachable machine — contribute
  compute as a host. One app, one account, one credit balance.

## 1. Goal & non-goals

**Goal.** Ship a thick desktop client that a non-technical user can double-click
and use to chat with an LLM anonymously over the deployed relay, with a status
portal that explains what is happening and why it is private, plus an
honestly-scoped path to contribute compute.

**Non-goals (this spec).**
- NAT-friendly (reverse-connection) hosting. Deferred to its own spec — see §9.
- In-process llama.cpp inference as a *requirement*. It remains an optional,
  feature-gated upstream (§4.2), never on the default build path.
- Token streaming in chat. The current network protocol returns a single sealed
  final chunk; streaming is a future enhancement (§9).

## 2. The product loop

One identity, two roles, one balance:

```
  Contribute compute  ── earns ──▶  credits  ── fund ──▶  acquire blind tokens
        (host role)                                              │
                                                                 ▼
                                              Chat  ── spends ──▶ anonymous inference
                                              (client role)
```

Each served request credits the host exactly 1 credit (`crates/lluma-broker/src/receipts.rs`);
credits are what let an account acquire blind tokens; tokens are spent to chat.
The desktop app surfaces both ends of this loop under a single account.

## 3. Buildability strategy (why this compiles here)

- `lluma-client` (chat) and `lluma-host` (serve) are **both pure Rust** and
  already compile in this workspace. `lluma-host` serves via an `Upstream`
  trait (`EchoUpstream`, `OpenAiUpstream`, and — feature-gated — in-process
  llama.cpp). No C toolchain is needed for either role's default build.
- `lluma-runtime` (llama.cpp, needs a C toolchain) becomes an **optional**
  dependency of `apps/lluma-desktop`, behind a `local-inference` feature that is
  **off by default**. The default build is 100% pure Rust.
- Tauri v2 on Windows uses the installed WebView2; `cargo build -p lluma-desktop`
  produces a runnable `.exe` with no bundler/node step (frontend is static
  `dist/` assets, as today).

## 4. Roles

### 4.1 Client role (always available)

Anonymous inference over the relay via `lluma-client`:

1. Fetch + pin issuer key-config (`key_id == BLAKE3(pubkey)`).
2. Acquire blind tokens (identity-bound at the issuer, but ride the relay so the
   issuer never sees IP). Balance = count of acquired-but-unspent tokens held
   locally (there is no server balance query).
3. Discover a host: `GET /v1/snapshot` over OHTTP, verify against the pinned
   broker **registry pubkey**, pick an `active` host (its `hpke_pk` +
   `host_account`). This replaces hand-fed host params.
4. Seal the prompt E2E to the host (`aad = spend_id`), spend the token via the
   broker, open the sealed final response.

The client makes **only outbound** connections through the relay, so it works
behind any NAT/CGNAT with no setup. Privacy invariant preserved: no party holds
both originator IP and prompt plaintext.

### 4.2 Host role (scoped to reachable machines this spec)

Via `lluma-host` (pure Rust): register with the broker (PoW) → heartbeat to
admission → run the ingress axum service → HPKE-decrypt sealed prompts → forward
to a chosen **Upstream** → seal the response → submit receipts to earn credits.

Upstream is user-selected in Settings:
- **OpenAI-compatible proxy** (default): point at a local Ollama / LM Studio / a
  llama.cpp server, or a remote endpoint. No C toolchain.
- **In-process llama.cpp**: only when built with `--features local-inference`.
- **Echo** (diagnostics only).

**Reachability.** The broker forwards sealed prompts to the host's
`ingress_addr`, so the host must be reachable there (public IP / port-forward).
The app must (a) make this explicit, (b) run a **reachability self-check** before
claiming the host is contributing, and (c) never present hosting as working when
the ingress is unreachable. Desktop-behind-NAT hosting is out of scope here (§9).

## 5. Application architecture

```
apps/lluma-desktop/
  src-tauri/src/
    lib.rs        # Tauri builder, managed state, command registration
    account.rs    # keystore: create/import/unlock, sealed at rest
    client.rs     # thin wrappers over lluma-client (status, acquire, chat)
    host.rs        # host lifecycle (register/heartbeat/serve), feature-aware upstream
    settings.rs   # load/save endpoints + host config; bootstrap fetch
    types.rs      # serde DTOs shared with the frontend
  dist/           # static frontend (index.html, styles.css, main.js) — rebuilt
```

### 5.1 Managed state

`AppState` holds: loaded `Settings`, an optional **unlocked account**
(Ed25519 + HPKE material), a persisted **encrypted unspent-token store**, a
lazily-built `Client`, and an optional running **host handle**. All guarded for
`Send + Sync` access from Tauri commands.

### 5.2 Persistence (Tauri app-data dir)

- `keystore.bin` — account mnemonic sealed with the user passphrase via
  `seal_keystore`/`open_keystore` (Argon2 + ChaCha20-Poly1305).
- `tokens.bin` — unspent blind tokens (bearer credits) encrypted at rest under
  the same unlocked key material.
- `settings.json` — endpoints + host config (non-secret).

### 5.3 Tauri commands (typed, no `unwrap` in the client crate)

| Command | Purpose |
|---|---|
| `network_status()` | relay reachable, key-config epoch/denomination, round-trip latency |
| `account_status()` | has-account, locked/unlocked, `account_id`, balance |
| `create_account(passphrase)` | generate BIP-39 account, persist sealed |
| `import_account(mnemonic, passphrase)` | import + persist sealed |
| `unlock(passphrase)` / `lock()` | open/close the keystore into memory |
| `acquire_tokens(n)` | attempt issuance; surface "not funded yet" cleanly |
| `send_message(prompt)` | key-config (cached) → snapshot host → seal+exec → answer |
| `get_settings()` / `set_settings(..)` | endpoints + host config |
| `fetch_bootstrap()` | pull `{relay, gateway key, registry pk, issuer key_id}` from relay `/v1/bootstrap` when available |
| `host_start()` / `host_stop()` / `host_status()` | host lifecycle + reachability check + earnings |

Long-running work (acquire, exec, host loop) runs off the UI thread; progress and
results are delivered via Tauri events.

## 6. Frontend (rebuild `dist/`)

Four tabs, styled as a polished thick client (dark theme, brand-consistent with
the site):

1. **Chat** — message thread + composer; per-message token spend; when balance
   is 0, the composer is disabled with a clear "fund your account — copy your
   account id" call to action. Single-answer response with a thinking state.
2. **Contribute** — pick upstream, set/validate ingress address, start/stop the
   host, live reachability indicator, credits earned + requests served. Clearly
   labeled "requires a reachable address" with inline guidance.
3. **Status** — network health (green/amber/red + latency + epoch +
   denomination), account fingerprint + balance, host status when contributing,
   and the **privacy explainer** (what each hop sees; the no-IP+plaintext
   invariant).
4. **Settings** — endpoints (relay URL prefilled; gateway key-config + registry
   pubkey via "Fetch from relay" or manual paste), account create/import/unlock,
   host config (upstream kind + ingress address).

## 7. `lluma-client` additions (TDD)

- `snapshot(&self, registry_pk: &AccountPublicKey) -> Result<Vec<HostEntry>>`:
  `GET /v1/snapshot` over OHTTP; verify signature over the full padded 64 KiB
  body against the pinned registry key; return active hosts.
- `exec_with_host(&self, kc, token, host: &HostEntry, prompt)`: exec against a
  snapshot-selected host, so `Client` no longer needs fixed host params at
  construction. The existing `exec` is refactored to delegate.
- All new paths use typed errors; no `unwrap`/`expect` in the library.

## 8. Endpoints & defaults

- **Relay URL** (stable): default `https://relay.n.lluma.bodegga.net`.
- **Gateway OHTTP key-config**: ephemeral on the server (regenerated on gateway
  restart). Not hardcodable. Obtained via `fetch_bootstrap()` when wired, else
  pasted in Settings.
- **Broker registry pubkey** and **issuer key_id**: obtained the same way.
- **Companion task (recommended, separate):** wire the relay's signed
  `/v1/bootstrap` to publish these so the app is zero-config. Until then, the app
  works via manual paste. This is not a blocker for the desktop build.

## 9. Deferred (explicit)

- **NAT-friendly reverse-connection hosting** — host holds an outbound
  connection to the broker/relay; work pushed down it. Protocol change to broker
  + host, crypto-architect review, live redeploy. Own spec.
- **Token streaming** in chat responses.
- **Relay `/v1/bootstrap`** publication (companion infra task, §8).
- **In-process llama.cpp** contribution — buildable only via `local-inference`
  on a C-toolchain box; not exercised in this environment.

## 10. Error handling

- Typed errors end-to-end; commands return `Result<T, String>` with actionable
  messages ("account not funded yet — credits arrive after your host serves, or
  ask your operator", "relay unreachable", "no active hosts in snapshot",
  "ingress not reachable from the internet").
- Fail closed on any snapshot signature / key-config pin mismatch.
- Never claim the host is contributing unless registration + admission +
  reachability all pass.

## 11. Testing & verification

- **Unit/integration (here):** `lluma-client` snapshot verify + host selection
  against a mock OHTTP transport; keystore round-trip; settings load/save;
  balance accounting. `cargo test` + `cargo clippy --all-targets -D warnings`
  green.
- **Build (here):** `cargo build -p lluma-desktop` (default features) succeeds
  and produces the `.exe`.
- **Live (manual):** chat against the live relay requires a current gateway
  key-config, registry pubkey, and a funded account; run as a manual smoke step
  (mirrors `examples/live_smoke.rs`).
- **GUI launch (user):** a headless session can't render the window; the user
  launches the produced `.exe`.

## 12. Build plan (subagents)

- `rust-net-engineer` — `lluma-client` snapshot + `exec_with_host` (TDD).
- `tauri-frontend` — command layer, state, persistence, feature-gating, and the
  four-tab UI.
- `test-writer` — client/keystore/settings coverage.
- `protocol-crypto-architect` — review the snapshot-verify + host-selection path
  and the keystore-at-rest handling before merge.

Controller stays in the loop, verifies each build, and enforces the privacy
invariant and the no-`unwrap` rule.
