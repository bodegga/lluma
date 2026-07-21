# Lluma

> Anonymous, contribution-based, peer-to-peer LLM inference. A **Bodegga** project.
> *Lluma* — a double-**L** nod to **LL**M and a play on Peta**luma**.

Lluma lets anyone get **anonymous LLM inference** — where no single participant can tie
*who you are* to *what you asked* — with compute supplied by a **contribution-based,
torrent-style peer-to-peer fabric** of volunteer hosts plus donated commercial API keys.

See the full design in [`docs/superpowers/specs/2026-07-14-lluma-design.md`](docs/superpowers/specs/2026-07-14-lluma-design.md).

## Core principle

**No single participant ever holds both "who you are" and "what you asked."**
Identity and content are split across a relay, a broker, and a serving host; blind-signed
tokens make request entitlement unlinkable to identity.

## Status

**Phase 1 (MVP) — the anonymous-inference network is built and tested.** One anonymous
request flows `client → relay → gateway → {issuer, broker} → host → model → back`, with the
privacy invariant asserted at every hop. Complete and green:

- **Crypto** — RFC 9474 RSA blind-signature tokens, RFC 9180 HPKE end-to-end sealing, OHTTP
  relaying, Ed25519 accounts + BIP-39/Argon2 keystore, anti-Sybil BLAKE3 proof-of-work.
- **Transport** — `lluma-net`/`lluma-relay`/`lluma-gateway` (OHTTP; the relay is the only
  party that sees client IPs, and only as ciphertext).
- **Broker (#4)** — durable redb accounting, host registry (PoW register + slow admission +
  replay-proof heartbeats + SSRF-hard ingress), signed fixed-size registry snapshots, usage
  receipts (atomic 1-credit), a `redeemed ≤ issued` tripwire, and anti-Sybil trial grants.
- **Serving (#5)** — an API-donor host with a generic OpenAI-compatible upstream adapter.

**213 tests pass across 9 crates; `clippy -D warnings` clean.** Every crypto/protocol change was
designed and reviewed adversarially (see *Development methodology*). Real local GGUF inference
(`lluma-runtime` + the Tauri desktop app) needs a C toolchain and is the next build target.

## Roadmap

- **Phase 0 — Dogfood:** local host app + GGUF runtime + local chat. ✅
- **Phase 1 — MVP:** relay + broker + blind-token issuer + credits → anonymous inference. ✅
- **Phase 2 — Torrent layer:** P2P content-addressed weight distribution.
- **Phase 3 — Decentralize:** DHT tracker, gossip health, latency beaconing, canary audits.
- **Phase 4 — Hardening:** TEE-attested confidential tier, paranoid mode, wider clients.

## Build

The 9 network crates are **pure Rust** — no C toolchain needed:

```bash
cargo test -p lluma-core -p lluma-crypto -p lluma-issuer -p lluma-net -p lluma-relay \
           -p lluma-gateway -p lluma-broker -p lluma-host -p lluma-client --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

Only `lluma-runtime` (the in-process llama.cpp GGUF runner) requires a **C toolchain**
(`cc`/`clang` + cmake). The **desktop app builds without one** — see below.

## Desktop client

`apps/lluma-desktop` is a Tauri v2 thick client with four tabs — **Chat** (anonymous
inference over the live relay), **Contribute** (run a serving host), **Status** (network +
privacy explainer + balance), and **Settings** (endpoints + account). Chat and hosting both
run on the pure-Rust path (`lluma-client` / `lluma-host`); in-process llama.cpp is an optional
`local-inference` feature, off by default.

```bash
# from the app's own workspace (it is standalone, not a root workspace member):
cd apps/lluma-desktop/src-tauri
cargo test                 # unit/integration tests (pure Rust, no C toolchain)
cargo build --release      # produces target/release/lluma-desktop(.exe)
```

Launch the built binary (or `cargo run`). First run opens with defaults: the relay URL is
pre-filled (`https://relay.n.lluma.bodegga.net`), but the **gateway key-config** and **broker
registry pubkey** must be supplied — click **Fetch from relay** (once the relay publishes
`/v1/bootstrap`) or paste them in **Settings** from your operator
(`journalctl -u lluma-gateway | grep key_config`). Then create or unlock an account in
Settings; **Chat needs a funded account** (credits are granted to your `account_id`, shown in
Status) and at least one active host in the network snapshot.

Contributing requires an **internet-reachable ingress address** (public IP / port-forward);
desktop-behind-NAT hosting is roadmap work.

## Repository layout

```
crates/lluma-core        shared wire types, proto DTOs, errors
crates/lluma-crypto      blind tokens, HPKE E2E, OHTTP, accounts, PoW
crates/lluma-issuer      blind-token issuer (issue/redeem/credits) + traits
crates/lluma-net         libp2p/relay transport primitives + framing
crates/lluma-relay       OHTTP relay (sees IP + ciphertext only)
crates/lluma-gateway     OHTTP gateway (decapsulates; path-allowlisted)
crates/lluma-broker      registry + durable accounting + receipts + snapshots + trial (redb)
crates/lluma-host        API-donor serving host + OpenAI-compatible upstream adapter
crates/lluma-client      consumer client (acquire tokens, exec anonymous inference)
crates/lluma-keygen      operator key-material generator (issuer/registry/salt)
crates/lluma-runtime     hardware detection, model recommendation, GGUF runner (needs C toolchain)
crates/lluma-registry    model catalog + content-addressed download/verify
apps/lluma-desktop       Tauri app — Chat/Contribute/Status/Settings (pure-Rust default build)
apps/lluma-web           marketing site (DO App Platform → lluma.bodegga.net)
ops/deploy               production deployment (scripts, systemd units, runbook)
docs/                    specs, plans, architecture (ADRs), handoffs
docs/INFRA.md            production infrastructure inventory + deploy procedure
.claude/agents/          specialized subagents for building Lluma
```

## Development methodology

Lluma is built by a small model-tiered agent team with adversarial review baked in — the
approach that has caught real security bugs (concurrent double-debit, two SSRF bypasses
incl. an IPv4-mapped-IPv6 filter bypass, a self-dealing inflation hole, a tripwire
false-trip) *before* merge rather than in production:

- **Reasoning & design → Fable / Opus.** Architecture, cryptography, protocol, threat
  modeling, and ADRs use the strongest models. The `protocol-crypto-architect` subagent
  (Fable) reviews the plan, the security-critical core, and the whole branch before any merge.
- **Bulk implementation → GLM 5.2** via `opencode run --auto -m opencode-go/glm-5.2`, but
  **only** for small, precisely-briefed, mechanical files (wire DTOs, signing mirrors). Every
  brief forbids workspace-wide `cargo fmt` and out-of-crate edits; every result is
  re-verified (`cargo test` + `clippy -D warnings`) by the controller — never trusted on its word.
- **Security-critical code → the controller (Opus)** writes it directly: proof-of-work
  gates, admission state machines, receipt fraud bounds, the double-spend/tripwire logic,
  redeem paths, snapshot padding.
- **Process → subagent-driven-development / TDD.** A task-decomposed plan, a fresh implementer
  per task, a per-task review, and a final whole-branch review. Progress is tracked in a durable
  ledger so work survives context loss.

Non-negotiables (see [`CLAUDE.md`](CLAUDE.md)): the privacy invariant (no single party holds
both originator IP and prompt plaintext); typed errors via `thiserror`, no `unwrap()`/`expect()`
in library crates; BLAKE3 content addressing; green tests + clippy before any task is "done".

## Deployment

Production runs the ADR-0002 topology across **two distinct providers** so no single vendor
sees both network edges (leak L10): the **relay** on one provider (Vultr) and the **co-located
issuer+broker origin + gateway** on another (DigitalOcean), with the marketing site on DO App
Platform and DNS on ZoneEdit. Generate operator keys with `lluma-keygen`, then follow the
runbook. Full inventory, hostnames, and step-by-step procedure: [`docs/INFRA.md`](docs/INFRA.md)
and [`ops/deploy/`](ops/deploy/). Deployment is operator-gated and never automatic.

## License

Apache-2.0.
