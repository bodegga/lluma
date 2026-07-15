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

Phase 0 (Dogfood): a point-and-click desktop app that auto-detects your hardware and
recommends a model to host, with a streaming chat UI. The BLAKE3-verified model download
and the llama.cpp GGUF runner are implemented as library crates and land in the app in the
next phase, alongside the anonymous network (relay + broker + credits).

## Roadmap

- **Phase 0 — Dogfood:** local host app + GGUF runtime + local chat. ← *current*
- **Phase 1 — MVP:** relay + broker + blind-token issuer + credits → anonymous inference.
- **Phase 2 — Torrent layer:** P2P content-addressed weight distribution.
- **Phase 3 — Decentralize:** DHT tracker, gossip health, latency beaconing, canary audits.
- **Phase 4 — Hardening:** TEE-attested confidential tier, paranoid mode, wider clients.

## Build

```bash
cargo build
cargo test
# run the desktop app (after Task 7):
cd apps/lluma-desktop && cargo tauri dev
```

## Repository layout

```
crates/lluma-core       shared types, errors
crates/lluma-runtime    hardware detection, model recommendation, GGUF runner
crates/lluma-registry   model catalog + content-addressed download/verify
apps/lluma-desktop      Tauri app (Contribute + Chat tabs)
docs/                   specs, plans, architecture
.claude/agents/         specialized subagents for building Lluma
```

## License

Apache-2.0.
