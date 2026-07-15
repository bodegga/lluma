# Lluma — Agent & Contributor Guide

This file orients any agent or engineer working in this repo.

## What Lluma is

Anonymous, contribution-based, peer-to-peer LLM inference. Read
`docs/superpowers/specs/2026-07-14-lluma-design.md` before making architectural changes.

## Golden rules

- **Privacy invariant:** never write code where a single party holds both the originator's
  IP and the prompt plaintext. If a change could violate this, stop and flag it.
- **Typed errors:** every crate defines its errors with `thiserror`. No `unwrap()`/`expect()`
  in library code outside tests.
- **TDD:** failing test first, then implementation, then commit. Small commits.
- **Content addressing:** BLAKE3 only.
- **Brand:** "Lluma" and "Bodegga" are always capitalized in user-facing copy.

## How we build (model strategy)

- **Fable (`claude-fable-5`)** does the high-reasoning work: protocol/crypto design, ADRs,
  threat modeling, architecture review. Use the `protocol-crypto-architect` agent.
- **Smaller models (Sonnet/Haiku) via subagents** do implementation grunt work: crate
  boilerplate, tests, glue, docs. Use `rust-net-engineer`, `model-runtime-engineer`,
  `tauri-frontend`, `test-writer`, `docs-writer`.

## Build & test

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

## Layout

See `README.md` → Repository layout.
