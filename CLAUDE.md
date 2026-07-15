# CLAUDE.md

Project-specific instructions for Claude Code in the Lluma repo.

## Read first
- Design spec: `docs/superpowers/specs/2026-07-14-lluma-design.md`
- Contributor guide: `AGENTS.md`

## Non-negotiables
- Privacy invariant: no single party ever holds both originator IP and prompt plaintext.
- Typed errors via `thiserror`; no `unwrap()`/`expect()` in library crates (tests excepted).
- BLAKE3 for all content addressing.
- TDD with frequent commits; run `cargo test` and `cargo clippy --all-targets -- -D warnings`
  before claiming a task is done.

## Model strategy
- Use Fable (`claude-fable-5`) for architecture/crypto/protocol reasoning.
- Use smaller models via subagents for implementation.

## Commit trailer
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
