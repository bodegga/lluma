# Desktop (Tauri) — feasibility assessment (2026-07-20)

Honest status of the `#5 desktop` thread, given this build environment.

## Blocked here (hard constraint)

`apps/lluma-desktop/src-tauri` depends on `lluma-runtime`, which depends on
`llama-cpp-2` — a C/C++ build requiring a C toolchain (`cc`/`clang`/`cl` + cmake).
**None is present on this machine** (the same constraint that forced redb over
rusqlite for the broker, confirmed 2026-07-19). Therefore the desktop app **cannot
be built, run, or verified in this environment.** Writing Tauri UI/command code
blind — with no ability to compile or exercise it — would violate the project's
"functional and proven-by-tests" bar and risk committing unverifiable code, so it
was **not** attempted autonomously.

The named Phase-1 first task ("wire download + LlamaRunner into lluma-desktop",
`docs/PHASE1-FOLLOWUPS.md`) is squarely in this blocked set, along with its three
gating fixes (streaming download, batch/context guards, `OnceLock` backend).

## Feasible without the C toolchain (recommended follow-ups, need UX steer)

The #4/#5 work done tonight makes two desktop paths buildable **without local
GGUF inference** — i.e. without `lluma-runtime`, so they'd compile here if the
desktop crate's runtime dependency were put behind a Cargo feature:

1. **Chat via the Lluma network (consumer):** wire the Chat tab to `lluma-client`
   (relay → gateway → broker → host). Pure-Rust; needs no local model. This is the
   most compelling demo — anonymous inference from the desktop — and reuses the
   exact client path proven by `e2e_slice`.
2. **Contribute via the OpenAI-compatible adapter (host):** run `lluma-host` with
   the new `OpenAiUpstream` (this commit series) so a contributor can serve without
   a local GPU/llama.cpp. Also pure-Rust.

Both are **large UI efforts** and involve product/UX decisions (tabs, streaming
display, account/keystore UX, host-earnings view) that the handoff correctly
flagged as needing the operator's steer. They are the right next desktop increment
**once a machine with a C toolchain is available** (so the local-inference path can
coexist and be tested), or behind a `--no-default-features`/feature split if we
want to ship a network-only desktop build first.

## Recommendation

Defer desktop to a session on a C-toolchain-equipped machine (or a CI runner with
one), where `lluma-runtime` + the Tauri app actually build. Prioritize the
network-chat consumer path first (highest demo value, fully proven backend). Do not
generate desktop code that cannot be compiled or exercised.
