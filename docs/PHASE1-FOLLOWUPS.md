# Phase 1 Follow-ups (carried from the Phase 0 whole-branch review)

These items were identified during the Phase 0 final code review (Fable, 2026-07-15)
and deliberately deferred. None block Phase 0. Several **must** be fixed as part of the
first Phase 1 task below, because they are only latent today thanks to code that does not
yet run end-to-end.

## Named first Phase 1 task: "Wire download + LlamaRunner into lluma-desktop"

The Phase 0 desktop app currently detects hardware, recommends a model, and streams via
`MockRunner`. It does **not** yet invoke `download_verified` or `LlamaRunner`. Wiring those
in is the first Phase 1 task, and it is **gated on fixing** the following, which will
otherwise bite immediately:

1. **Download buffers the whole file in memory** (`crates/lluma-registry/src/download.rs`).
   The 8B catalog model is ~4.9 GB resident — this will OOM/thrash the 8–16 GB machines the
   catalog targets. Rewrite to stream to a `*.part` temp file while hashing, then verify and
   atomically rename. (Also fixes the non-atomic final write.)
2. **`LlamaRunner` context/batch guards** (`crates/lluma-runtime/src/runner.rs`).
   `LlamaBatch::new(512, 1)` caps prefill at 512 tokens; there is no `tokens.len() + max_tokens
   <= n_ctx` check. Add an upfront typed error ("prompt too long") and size the batch to the
   prompt. A 512-token cap is below routine chat prompts.
3. **`LlamaBackend::init()` is process-global** (`runner.rs`). A second live runner returns
   `BackendAlreadyInitialized`. Acquire the backend via a `OnceLock<Arc<LlamaBackend>>` before
   Phase 1 hosts multiple quants concurrently.

## Correctness / robustness

- **Verify GGUF hash on load**, not only on download (`download.rs`) — guards against on-disk
  corruption/tampering between download and use.
- **BLAKE3 hash comparison is case-sensitive** (`download.rs`). Normalize with
  `eq_ignore_ascii_case` (or lowercase catalog values) so an uppercase pinned digest doesn't
  produce a permanent, confusing mismatch.
- **Recommendation ignores disk space** (`crates/lluma-runtime/src/recommend.rs`). Add
  `disk_free_bytes >= download_bytes` to the fit filter — the profile already carries the data.
- **Per-request sampler entropy + chat template** (`runner.rs`). The sampler seed is fixed
  (`dist(1234)`), so every generation is byte-identical across users/runs, and prompts are fed
  raw with no chat template — instruct models will behave poorly. Apply a chat template at the
  call site and use per-request entropy before real chat ships.

## Wire-format / API hygiene (resolve before any Phase 1 wire format is frozen)

- **`Quant` serde representation** — FIXED in Phase 0 (`#[serde(rename = ...)]` now matches the
  GGUF Display strings). Keep this alignment when defining protocol messages.
- **Commit `Cargo.lock`** — this workspace ships an application; the lockfile should be committed
  for reproducible builds. Consider pinning `llama-cpp-2` to an exact patch (the branch already
  absorbed one `token_to_piece` signature change from `0.1.x` drift).

## Desktop app polish

- **Make Tauri commands `async`** (`apps/lluma-desktop/src-tauri/src/lib.rs`). Sync commands run
  on the main thread; `System::new_all()` in `detect_hardware()` can briefly freeze the UI. Also
  slim detection to `System::new()` + targeted refreshes (the `refresh_memory()` after
  `new_all()` is redundant).
- **`AppState.last_profile` is written but never read**; `recommend_model_cmd` re-detects hardware
  instead of reusing it. Either read the cached profile or drop the field.
- **Concurrent `start_generate` calls interleave** token events into one pane (no generation id).
  Harmless with the instant MockRunner; matters once real multi-second generation lands — add a
  generation id to `token`/`done`/`error` events.

## Testing

- **Run the gated integration test once with a real GGUF** (a ~300 MB Qwen 0.5B is enough) before
  Phase 1 begins — `LlamaRunner` is the only nontrivial Phase 0 code that has never executed
  against a real model. Set `LLUMA_TEST_GGUF` to the file path.
- Add a JSON round-trip test for `ModelRecommendation` (other serde types are covered).
- `MockRunner` with `max_tokens: 0` still emits one token (`.max(1)`); document or drop the clamp.

## Privacy invariant (structural note for Phase 1)

Phase 0 is structurally clean: no prompt text is logged, no error variant embeds prompt content,
and no global state couples identity to content. Preserve this when adding the relay/broker:
the serving-side prompt must never be written to logs or telemetry, and request routing metadata
must stay separate from prompt plaintext.
