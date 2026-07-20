# Lluma Phase 1 — Overnight Autonomous Session Report

**Written:** 2026-07-19 (overnight, autonomous) · **For:** the morning review.
**Branch/state:** local `main`, **~25 commits ahead of `origin/main`, NOT pushed** (per your standing "local only, ask before pushing / deploying").

---

## TL;DR

Started the night at Phase-1 sub-project **#2**. Ended with a **working, tested end-to-end anonymous-inference slice**: one anonymous request goes `client → relay → gateway → {issuer, broker} → host → (echo) model → back`, proven by a marquee integration test, with the privacy invariant asserted across every party. **150 tests pass across all 9 Phase-1 crates; clippy `-D warnings` clean.** Everything is merged to **local `main`**. Nothing pushed or deployed.

The security-review loop earned its keep: adversarial review (Fable + a background reviewer) caught **four real security bugs** in code I wrote — a concurrent double-debit race, two SSRF path-traversal bypasses (plain, then encoded/control-char), and an ~80%-flaky privacy test — all fixed with regression tests before merge.

## What shipped (merged to local `main`)

| Sub-project | State |
|---|---|
| #2 `lluma-issuer` — token issuance loop | ✅ merged; Fable-reviewed; double-debit race fixed |
| #3 transport — `lluma-net` + `lluma-relay` + `lluma-gateway` | ✅ merged; 2 SSRF holes fixed; marquee OHTTP invariant harness |
| #4 broker — **durable accounting core** (`lluma-broker`: redb ledger + spent-set) | ✅ merged; **closes #2's restart-respend deployment blocker** |
| #4/#5 **slice** — broker `/v1/exec`, `lluma-host` (echo upstream), `lluma-client`, marquee e2e | ✅ merged; Fable-reviewed |

## The marquee proof (`crates/lluma-client/tests/e2e_slice.rs`)

One anonymous request end-to-end. Asserted: the answer carries both prompt+response sentinels (reached the model); relay/gateway/origin never see prompt OR response plaintext (a positive control proves the scanner isn't vacuous); the host is reached exactly once and only via the broker; a replayed token is refused (`409`) and never reaches the host (durable spent-set).

## Key engineering decisions I made autonomously (please review)

1. **redb instead of rusqlite** for the durable store — this box has **no C compiler** (`cc`/`gcc`/`cl`/`clang` all absent), so rusqlite's bundled SQLite (C) would wall like `lluma-runtime`. redb is pure-Rust ACID. (spec §R4, deviation recorded.)
2. **Fail-closed durable trait impls** instead of Fable's fallible-traits refactor — same security guarantee, **zero changes to the merged, green #2** (spec §R5).
3. **Static host registry + broker-as-sole-redeemer + echo upstream** for the slice (ADR-0003) — deferring anti-Sybil/matchmaking/receipts, which defend availability, not the linkage invariant.
4. **Kimi K3 removed from the critical path.** It stalled/thrashed on every substantial task (the #2 e2e harness, the #2 fix-batch, the #3 relay, the #4 fix-batch). I wrote the security-critical code myself with Fable as reviewing operator. Slower on my side, but it's why the four security bugs were caught, not shipped. **Decide in the morning whether to keep Kimi in the loop.** (One of its half-finished files — a flaky raw-JSON sweep — did leak into the tree and caused the late flakiness; now fixed.)

## What remains (needs you / larger effort)

- **Full #4** (buildable next): signed registry snapshots, host registration + heartbeats + slow admission, receipt ingest + crediting, trial-grant anti-Sybil (global daily budget + PoW). Design already ruled by Fable + spec'd (`docs/superpowers/specs/2026-07-19-lluma-broker-design.md`).
- **#5 real inference:** a real OpenAI-compatible adapter behind the host's `Upstream` trait (~20 lines + a provider key). Local GGUF (`lluma-runtime`) is blocked here by the missing C toolchain.
- **#5 desktop:** Tauri wiring (Contribute + Chat tabs) — a large separate effort.
- **Deployment:** the ≥2-VPS topology (ADR-0002) — **outward/irreversible, gated on your go-ahead.**

## Honest caveats (per ADR-0003)
The e2e test is in-process on localhost — it *models* IP-separation via the connection graph + recorded views rather than proving it across real infrastructure; the "model" is an echo stub; timing/size side-channels and network-level unlinkability are #5/deployment concerns. New leak carry-forwards (issue→spend timing correlation, bearer-token gateway visibility, size/timing side channel) are recorded in ADR-0003.

## How to verify
```
cargo test -p lluma-core -p lluma-crypto -p lluma-issuer -p lluma-net -p lluma-relay \
           -p lluma-gateway -p lluma-broker -p lluma-host -p lluma-client --all-features
```
(cargo on PATH at `/c/Users/A/.cargo/bin`; all pure-Rust — no MSVC env needed for these 9 crates.)
Design/ADR docs: `docs/architecture/adr-0002` (hosting/DDoS), `adr-0003` (slice scope), and the specs under `docs/superpowers/specs/2026-07-*`.
