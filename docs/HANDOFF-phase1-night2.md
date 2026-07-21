# Lluma Phase 1 — Overnight Session 2 Report (Full #4 + #5 adapter)

**Written:** 2026-07-20 (overnight, autonomous). **For:** the morning review.
**State:** local `main`, **~53 commits ahead of `origin/main`, NOT pushed, NOT deployed.**

## TL;DR

Picked up from the night-1 slice and built **Full #4 (the broker: host registry,
signed snapshots, usage receipts, anti-Sybil trial registration)** and the **#5
generic OpenAI-compatible inference adapter**, then merged the whole thing to local
`main`. **213 tests pass across all 9 Phase-1 crates; `clippy --all-targets
--all-features -D warnings` clean.** Fable reviewed the design, the fraud core, and
the whole branch; every fix it asked for before merge landed.

Execution model (as instructed): **Fable** (`protocol-crypto-architect`) for design
+ security reviews; **GLM 5.2** (`opencode run --auto -m opencode-go/glm-5.2`) for
mechanical wire/crypto-mirror tasks; **controller (me, Opus)** for all
security-critical logic + coordination.

## What shipped (merged to local `main`)

| Piece | State |
|---|---|
| Anti-Sybil **PoW** (domain-separated, fixed-width BLAKE3) + register/heartbeat/snapshot Ed25519 signing | ✅ crypto Task 1 |
| **Store** extended: RECEIPTS/HOSTS/COUNTERS/TRIAL_*/SPEND_HOST + `with_write` multi-table atomicity backbone | ✅ Task 3a |
| **Registry**: PoW register, time-gated slow admission, replay-proof heartbeats, SSRF-hard ingress policy | ✅ Task 3b |
| **Receipts**: one-txn RECEIPTS+LEDGER credit of **exactly 1** (self-dealing zero-sum), SPEND_HOST binding | ✅ Task 3c |
| **Counters + tripwire**: per-token-epoch `redeemed ≤ issued`, refuse+rollback on trip | ✅ Task 3c |
| **Trial grant**: one-per-account, global daily budget, uniform refusal | ✅ Task 3d |
| **Snapshot**: deterministic, fixed 64 KiB, padded, signed, fail-closed; client verify | ✅ Task 4 |
| **Service**: two routers (core/ingress), registry-resolved redeem, redirect-none forwarder | ✅ Task 5 |
| **Co-located binary** (`lluma-broker`): issuer+broker on one store, issued-hook, zero-salt guard | ✅ Task 5 |
| **Marquee `broker_e2e`**: matchmaking+receipts, durable respend, tripwire, unknown-host-no-burn | ✅ Task 6 |
| **#5 `OpenAiUpstream`**: any OpenAI-compatible endpoint behind a fallible `Upstream`; mock-tested | ✅ #5 adapter |

## Adversarial review earned its keep again

- **Plan review (Fable):** caught a receipt-crediting atomicity flaw (would
  self-deadlock/non-atomic), a self-dealing inflation hole (`units`→credit), and a
  counter-keying bug that would have destroyed the tripwire. All fixed in the plan
  before a line was written.
- **Fraud-core review (Fable):** caught a **real SSRF bypass** — `::ffff:169.254.169.254`
  (IPv4-mapped IPv6) slipped past the ingress filter to cloud metadata. Fixed +
  regression-tested. Plus write-lock/admission hardening.
- **Whole-branch review (Fable):** caught **I1** — the anti-Sybil trial endpoint was
  on the host-ingress listener, which would have either been dead to clients or
  leaked `account_pk + IP` to the broker (leak L16). Moved to the core (relay-routed)
  router before merge.

## Decisions I made autonomously (please review)

1. **GLM 5.2 kept to mechanical, precisely-briefed files only** (wire DTOs, the
   sign/verify mirrors). It succeeded on those — but on its very first task it ran a
   **workspace-wide `cargo fmt`** and churned 29 out-of-scope files; I reverted that
   and added an explicit anti-fmt guard to later briefs. All security-critical
   broker code (PoW gate, admission, receipt fraud bounds, tripwire, snapshot
   padding, redeem path) I wrote myself, per the standing lesson. Recommend keeping
   GLM on this tight leash.
2. **`Upstream` trait made fallible** (`Result<_, UpstreamError>`) so a real model
   call that times out returns a 502 instead of sealing a fabricated "answer".
   Small change to the merged host; slice e2e still green.
3. **`issued` counter wired via an issuer `issued_observer` hook** (co-located main
   bumps it before releasing signatures). Required for the tripwire to function, not
   just tests. `None` for the standalone issuer.
4. **Redeem counter keyed by `cfg.epoch`** (single-epoch MVP). Sound today; a
   `TODO(multi-epoch)` marks where to derive it from `key_id` before key rotation.

## Verify
```
cargo test -p lluma-core -p lluma-crypto -p lluma-issuer -p lluma-net -p lluma-relay \
           -p lluma-gateway -p lluma-broker -p lluma-host -p lluma-client --all-features
cargo clippy --all-targets --all-features -- -D warnings   # (per-crate as above)
```
(cargo at `/c/Users/A/.cargo/bin`; all pure-Rust — no MSVC/C toolchain needed for these 9 crates.)

## What remains — your steer

- **Deployment** (`ops/deploy/`): **prepared, NOT executed** — outward/irreversible,
  gated on your explicit go-ahead. ≥2-VPS topology, systemd templates, env example,
  key-material helper, manual checklist. Before real traffic: persist the gateway
  OHTTP key, and address the pre-production follow-ups below.
- **Pre-production hardening** (`docs/PHASE1-FOLLOWUPS.md`, all non-blocking): I2
  `spawn_blocking` for store calls; I3 snapshot fixed-cadence cache (soft-DoS on the
  redeem listener otherwise); M2 issued-bump failure handling; M4 fail-closed
  SSRF-client builder; multi-epoch counter keying.
- **Desktop/Tauri** (`docs/DESKTOP-ASSESSMENT.md`): **blocked in this environment**
  by the C toolchain (`lluma-runtime → llama-cpp-2`). Feasible without local
  inference: a network-chat consumer tab (via `lluma-client`) and a contribute tab
  via the new OpenAI adapter — both need your UX steer and a C-toolchain machine to
  build/test the coexisting local-inference path.
- **Real local inference**: the `lluma-runtime`/GGUF path (and the three
  PHASE1-FOLLOWUPS fixes) needs a C toolchain — not available here.

I stopped at a fully-green, Fable-reviewed, merged milestone. Nothing is pushed or
deployed. Say the word on deployment or the desktop UX and I'll pick it up.
