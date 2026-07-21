# Lluma Phase 1 · Full #4 — Broker (registry + snapshots + receipts + anti-Sybil) Implementation Plan

Executes the design spec `docs/superpowers/specs/2026-07-19-lluma-broker-design.md`
(Fable rulings R1–R12) on top of the already-merged durable accounting core
(`Store`/`RedbSpentSet`/`RedbLedger`, broker `/v1/exec`).

**Status:** Fable design review complete (2026-07-20) — **APPROVE-WITH-CHANGES**. All 7 must-fixes
and the binding should-fixes are folded into the task sections below and marked `[FABLE]`.

- **Branch:** `feat/phase1-broker-full` (merges to local `main`, not pushed).
- **Execution:** subagent-driven-development. Bulk/mechanical tasks → GLM 5.2 via
  `opencode run --auto -m opencode-go/glm-5.2`. Security-critical decision logic + the
  `Store::with_write` txn backbone + all policy validation → controller (Opus). Design + security
  review → Fable (`protocol-crypto-architect`).
- **Non-negotiables (Global Constraints — copy verbatim into every reviewer prompt):**
  - Privacy invariant: no single party ever holds both originator IP and prompt plaintext.
    The broker sees `{spend_id, host, model, tier, units, timestamp_h}` — **never** a consumer
    account, originator IP, or prompt plaintext.
  - Typed errors via `thiserror`; **no `unwrap()`/`expect()` in library crates** (tests excepted).
  - BLAKE3 for all content addressing and PoW.
  - Ed25519 signing is **domain-separated** — every new signed body gets its own distinct
    domain string; domains are never shared or reused. PoW hashing is likewise domain-separated.
  - Fail-closed on storage/verification error (mirror the merged `RedbSpentSet`/`RedbLedger`).
  - **No redb write-txn is ever held across an `.await`.** Multi-table atomic units go through the
    controller-written `Store::with_write(|txn| …)` primitive (Task 3a).
  - `cargo test` (all 9 crates) + `cargo clippy --all-targets -- -D warnings` green before any
    task is marked complete.

## redb schema translation (spec §5 SQL → redb tables) — [FABLE-ruled]

| Table (const)      | Key                | Value                                              | Notes |
|--------------------|--------------------|----------------------------------------------------|-------|
| `SPENT` (exists)   | `spend_id &[u8]`   | `epoch u64`                                         | presence = spent; purge `< k−1` |
| `LEDGER` (exists)  | `account &[u8]`    | `postcard(LedgerRow{balance,earned,spent})`        | fail-closed |
| `RECEIPTS`         | `spend_id &[u8]`   | `postcard(ReceiptRow{host_account,model_id,tier,units,epoch:u64,timestamp_h,sig})` | presence = credited (idempotency); **purge `< k−1` together with SPENT** |
| `HOSTS`            | `host_account &[u8]` | `postcard(HostRow{hpke_pk,ingress_addr,models,status,hb_counter,last_hb,load_bucket,admit_progress})` | status: 0=pending,1=active |
| `COUNTERS`         | `token_epoch u64`  | `postcard(CounterRow{issued,redeemed,trial_granted})` | **keyed by TOKEN epoch (via key_id), NOT wall-clock** (must-fix 5) |
| `TRIAL_ACCTS`      | `account &[u8]`    | `day u64`                                           | one trial grant per account; **never purged** (forever guard) |
| `TRIAL_BUDGET`     | `day u64`          | `granted u64`                                       | global daily trial-credit budget |
| `SPEND_HOST`       | `spend_id &[u8]`   | `host_account [u8;32]`                              | [FABLE should-fix 4] records which host a spend was forwarded to; receipt ingest checks `receipt.host_account` matches. Side table so merged `SPENT` value format is untouched |

- **Epoch integer type:** `UsageReceiptBody.epoch` is `u32` (merged); everything in the store is
  `u64`. Normalize in Task 2 by widening `u32→u64` at the store boundary; document the widening.
- **Atomicity:** every mutation is one redb write-txn (read-check-write + commit). Multi-table
  units use `Store::with_write`. The named atomic units: (a) **receipt ingest** = RECEIPTS+LEDGER;
  (b) **trial grant** = TRIAL_ACCTS+TRIAL_BUDGET+LEDGER+COUNTERS; (c) **redeem** =
  SPENT+SPEND_HOST+COUNTERS.redeemed. `spawn_blocking` wraps the sync store from async handlers.

## Security defaults — [FABLE-ruled, final]

- **PoW** — `blake3(DOMAIN ‖ account_pk[32] ‖ nonce[8] ‖ epoch_salt[32])` must have ≥ **D=20**
  leading zero bits (config knob). All three fields **fixed-width, length-validated before
  hashing** (no length prefixes needed). `DOMAIN` is **per-purpose**: `b"lluma-pow-trial-v1"` for
  issuer trial registration, `b"lluma-pow-host-v1"` for host registration (one solve must not
  serve both). `epoch_salt` is **one global 32-byte value per epoch** (published; accept `k` and
  `k−1` to bound precomputation) — never per-requester (that would be a linkage tag).
- **Trial grant** — **20 credits**, one-time per new account (config).
- **Global daily trial budget** — **10 000 credits/day** as the config default. ⚠️ This size is a
  **product/growth decision, NOT security-reviewed** — the *security* property is only that a
  fail-closed global cap exists. Budget exhaustion response is **uniform** (no per-account signal).
- **Slow admission `M`** — **3** valid heartbeats `pending→active`; evict after **3** consecutive
  missed intervals.
- **Heartbeat interval** 30 s; **snapshot cadence** 60 s (R10).
- **Receipt crediting** — [FABLE must-fix 4] **exactly 1 credit per valid receipt** (single
  `DENOMINATION`). `units ≤ 4` is retained ONLY as a metering/audit bound; `units` is **never**
  multiplied into the credited amount (prevents self-dealing inflation).
- **Snapshot padding** — postcard body + fixed-width `u32` length prefix, zero-padded to a **fixed
  64 KiB bucket** (L4), then signed whole (domain `lluma-registry-snapshot-v1`). Overflow ⇒
  `publish()` **fails closed + alarm-logs** (no silent bucket growth).
- **Epoch window** — `SPENT`/`RECEIPTS` rows carry epoch; accept `k` and `k−1`; purge `< k−1`.

## Leak-register additions — [FABLE] (record in ADR-0001/0002; confirm numbering, L14 is latest)
- **L15 — receipt `units` output-size channel:** host-attested response-size metering per spend_id
  survives future response padding; mitigated by coarse buckets (≤4) + hour-coarse timestamps.
- **L16 — trial-register temporal linkage:** register(account_pk)→issue→spend for brand-new
  accounts extends the issue→spend correlation to the account's creation moment. Mitigate via
  **mandatory relay-routed register** (never the direct ingress listener) + #5 pre-fetch/delay.
- **L17 — snapshot-fetch fingerprint:** a direct (non-relay) snapshot GET reveals client IP + "is a
  Lluma user" + fetch-timing preceding exec; mitigate via relay-path fetch + fixed-cadence polling
  (client, #5).

---

## Task 2 — wire bodies + proto DTOs (`lluma-core`)  [GLM — mechanical, follows existing pattern]

`crates/lluma-core/src/wire.rs` — add canonical bodies (postcard-serializable, `Debug` safe,
public material):
- `HostRegisterBody { version:u8, host_account:[u8;32], hpke_pk:Vec<u8>, ingress_addr:String, models:Vec<ModelId> }`
- `HeartbeatBody { version:u8, host_account:[u8;32], hb_counter:u64, load_bucket:u8, models:Vec<ModelId> }`
- `TrialRegisterBody { version:u8, account:[u8;32] }`  (the PoW-gated trial-grant request body)
- `SnapshotHostEntry { host_account:[u8;32], hpke_pk:Vec<u8>, models:Vec<ModelId>, tier_flags:u8, load_bucket:u8, freshness_bucket:u8 }` — **note: NO `ingress_addr`** (clients never learn host addresses).
- `SnapshotHeader { epoch:u64, issued_at_h:u32, issuer_key_id:[u8;32] }`
- `SnapshotBody { header:SnapshotHeader, hosts:Vec<SnapshotHostEntry> }`

`crates/lluma-core/src/proto.rs` (`v1`) — add DTOs with the existing base64-string serde helper
pattern + `validate()` (exact lengths, fail closed). `validate()` does **length/shape only** —
never address policy (that is controller logic in Task 3b):
- `HostRegisterRequest { body:HostRegisterBody, sig:base64(64), pow_nonce:base64(8) }`
- `HeartbeatRequest { body:HeartbeatBody, sig:base64(64) }`
- `TrialRegisterRequest { body:TrialRegisterBody, pow_nonce:base64(8) }`
- `ReceiptSubmit { body:UsageReceiptBody, sig:base64(64) }`
- `SnapshotResponse { body:base64(64 KiB), sig:base64(64) }`

Normalize epoch types here (should-fix 1): store/header epoch is `u64`; document the `u32→u64`
widen at the store boundary. Tests: JSON round-trip + `validate()` accept/reject (wrong sig
length, wrong nonce length, empty ingress_addr, etc.) — mirror existing `proto::v1` tests.

## Task 1 — crypto signing domains + PoW (`lluma-crypto`)  [GLM sign/verify mirrors; CONTROLLER writes PoW]

Add to `crates/lluma-crypto/src/account.rs`, mirroring `receipt_sign`/`receipt_verify` exactly
(domain-separated `DOMAIN ‖ postcard(body)`, Ed25519, `Result<_, CryptoError>`):
- `host_register_sign/verify` — domain `b"lluma-host-register-v1"`, body `HostRegisterBody`.
- `heartbeat_sign/verify` — domain `b"lluma-heartbeat-v1"`, body `HeartbeatBody`.
- `snapshot_sign/verify` — domain `b"lluma-registry-snapshot-v1"`, message = the padded 64 KiB
  snapshot bytes (NOT a postcard body — sign the exact bytes clients verify).
- **[CONTROLLER][FABLE must-fix 6]** `pow_verify(domain:&[u8], account_pk:&[u8;32], nonce:&[u8;8],
  epoch_salt:&[u8;32], difficulty_bits:u32) -> bool` — `h = blake3(domain ‖ account_pk ‖ nonce ‖
  epoch_salt)`; count big-endian leading zero bits; `>= difficulty_bits`. Fixed-width inputs typed
  in the signature. Add `pow_solve(domain, account_pk, epoch_salt, difficulty_bits) -> [u8;8]`
  (test/client helper) incrementing a `u64` nonce until satisfied.

Tests: round-trip + tampered-body + wrong-key for each domain; **cross-domain rejection** (a
`heartbeat` sig must not verify as `host_register`); `pow_verify` accepts a solved nonce, rejects
`difficulty+1`, and **rejects a trial-domain solve under the host domain** (per-purpose separation).

## Task 3a — store: tables + row types + `with_write` primitive + CRUD (`lluma-broker`)  [GLM CRUD; CONTROLLER writes `with_write`]

`store.rs` — add the six new `TableDefinition`s (RECEIPTS, HOSTS, COUNTERS, TRIAL_ACCTS,
TRIAL_BUDGET, SPEND_HOST); open all in `Store::open`. Add row structs (`HostRow`, `ReceiptRow`,
`CounterRow`) with `Serialize/Deserialize`.
- **[CONTROLLER][FABLE must-fix 2]** `Store::with_write(f)` — opens ONE write-txn, passes it to
  `f` (which may open multiple tables), commits on `Ok`, aborts on `Err`; fail-closed to
  `BrokerError::Storage`. This is the multi-table atomicity backbone; no txn crosses `.await`.
- **[GLM]** per-table typed get/put helpers for single-table reads/writes, mirroring
  `RedbLedger::mutate`. Tests: put/get round-trip + restart persistence per table;
  `with_write` commits all-or-nothing (a closure returning `Err` leaves no partial writes).

## Task 3b — registry: host register (PoW+admission) + heartbeat + ingress policy (`lluma-broker`)  [CONTROLLER]

`registry.rs`:
- `register(signed: HostRegisterRequest, cfg) -> RegisterOutcome` — `host_register_verify`;
  `pow_verify` with domain `lluma-pow-host-v1` at `cfg.pow_difficulty`; **[FABLE must-fix 7]
  `ingress_addr` policy validation** (controller, not DTO `validate()`): require http(s) scheme;
  under prod config **deny loopback/link-local/RFC1918**, allow loopback only under a test flag.
  Insert `HostRow{status:pending, admit_progress:0}` if absent (idempotent re-register updates
  addr/models, keeps status). Fail closed on any check.
- `heartbeat(signed) -> HeartbeatOutcome` — **key-id HashSet pre-filter** (unknown host ⇒ cheap
  reject before Ed25519); verify sig; enforce **monotonic** `hb_counter` (≤ stored ⇒ replay
  reject); update `last_hb`, `load_bucket`; `admit_progress += 1`; at `>= cfg.admission_M` set
  `status:active`. [FABLE should-fix 6] the HashSet is rebuilt from HOSTS on startup and updated
  on register/evict.
- `evict_stale(now_h, cfg)` — hosts with `last_hb` older than `3 × interval` → pending/ineligible.
Tests: register pending → M heartbeats → active; bad PoW rejected; RFC1918 ingress rejected under
prod flag; replayed/stale hb_counter rejected; unknown-key heartbeat rejected cheaply; eviction.

## Task 3c — receipts ingest (atomic credit) + counters/tripwire (`lluma-broker`)  [CONTROLLER]

`receipts.rs`:
- **[FABLE must-fix 1,4]** `ingest(submit, cfg) -> IngestOutcome` via **one `Store::with_write`**
  opening RECEIPTS+LEDGER together: `receipt_verify` against the **registered** host's pubkey
  (unknown host ⇒ reject); `spend_id` MUST be present in `SPENT`; **`SPEND_HOST[spend_id]` must
  equal `receipt.host_account`** (should-fix 4 — the spend was forwarded to this host); `units ≤
  cfg.units_audit_cap` (audit only); insert RECEIPTS **only if absent** and in the SAME txn credit
  the host ledger **exactly 1 credit** (never `units`). Returns `Credited`/`AlreadyCredited`/reject.
  Fail closed (no row ⇒ no credit; retryable).
`counters.rs`:
- **[FABLE must-fix 5]** per-token-epoch `issued`/`redeemed`/`trial_granted`. `issued` is bumped in
  the issuer's issuance txn **before signatures are released** (undercount would false-trip the
  alarm). `note_redeem` keys COUNTERS by the **token's epoch** (from key_id). Invariant
  `redeemed ≤ issued`; the **redeem path refuses + alarm-logs** the instant `redeemed > issued`
  (R11 tripwire). Operator-only `GET /admin/invariant` returns status.
Tests: valid receipt credits exactly 1, duplicate ⇒ AlreadyCredited (credited once); receipt with
no burned spend_id rejected; receipt for wrong host (SPEND_HOST mismatch) rejected; wrong-host-key
rejected; a self-dealing loop is zero-sum (earn == spend, no inflation); synthetic extra redeem
trips the alarm and refuses.

## Task 3d — issuer trial-grant endpoint `/v1/register` (`lluma-issuer` + `lluma-broker` store)  [CONTROLLER][FABLE must-fix 3]

New issuer endpoint (relay-routed, gateway-allowlisted — **never** the host-ingress listener; L16):
- `POST /v1/register` accepts `TrialRegisterRequest`; `pow_verify` domain `lluma-pow-trial-v1`;
  one-per-account via TRIAL_ACCTS; global daily budget via TRIAL_BUDGET (uniform fail-closed
  response on exhaustion); grant 20 credits; bump `trial_granted` — **all in one
  `Store::with_write`** (TRIAL_ACCTS+TRIAL_BUDGET+LEDGER+COUNTERS).
- Naming: **issuer trial = `/v1/register`**, **host = `/v1/host/register`** (no collision).
Tests: first register grants 20 + records account + bumps budget; second register for same account
⇒ AlreadyGranted (no double grant); budget exhaustion ⇒ uniform refusal; bad PoW ⇒ reject.

## Task 4 — snapshot build/pad/sign + verify (`lluma-broker` + client verify)  [CONTROLLER pad/sign; GLM scaffold]

`snapshot.rs`:
- `build(active_hosts, header) -> SnapshotBody` — **hosts sorted by `host_account`** (redb key
  order gives this — state it) for determinism.
- `publish() -> SignedSnapshot` — postcard-encode; prepend **fixed-width `u32` length prefix**;
  zero-pad to **exactly 64 KiB**; overflow ⇒ **fail closed + alarm** (no silent growth); sign the
  full padded 64 KiB with the registry key (`snapshot_sign`).
- `verify(registry_pk, signed) -> SnapshotBody` (client-side) — check sig over full bytes, read
  length prefix, strip padding, decode.
- 60 s cadence lives in `main.rs` (tokio interval calling `publish()`); the fn is unit-testable.
Tests: snapshot is exactly 64 KiB; **byte-identical across two builds of the same host set**;
verifies under the registry key, fails under a wrong key; only `active` hosts appear; dropping a
host's heartbeats removes it next build; oversize host set fails closed.

## Task 5 — service wiring: two routers + registry resolver + SSRF-hard forwarder + main  [CONTROLLER]

`service.rs` / `main.rs`:
- **Split ingress (R9):** core router (`/v1/exec`, `GET /v1/snapshot`) and a **separately-bound**
  ingress router (`/v1/host/register`, `/v1/heartbeat`, `/v1/receipt`, `/admin/*`) so a
  heartbeat/receipt flood can't starve redeem.
- `/v1/exec` resolves the host from the **registry** (`HostRow.ingress_addr` for an `active` host);
  **records `SPEND_HOST[spend_id] = host_account` in the same txn as the SPENT insert**
  (should-fix 4). SSRF guard: "exact registered, admission-checked address only" **and [FABLE
  must-fix 7] the forwarding `reqwest::Client` sets `redirect::Policy::none()`** (the merged client
  follows redirects — a registered origin could 302 to an internal address otherwise).
- Migrate the existing slice `/v1/exec` test to a registered active host (or keep
  `StaticHostDirectory` behind a `#[cfg(test)]`/config flag).
- `main.rs`: broker core + mounted #3 gateway (registry-backed origin resolver; issuer paths incl.
  `/v1/register` still allowlisted) + co-located issuer behind the `settle(txn, receipt)` seam (R6).
Tests: `/v1/exec` forwards to a registered active host; refuses pending/unknown host (fail closed);
a registered host that 302-redirects is NOT followed; ingress and core bind independently.

## Task 6 — marquee `tests/broker_e2e.rs` (`lluma-broker`)  [CONTROLLER + test-writer; security assertions by controller]

The four spec §7 scenarios in-process (issuer + broker + 2 stub hosts + client):
1. **Durable-respend inverse:** issue → redeem T1 → drop Store (no graceful close) → reopen file
   → replay T1 ⇒ 409; a pre-restart unspent T2 still redeems.
2. **Earn/spend unlinkability sweep:** full transcripts at issuer `/issue`+`/register` and broker
   redeem+receipt; no shared ≥8-byte substring outside whitelisted publics; no consumer-account
   bytes in any broker record/receipt row. Use **typed crypto-material**, not raw JSON (the
   de-flake fix, commit 7ac83c8).
3. **Matchmaking + accounting loop:** register 2 stub hosts (PoW + admission) → heartbeats →
   snapshot verifies, is fixed size, byte-identical across clients → client picks a host → forwards
   to the live host → spend_id lands in SPENT + SPEND_HOST → host submits a receipt twice ⇒
   credited exactly once (1 credit) → stop host B heartbeats ⇒ next snapshot drops it.
4. **Invariant tripwire:** `redeemed ≤ issued` holds per token-epoch; a synthetic extra redeem trips
   the alarm.

Proptests: ledger never negative under concurrent debits on redb; `SpentSet::insert` returns
`AlreadySpent` exactly once per id across threads; **self-dealing loop never nets positive credit**.

---

## Sequencing
Task 2 → Task 1 → Task 3a → 3b → 3c → 3d → Task 4 → Task 5 → Task 6. Same-crate tasks run
sequentially. Fable **security review** after 3b/3c/3d (the fraud/anti-Sybil core) and after Task 6.
Controller task-review after every task; Fable whole-branch review at the end.
