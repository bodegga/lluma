# lluma-issuer (Token Issuance Loop) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Delegation model for this repo:** each task below is handed to **GLM 5.2 via opencode**
> (`opencode run --auto -m opencode-go/glm-5.2 --dir "C:\Projects\Bodegga\Lluma" "<task>"`) with a
> self-contained delegation brief (this task + Global Constraints + exact APIs). The controller
> (Claude) re-verifies every diff: `cargo test` + `cargo clippy --all-targets -- -D warnings`, and
> spot-checks the privacy assertions. GLM has NO prior context — briefs must be self-contained.

**Goal:** Ship `lluma-issuer` (an axum HTTP service that blind-signs entitlement tokens while debiting a credit balance, and redeems tokens with double-spend protection) plus a client redemption library, proving unlinkable issuance↔redemption end-to-end over a real HTTP wire.

**Architecture:** Thin issuer + trait seams. In-memory `CreditLedger` and `SpentSet` behind traits (#4's broker swaps durable impls later); only the epoch keypair persists to disk. HTTP DTOs live in `lluma_core::proto::v1`; the signed issue-authorization type lives in `lluma_core::wire` with sign/verify in `lluma_crypto::account`. Client and server compose the pure `lluma-crypto` token API over the wire.

**Tech Stack:** Rust, axum + tower (server), reqwest (client, behind `client` feature), tokio, serde/serde_json + base64 (DTOs), postcard (batch hashing), blake3, ed25519 via `lluma-crypto`, `blind-rsa-signatures` via `lluma-crypto`, thiserror, proptest.

**Spec:** `docs/superpowers/specs/2026-07-16-lluma-issuer-design.md` (normative). Read it alongside this plan.

## Global Constraints

- **Privacy invariant:** no single party ever holds both originator IP and prompt plaintext. (Issuer holds neither prompt nor — at redeem — identity.)
- **Unlinkability scope:** #2 proves cryptographic + engineering unlinkability only; network-level (IP) unlinkability is #3. `/redeem` DTO carries **zero identity**.
- **Typed errors** via `thiserror`; **no `unwrap()`/`expect()`** in library code (tests excepted).
- **BLAKE3** for all content addressing (`key_id`, `blinded_batch_hash`, `spend_id`).
- **RNG split (do not assume one shared RNG):** token path uses `blind_rsa_signatures::DefaultRng` (rand_core 0.10); Ed25519/account path uses rand_core 0.6 `OsRng`.
- **L8 (no plaintext/secret leakage):** no error body or log line may interpolate token/blinded/account bytes or inner blind/RSA `Display` strings. Static messages only.
- **DTO discipline:** JSON, byte fields base64; enforce **exact lengths** on deserialize (token = 320 B, 32-B keys/ids, 64-B sigs). Version module as `proto::v1`.
- **Single denomination**, hard-coded constant — no denomination parameter anywhere (leak L6).
- **Key_id** = full 32-byte `BLAKE3(issuer pubkey DER)`, no truncation; client recomputes & pins.
- Run `cargo test` + `cargo clippy --all-targets -- -D warnings` green before any task is done.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Cargo is at `/c/Users/A/.cargo/bin` (prepend to PATH in fresh shells). All Phase-1 crates here are pure Rust — no MSVC env needed.

---

## File Structure

- `crates/lluma-core/src/wire.rs` — ADD `IssueRequestBody`, `IssueSignature`.
- `crates/lluma-core/src/proto.rs` — NEW: `proto::v1` HTTP DTOs (serde + base64 + exact-length).
- `crates/lluma-core/src/lib.rs` — add `pub mod proto;`.
- `crates/lluma-crypto/src/account.rs` — ADD `issue_request_sign` / `issue_request_verify`.
- `crates/lluma-issuer/Cargo.toml` — NEW crate manifest (`client` feature gates reqwest+client.rs).
- `crates/lluma-issuer/src/lib.rs` — module wiring + re-exports.
- `crates/lluma-issuer/src/error.rs` — `IssuerError` + HTTP status/`code` mapping.
- `crates/lluma-issuer/src/ledger.rs` — `CreditLedger` trait + `InMemoryLedger`.
- `crates/lluma-issuer/src/spent_set.rs` — `SpentSet` trait + `InMemorySpentSet`.
- `crates/lluma-issuer/src/idem.rs` — `IssueIdempotencyCache`.
- `crates/lluma-issuer/src/keys.rs` — persist/load epoch keypair (atomic write).
- `crates/lluma-issuer/src/service.rs` — axum router + handlers over the traits.
- `crates/lluma-issuer/src/client.rs` — `[cfg(feature="client")]` reqwest flows.
- `crates/lluma-issuer/src/main.rs` — binary: config + wiring + serve.
- `crates/lluma-issuer/tests/loop_e2e.rs` — marquee unlinkability harness + full-loop tests.
- `Cargo.toml` (workspace) — add `axum`, `tower`, `base64`, `tracing` to `[workspace.dependencies]`.

Dependency order: Task 1 → 2 → (3,4,5,6 independent) → 7 → 8 → 9 → 10.

---

### Task 1: `lluma-core` — issue-auth types + `proto::v1` DTOs + `lluma-crypto` sign/verify

**Files:**
- Modify: `crates/lluma-core/src/wire.rs`
- Create: `crates/lluma-core/src/proto.rs`
- Modify: `crates/lluma-core/src/lib.rs` (add `pub mod proto;`)
- Modify: `crates/lluma-crypto/src/account.rs`
- Test: unit tests inline in `account.rs` (`#[cfg(test)]`) and `proto.rs`.

**Interfaces produced (later tasks rely on these exact names/types):**

```rust
// lluma_core::wire  (append)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRequestBody {
    pub version: u8,                    // = 1
    pub account: [u8; 32],             // signer's own Ed25519 pubkey bytes
    pub key_id: [u8; 32],
    pub request_id: [u8; 32],
    pub ts_unix_s: u64,
    pub blinded_batch_hash: [u8; 32],
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]  // NOT Debug (sig bytes)
pub struct IssueSignature(pub Vec<u8>);   // Ed25519, 64 B

// lluma_crypto::account  (append) — mirror receipt_sign/receipt_verify (account.rs:71–94)
pub fn issue_request_sign(sk: &AccountSecretKey, body: &IssueRequestBody) -> Result<IssueSignature>;
pub fn issue_request_verify(pk: &AccountPublicKey, body: &IssueRequestBody, sig: &IssueSignature) -> Result<()>;

// lluma_core::proto::v1  (new module)
pub const ISSUE_BATCH_MAX: usize = 64;
pub const DENOMINATION: u64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyConfigResponse { pub key_id: [u8;32], pub issuer_public_key: IssuerPublicKey, pub epoch: u64, pub denomination: u64 }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueRequest { pub body: IssueRequestBody, pub blinded: Vec<BlindedTokenRequest>, pub auth_sig: IssueSignature }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueResponse { pub key_id: [u8;32], pub signatures: Vec<BlindSignature> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemRequest { pub key_id: [u8;32], pub token: Token }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemResponse { pub spend_id: SpendId }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRequest { pub account_id: AccountId, pub amount: u64 }
```

**Design notes for the implementer:**
- `issue_request_sign` signs Ed25519 over `b"lluma-issue-request-v1" ‖ postcard::to_allocvec(body)`, exactly mirroring `receipt_sign`'s domain-separated construction (reuse the `signing_key(sk)` helper). Use a **distinct domain string** from the receipt one — do not share.
- Byte fields (`IssuerPublicKey`, `BlindedTokenRequest`, `BlindSignature`, `Token` are `Vec<u8>` newtypes; `SpendId`/`AccountId` are `[u8;32]`) serialize via serde. Add base64 for the JSON representation using serde helpers, or rely on serde_json's default array encoding **only if** you add explicit length validation on deserialize. Preferred: `#[serde(with=...)]` base64 for `Vec<u8>`/`[u8;32]` fields plus a `validate()` that checks lengths (token 320, keys 32, sig 64) and returns `CoreError`/`CryptoError`.
- Do not add axum/reqwest deps to `lluma-core` — DTOs are serde-only.

**Steps (TDD):**
- [ ] **Step 1 — failing test (account):** `issue_request_sign` then `issue_request_verify` round-trips; a tampered `body.key_id` fails verify; a signature from account A fails under account B's pubkey. Write these in `account.rs` `#[cfg(test)]`.
- [ ] **Step 2 — run, expect FAIL** (`cargo test -p lluma-crypto issue_request`) — undefined fns.
- [ ] **Step 3 — implement** `IssueRequestBody`/`IssueSignature` in `wire.rs`; `issue_request_sign`/`verify` in `account.rs`.
- [ ] **Step 4 — failing test (proto):** each DTO round-trips through `serde_json`; a `RedeemRequest` with a 319-byte token fails to deserialize; a `KeyConfigResponse` with a 31-byte `key_id` fails.
- [ ] **Step 5 — run, expect FAIL.**
- [ ] **Step 6 — implement** `proto.rs` with base64 + length validation; wire `pub mod proto;`.
- [ ] **Step 7 — run all:** `cargo test -p lluma-crypto -p lluma-core` PASS; `cargo clippy -p lluma-crypto -p lluma-core --all-targets -- -D warnings` clean.
- [ ] **Step 8 — commit:** `feat(core,crypto): issue-auth signature + proto::v1 issuer DTOs`.

---

### Task 2: `lluma-issuer` scaffold + `IssuerError`

**Files:**
- Create: `crates/lluma-issuer/Cargo.toml`, `crates/lluma-issuer/src/lib.rs`, `crates/lluma-issuer/src/error.rs`
- Test: inline in `error.rs`.

**Cargo.toml:**
```toml
[package]
name = "lluma-issuer"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
lluma-core = { path = "../lluma-core" }
lluma-crypto = { path = "../lluma-crypto" }
axum = "0.7"
tower = "0.5"
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
blake3 = { workspace = true }
postcard = { workspace = true }
thiserror = { workspace = true }
tracing = "0.1"
blind-rsa-signatures = { workspace = true }
reqwest = { workspace = true, optional = true }
base64 = "0.22"

[features]
default = ["client"]
client = ["dep:reqwest"]

[dev-dependencies]
proptest = { workspace = true }
tokio = { workspace = true }
```
(Add `axum="0.7"`, `tower="0.5"`, `base64="0.22"`, `tracing="0.1"` to workspace `[workspace.dependencies]` and reference via `workspace = true` if preferred; either is acceptable so long as `cargo` resolves cleanly.)

**Interfaces produced:**
```rust
#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("insufficient credits")] InsufficientCredits,
    #[error("unauthorized")] Unauthorized,
    #[error("token invalid")] TokenInvalid,
    #[error("double spend")] DoubleSpend,
    #[error("request id conflict")] RequestIdConflict,
    #[error("bad request")] BadRequest,
    #[error("internal error")] Internal,   // maps ALL CryptoError; never surfaces inner Display
}
impl IssuerError {
    pub fn code(&self) -> &'static str;    // insufficient_credits | unauthorized | token_invalid | double_spend | request_id_conflict | bad_request | internal
    pub fn status(&self) -> u16;           // 402 | 403 | 422 | 409 | 409 | 422 | 500
}
impl From<lluma_crypto::CryptoError> for IssuerError { fn from(_: lluma_crypto::CryptoError) -> Self { IssuerError::Internal } }
```
- **L8:** the `From<CryptoError>` impl must drop the inner error entirely (map to `Internal`) — do NOT `#[from]` it in a way that keeps its `Display`.

**Steps (TDD):**
- [ ] **Step 1 — failing test:** assert `IssuerError::DoubleSpend.status() == 409 && .code() == "double_spend"` and the same for each variant; assert `IssuerError::from(some CryptoError).code() == "internal"`.
- [ ] **Step 2 — run, expect FAIL** (crate doesn't compile yet).
- [ ] **Step 3 — implement** Cargo.toml, `lib.rs` (`pub mod error;` + re-export `IssuerError`), `error.rs`.
- [ ] **Step 4 — run:** `cargo test -p lluma-issuer` PASS; `cargo clippy -p lluma-issuer --all-targets -- -D warnings` clean.
- [ ] **Step 5 — commit:** `feat(issuer): crate scaffold + typed IssuerError (L8-safe)`.

---

### Task 3: `CreditLedger` + `InMemoryLedger` (atomic debit)

**Files:** Create `crates/lluma-issuer/src/ledger.rs`; add `pub mod ledger;` to `lib.rs`. Test inline.

**Interfaces produced:**
```rust
pub trait CreditLedger: Send + Sync {
    fn balance(&self, account: &AccountId) -> u64;
    fn grant(&self, account: &AccountId, amount: u64);
    fn debit(&self, account: &AccountId, amount: u64) -> Result<(), IssuerError>; // Err(InsufficientCredits) if balance < amount
}
#[derive(Default)]
pub struct InMemoryLedger { /* Mutex<HashMap<AccountId,u64>> */ }
impl InMemoryLedger { pub fn new() -> Self }
```
- `debit` must be **atomic**: lock once, check-and-subtract under the same guard. No `balance()`-then-`debit()` race.

**Steps (TDD):**
- [ ] **Step 1 — failing tests:** grant 5 → balance 5; debit 3 → Ok, balance 2; debit 3 → Err(InsufficientCredits), balance still 2; debit 2 → Ok, balance 0. Plus a proptest: N concurrent `debit(1)` on a balance of M never drives balance below 0 and succeeds exactly `min(N,M)` times (use threads + `Arc`).
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement** with a `std::sync::Mutex<HashMap<AccountId,u64>>`.
- [ ] **Step 4 — run:** PASS; clippy clean.
- [ ] **Step 5 — commit:** `feat(issuer): CreditLedger trait + atomic InMemoryLedger`.

---

### Task 4: `SpentSet` + `InMemorySpentSet` (atomic check-and-set)

**Files:** Create `crates/lluma-issuer/src/spent_set.rs`; add `pub mod spent_set;`. Test inline.

**Interfaces produced:**
```rust
#[derive(Debug, PartialEq, Eq)]
pub enum InsertOutcome { Inserted, AlreadySpent }
pub trait SpentSet: Send + Sync {
    fn insert(&self, id: SpendId) -> InsertOutcome;   // atomic: single map/set op
}
#[derive(Default)]
pub struct InMemorySpentSet { /* Mutex<HashSet<SpendId>> */ }
impl InMemorySpentSet { pub fn new() -> Self }
```
- `insert` returns `Inserted` the first time and `AlreadySpent` every time after, atomically (`HashSet::insert` under one guard).

**Steps (TDD):**
- [ ] **Step 1 — failing tests:** first insert → `Inserted`; second insert of same id → `AlreadySpent`; different id → `Inserted`. Proptest: across concurrent inserts of the same id, exactly one thread observes `Inserted`.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement.**
- [ ] **Step 4 — run:** PASS; clippy clean.
- [ ] **Step 5 — commit:** `feat(issuer): SpentSet trait + atomic InMemorySpentSet`.

---

### Task 5: `IssueIdempotencyCache`

**Files:** Create `crates/lluma-issuer/src/idem.rs`; add `pub mod idem;`. Test inline.

**Interfaces produced:**
```rust
pub enum IdemLookup { Fresh, Replay(IssueResponse), Conflict }
pub struct IssueIdempotencyCache { /* Mutex<HashMap<(AccountId,[u8;32]), (blinded_batch_hash,[u8;32], IssueResponse)>> */ }
impl IssueIdempotencyCache {
    pub fn new() -> Self;
    /// Look up (account, request_id). Fresh if unseen; Replay(resp) if seen with SAME batch hash;
    /// Conflict if seen with a DIFFERENT batch hash.
    pub fn lookup(&self, account: &AccountId, request_id: &[u8;32], batch_hash: &[u8;32]) -> IdemLookup;
    /// Record a completed response under (account, request_id, batch_hash).
    pub fn store(&self, account: &AccountId, request_id: [u8;32], batch_hash: [u8;32], resp: IssueResponse);
}
```
- TTL/eviction is bounded by the ±10-min `ts` window enforced in the handler (Task 7); a simple map is acceptable for #2 (note in code that #4 adds real TTL eviction). Do not implement a background reaper.

**Steps (TDD):**
- [ ] **Step 1 — failing tests:** unseen → `Fresh`; after `store`, same (account,request_id,hash) → `Replay(resp)` with equal signatures; same (account,request_id) different hash → `Conflict`.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement.**
- [ ] **Step 4 — run:** PASS; clippy clean.
- [ ] **Step 5 — commit:** `feat(issuer): issue idempotency cache`.

---

### Task 6: `keys.rs` — persist/load epoch keypair (atomic)

**Files:** Create `crates/lluma-issuer/src/keys.rs`; add `pub mod keys;`. Test inline (use a temp dir).

**Interfaces produced:**
```rust
pub struct EpochKeys { pub epoch: u64, pub secret: IssuerSecretKey, pub public: IssuerPublicKey }
impl EpochKeys {
    /// key_id = BLAKE3(public DER), full 32 bytes.
    pub fn key_id(&self) -> [u8;32];
}
/// Load epoch keys from `path`; if absent, generate (issuer_keygen with DefaultRng), persist, return.
pub fn load_or_create(path: &std::path::Path, epoch: u64) -> Result<EpochKeys, IssuerError>;
```
- On-disk format: JSON `{ epoch, sk_der(base64), pk_der(base64) }`. **Atomic write:** write to `path.tmp` then `rename` over `path`.
- Uses `lluma_crypto::issuer_keygen(&mut blind_rsa_signatures::DefaultRng)` — the RNG-split constraint. Do NOT use rand_core 0.6 `OsRng` here.
- Restrictive file perms best-effort; note in code that plaintext-on-disk is acceptable for MVP (compromise = credit-integrity failure, not deanonymization; spec §8/§11).

**Steps (TDD):**
- [ ] **Step 1 — failing tests:** `load_or_create` on empty temp path creates a file and returns keys whose `key_id() == BLAKE3(pubkey DER)`; a second `load_or_create` on the same path returns **byte-identical** keys (same key_id); a token issued+unblinded under the first load `token_verify`s under the reloaded pubkey.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement** (atomic temp+rename).
- [ ] **Step 4 — run:** PASS; clippy clean.
- [ ] **Step 5 — commit:** `feat(issuer): persistent epoch keypair (atomic write)`.

---

### Task 7: `service.rs` — axum router + handlers

**Files:** Create `crates/lluma-issuer/src/service.rs`; add `pub mod service;`. Test inline using `tower::ServiceExt::oneshot` (no network needed).

**Interfaces produced:**
```rust
pub struct AppState {
    pub keys: std::sync::Arc<EpochKeys>,
    pub ledger: std::sync::Arc<dyn CreditLedger>,
    pub spent: std::sync::Arc<dyn SpentSet>,
    pub idem: std::sync::Arc<IssueIdempotencyCache>,
    pub admin_secret: std::sync::Arc<String>,
    pub now_unix_s: fn() -> u64,     // injectable clock for tests
}
pub fn router(state: AppState) -> axum::Router;   // routes below
```
Routes: `GET /v1/key-config`, `POST /v1/issue`, `POST /v1/redeem`, `POST /v1/admin/grant`.

**Handler logic (normative — spec §5, §6, §7):**
- **key-config:** return `KeyConfigResponse { key_id: keys.key_id(), issuer_public_key: keys.public.clone(), epoch: keys.epoch, denomination: DENOMINATION }`.
- **issue** (order exactly per spec §6):
  1. Deserialize `IssueRequest` via a wrapper extractor that maps any rejection → 422 `bad_request` (do NOT use bare `Json<T>`; wrap so serde error text never reaches the body — L8).
  2. `issue_request_verify(&AccountPublicKey(body.account.to_vec()), &body, &auth_sig)` → 403 `unauthorized`.
  3. `|now - body.ts_unix_s| <= 600` → else 422 `bad_request`.
  4. `body.key_id == keys.key_id()` and `blake3(postcard(&blinded)) == body.blinded_batch_hash` → else 422.
  5. `1 ..= ISSUE_BATCH_MAX contains blinded.len()` → else 422.
  6. `account_id = account_fingerprint(&AccountPublicKey(body.account…))`; `idem.lookup(account_id, body.request_id, body.blinded_batch_hash)`: `Replay(r)`→return r; `Conflict`→409 `request_id_conflict`; `Fresh`→continue.
  7. `ledger.debit(&account_id, blinded.len() as u64)` → 402 on `InsufficientCredits`.
  8. For each `b` in `blinded`: `token_issue(&mut DefaultRng, &keys.secret, b)` in order → collect `signatures`. On any Err: `ledger.grant(&account_id, blinded.len())` (refund) then 500 `internal`.
  9. `resp = IssueResponse { key_id: keys.key_id(), signatures }`; `idem.store(...)`; return resp.
- **redeem:**
  1. Wrapped extractor → 422 on malformed.
  2. `req.key_id == keys.key_id()` → else 422 `token_invalid` (cross-key isolation).
  3. `token_verify(&keys.public, &req.token)` → else 422 `token_invalid`.
  4. `spend_id = token_spend_id(&req.token)`; `spent.insert(spend_id)`: `AlreadySpent`→409 `double_spend`; `Inserted`→return `RedeemResponse { spend_id }`.
- **admin/grant:** require header `x-admin-secret == admin_secret` → else 403; `ledger.grant(&req.account_id, req.amount)`; 200.
- **Error rendering:** a single `IntoResponse` for `IssuerError` emitting `{ "code": <code>, "message": <static Display> }` with `.status()`. No request bytes in any body. No body logging in any layer.

**Steps (TDD):** write handler tests against `router(state).oneshot(request)` with an injected fixed clock and freshly-built in-memory state:
- [ ] **Step 1 — failing tests:** (a) key-config returns key_id == BLAKE3(pubkey); (b) full happy issue (grant 10, valid signed batch of 3) → 200 with 3 signatures, ledger balance 7; (c) issue beyond balance → 402; (d) bad `auth_sig` → 403; (e) stale `ts` → 422; (f) wrong `blinded_batch_hash` → 422; (g) batch of 0 and of 65 → 422; (h) replay same request_id+hash → identical body, balance debited once; (i) same request_id different hash → 409; (j) redeem valid token → 200 spend_id; (k) redeem same token twice → second 409; (l) redeem token with wrong key_id → 422; (m) tampered token → 422; (n) grant without admin secret → 403.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement** router + handlers + `IntoResponse`.
- [ ] **Step 4 — run:** PASS; clippy clean.
- [ ] **Step 5 — commit:** `feat(issuer): axum router + issue/redeem/key-config/grant handlers`.

---

### Task 8: `client.rs` — redemption client (feature = "client")

**Files:** Create `crates/lluma-issuer/src/client.rs` gated `#[cfg(feature = "client")]`; add `#[cfg(feature="client")] pub mod client;`. Test inline against an in-process server (`axum::serve` on `TcpListener` bound to `127.0.0.1:0`).

**Interfaces produced:**
```rust
pub struct IssuerClient { /* base_url, reqwest::Client */ }
impl IssuerClient {
    pub fn new(base_url: impl Into<String>) -> Self;                    // its own reqwest::Client
    pub async fn fetch_key_config(&self) -> Result<KeyConfigResponse, IssuerError>; // recompute+verify key_id==BLAKE3(pk); else BadRequest
    /// Blind `count` nonces against `pk`, sign the batch with `account_sk`, POST /issue, unblind → tokens.
    pub async fn request_tokens(&self, kc: &KeyConfigResponse, account_sk: &AccountSecretKey, account_pk: &AccountPublicKey, count: usize) -> Result<Vec<Token>, IssuerError>;
}
/// A SEPARATE type/client for redemption — must NOT reuse the issue client's reqwest::Client (transport-linkage, spec §9).
pub struct RedeemClient { /* base_url, reqwest::Client */ }
impl RedeemClient {
    pub fn new(base_url: impl Into<String>) -> Self;                    // its own reqwest::Client, minimal fixed headers
    pub async fn redeem(&self, key_id: [u8;32], token: Token) -> Result<SpendId, IssuerError>;
}
```
- `request_tokens`: for each of `count`, `token_blind(&mut DefaultRng, &kc.issuer_public_key)` → collect `(state_i, blinded_i)`; `blinded_batch_hash = blake3(postcard(&blinded))`; build `IssueRequestBody { version:1, account: account_pk bytes, key_id: kc.key_id, request_id: random 32B, ts_unix_s: now, blinded_batch_hash }`; `auth_sig = issue_request_sign(account_sk, &body)`; POST; then `token_unblind(&kc.issuer_public_key, state_i, &sig_i)` per position.
- Map non-2xx responses to `IssuerError` by the `code` field.
- **Transport separation is a hard requirement:** `IssuerClient` and `RedeemClient` each construct their own `reqwest::Client`; never share one.

**Steps (TDD):**
- [ ] **Step 1 — failing tests:** spin an in-process server; `fetch_key_config` returns kc and rejects a doctored key_id; `request_tokens(count=4)` returns 4 tokens that each `token_verify` under `kc.issuer_public_key`; `RedeemClient::redeem` on each → Ok(spend_id); redeem again → Err(DoubleSpend).
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement** both clients.
- [ ] **Step 4 — run:** `cargo test -p lluma-issuer` PASS; `cargo clippy -p lluma-issuer --all-targets --all-features -- -D warnings` clean; also `cargo build -p lluma-issuer --no-default-features` (server-only, no reqwest) must compile.
- [ ] **Step 5 — commit:** `feat(issuer): redemption client (separate issue/redeem HTTP clients)`.

---

### Task 9: `main.rs` — binary

**Files:** Create `crates/lluma-issuer/src/main.rs`.

**Behavior:** read config from env with defaults — `LLUMA_ISSUER_BIND` (default `127.0.0.1:8781`), `LLUMA_ISSUER_KEY_PATH` (default `./issuer-key.json`), `LLUMA_ISSUER_EPOCH` (default `1`), `LLUMA_ISSUER_ADMIN_SECRET` (required; refuse to start if empty). Build `AppState` with `load_or_create`, `InMemoryLedger`, `InMemorySpentSet`, `IssueIdempotencyCache`, `now_unix_s = || SystemTime::now()...`; `axum::serve(TcpListener::bind(bind), router(state))`. Init `tracing_subscriber` with **no body logging**. No `unwrap` outside `main`'s top-level `?`.

**Steps:**
- [ ] **Step 1 — implement** `main.rs` (no separate unit test; covered by Task 10 e2e).
- [ ] **Step 2 — run:** `cargo build -p lluma-issuer` OK; `cargo clippy -p lluma-issuer --all-targets --all-features -- -D warnings` clean; smoke: start with a test admin secret, `curl /v1/key-config` returns JSON (controller verifies).
- [ ] **Step 3 — commit:** `feat(issuer): server binary + env config`.

---

### Task 10: `tests/loop_e2e.rs` — marquee unlinkability harness + full loop

**Files:** Create `crates/lluma-issuer/tests/loop_e2e.rs`.

**Setup:** a helper spins the real `router` via `axum::serve` on `127.0.0.1:0`, returns base URL; a **logging wrapper** records every `/issue` and `/redeem` request+response transcript (implement as a `tower` layer capturing raw JSON bytes, or an in-test `Arc<Mutex<Vec<Transcript>>>` populated by wrapping the handlers). Two accounts A, B via `account_mnemonic_new`/`derive_keypair_from_seed`.

**Required tests (spec §9):**
- [ ] **Full happy loop:** grant → fetch+pin key-config → `request_tokens(10)` → redeem all 10 → all Ok.
- [ ] **Unlinkability (two-account interleaved):** A and B each issue a batch, then redeem all tokens **shuffled** (deterministic shuffle, no `rand` on the token bytes). Assertions over the logged transcripts:
  - **Byte-disjointness:** no ≥8-byte substring shared between any issue-side record and any redeem-side record, excluding whitelisted constants (`key_id`, issuer pubkey DER, denomination bytes).
  - **Derivability sweep:** for every redeemed `spend_id`, assert `spend_id != blake3(x)` for every `x` the issuer saw at issue time (each blinded msg, each blind sig, each account pubkey, each batch hash).
  - **Structural sweep:** every `/redeem` request+response byte-buffer contains neither account's pubkey/account_id bytes nor either `IssueSignature`.
- [ ] **Transport separation:** assert issue and redeem go through distinct `reqwest::Client`s (by construction in the harness; document the invariant).
- [ ] **Double-spend:** redeem a token twice → second `DoubleSpend`.
- [ ] **Balance enforced:** `request_tokens` beyond granted balance → `InsufficientCredits`.
- [ ] **Idempotency:** replay identical `/issue` (same request_id+hash via a hand-built request) → identical signatures, balance debited once; different hash → `RequestIdConflict`; stale ts → `BadRequest`.
- [ ] **Tamper:** mutate a token byte → redeem `TokenInvalid`.
- [ ] **Cross-key isolation:** token minted by issuer-A fails redeem at issuer-B (second server, different key path).
- [ ] **key-config integrity:** A and B receive byte-identical key-config; client rejects a key-config whose `key_id != BLAKE3(pubkey)`.
- [ ] **L8:** every captured error-response body contains no token/blinded/account bytes and no interpolated request data.
- [ ] **Restart-respend hole (must demonstrate):** redeem a token → drop+rebuild the server from the **same key path** (fresh in-memory spent-set) → the same token redeems **again** successfully. Assert it, with a comment: "documents the #4 durable-spent-set blocker (spec §11)."

**Steps:**
- [ ] **Step 1 — write all tests** (they compile against Tasks 1–9).
- [ ] **Step 2 — run:** `cargo test -p lluma-issuer --all-features` — expect the restart-respend test to PASS (it asserts the hole) and all others PASS.
- [ ] **Step 3 — full gate:** `cargo test` (workspace) + `cargo clippy --all-targets --all-features -- -D warnings` green.
- [ ] **Step 4 — commit:** `test(issuer): end-to-end loop + unlinkability harness + restart-hole`.

---

## Self-Review

**Spec coverage:** §1 goal → Tasks 8/10; §2 threat model → §9 tests + L8 (Task 7); §3 decisions → Tasks 3/4/6 (traits, in-mem, persisted key); §4 layout → all tasks; §5.1 issue-auth sig → Task 1; §5.2 endpoints → Task 7; §5.3 replay/idempotency → Tasks 5/7; §6 handler order → Task 7; §7 errors → Task 2 + Task 7 rendering; §8 trait seams → Tasks 3/4; §9 tests → Task 10; §10 non-negotiables → Global Constraints; §11 leak addenda → recorded in spec (ADR amend is a doc follow-up, not code); §12 YAGNI → respected (no OHTTP, no session key, no durable store). **Gap noted:** amending ADR-0001's leak register (L1/L2 addenda) is a docs task — fold into Task 10's commit or a trailing docs commit.

**Placeholder scan:** no TBD/TODO; every interface has concrete signatures; test intents have concrete assertions. (Production bodies are implemented by GLM from these signatures + spec — the delegation model; the plan fixes the contract, not every line.)

**Type consistency:** `key_id: [u8;32]` everywhere; `SpendId`/`AccountId` are `[u8;32]` (per wire.rs); `IssueResponse` shape identical in Tasks 1/5/7/8; `InsertOutcome`/`IdemLookup` names stable; `DefaultRng` used in every token/keygen path, never `OsRng`.

## Execution Handoff

Execution uses **GLM 5.2 via opencode** per task (this repo's delegation model), with the controller reviewing every diff between tasks — the subagent-driven-development pattern with GLM as the implementer.
