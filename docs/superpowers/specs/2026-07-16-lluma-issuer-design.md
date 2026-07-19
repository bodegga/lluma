# Lluma Phase 1 · Sub-project #2 — Token Issuance Loop (`lluma-issuer` + client redemption) Design Spec

> The first networking sub-project: prove **unlinkable issuance↔redemption end-to-end over a real HTTP wire**.
> A **Bodegga** project.

- **Status:** Proposed (pre-implementation)
- **Date:** 2026-07-16
- **Author:** Bodegga / Lluma (design ruled by Fable; see §12 for the ruling provenance)
- **Parent design:** [`2026-07-14-lluma-design.md`](2026-07-14-lluma-design.md) (§5 request lifecycle, §8 accounting)
- **Consumes:** [`2026-07-15-lluma-crypto-design.md`](2026-07-15-lluma-crypto-design.md) and [ADR-0001](../../architecture/adr-0001-lluma-crypto-primitives.md) (leak register L1–L8). This spec does **not** re-litigate primitive choices; it composes the `lluma-crypto` public API over a wire.

---

## 1. Summary & role in Phase 1

Phase 1 (the anonymity MVP) is five sub-projects, each its own spec → plan → build cycle. #1 (`lluma-crypto`) is DONE and merged. This is **#2**:

- **`lluma-issuer`** — an HTTP service that blind-signs entitlement tokens while debiting a credit balance, and verifies/redeems tokens with double-spend protection.
- **client redemption** — the client-side flow that blinds nonces, obtains blind signatures, unblinds them into tokens, and later redeems them.

**Goal / definition of done:** a client blinds nonces, the issuer blind-signs them while debiting a credit balance, the client unblinds into tokens, and later redeems each token at the issuer, which verifies it and rejects double-spends — with **no field or transport artifact linking a redeemed token back to the account it was issued to**.

**Scope of the unlinkability claim (stated honestly):** #2 proves **cryptographic unlinkability** (RFC 9474 blinding — a malicious, fully-logging issuer cannot correlate issue↔redeem) plus **engineering unlinkability** (the redeem DTO carries zero identity; issue and redeem never share a TCP connection or HTTP client). #2 does **not** provide **network-level** unlinkability against a global observer or an issuer that correlates by source IP/timing: in #2 the client hits `/redeem` directly, so the issuer sees the redeemer's IP. That is acceptable **only** because #2 is a test topology; production redemption traverses the relay (sub-project #3). This limit is called out again in §8 and §11.

## 2. Threat model for #2

The issuer is **trusted for credit integrity, not for anonymity.**

- At `/issue` it legitimately sees `{account public key, N blinded blobs}` — issuance is the *identified* side of the protocol.
- At `/redeem` it must see `{key_id, token}` and nothing else.
- RFC 9474 blinding makes cryptographic linkage impossible **even for a malicious issuer that logs everything**. Therefore every residual linkage risk in #2 is **engineering, not crypto**:
  1. transport-layer linkage (same TCP connection / HTTP client / IP for issue and redeem),
  2. DTO regressions that smuggle identity into `/redeem`,
  3. timing/count correlation (leak L4),
  4. log/error-body leakage (leak L8).
- Out of scope for #2's threat model: a network adversary observing source IPs (→ #3 relay), and durable double-spend across issuer restarts (→ #4 broker; see §11).

## 3. Decisions locked with the user

- **Scope:** thin issuer + trait seams. The issuer owns a minimal **in-memory** credit balance (`CreditLedger` trait) that `/issue` debits, and a minimal **in-memory** spent-set (`SpentSet` trait) that `/redeem` checks. #4's broker later swaps in durable implementations without changing the interfaces. NOT full accounting now; NOT issuance-only.
- **Transport:** axum (server) + reqwest (client). `tokio` and `reqwest` are already workspace deps; axum + tower are added.
- **Persistence:** in-memory balances + spent-set; **only the issuer epoch keypair persists to disk** (atomic write) so tokens survive a restart.

## 4. Crate & module layout

```
crates/lluma-issuer/
├─ Cargo.toml           # server deps always; client + reqwest behind `client` feature
└─ src/
   ├─ lib.rs            # module wiring + re-exports; crate docs
   ├─ error.rs          # IssuerError (thiserror) + HTTP status/code mapping (L8-safe)
   ├─ ledger.rs         # CreditLedger trait + InMemoryLedger (atomic debit)
   ├─ spent_set.rs      # SpentSet trait (atomic check-and-set) + InMemorySpentSet
   ├─ idem.rs           # IssueIdempotencyCache: (account_id, request_id) -> cached response, TTL
   ├─ keys.rs           # persist/load issuer epoch keypair {epoch, sk_der, pk_der}, atomic
   ├─ service.rs        # axum router + handlers, generic over the traits
   ├─ client.rs         # [feature = "client"] reqwest flows: fetch_key_config/request_tokens/redeem_token
   └─ main.rs           # binary: config, wire InMemory impls + keys, serve
 tests/
   └─ loop_e2e.rs       # full loop + unlinkability harness + double-spend + balance + tamper + cross-key + restart

crates/lluma-core/src/
   ├─ wire.rs           # ADD: IssueRequestBody, IssueSignature (signed-auth types; §5.1)
   └─ proto.rs          # NEW: proto::v1 HTTP DTOs (serde, base64 byte fields, exact-length checks)
```

Rationale for the two adjustments Fable ruled: `client.rs` behind a `client` cargo feature so the future `lluma-client` (#5) can depend on this crate's client without dragging in axum; `keys.rs` (not `keystore.rs`) because it persists a DER epoch keypair and shares nothing with the passphrase-sealed **keystore** in `lluma-crypto` — the name collision would mislead. `CreditLedger`/`SpentSet` live in `lluma-issuer`, **not** in core: #4 swaps impls, not interfaces.

## 5. Protocol

All HTTP DTOs live in `lluma_core::proto::v1`, serde JSON, byte fields base64-encoded, **exact lengths enforced on deserialize** (token = 320 B, keys = 32 B — mirror the length checks already in `tokens.rs::split_token`). Errors are §7.

### 5.1 Issue authorization (signed body) — `lluma-crypto` addition

`/issue` must be authenticated so a client can only debit **its own** balance, without introducing a generic account signer (which would break ADR-0001 §4.3's property that the set of things an account key can sign is enumerable). We add a **purpose-typed, domain-separated** signature that mirrors `receipt_sign`:

```rust
// lluma_core::wire
pub struct IssueRequestBody {
    pub version: u8,                    // = 1
    pub account: [u8; 32],             // signer's own Ed25519 pubkey (anti-substitution)
    pub key_id: [u8; 32],              // epoch binding: auth cannot replay across epochs
    pub request_id: [u8; 32],          // client-random; idempotency key (§5.3)
    pub ts_unix_s: u64,                // coarse freshness window (identified side — L4 N/A)
    pub blinded_batch_hash: [u8; 32],  // BLAKE3(postcard(Vec<BlindedTokenRequest>))
}
pub struct IssueSignature(pub Vec<u8>);   // Ed25519, 64 B; not Debug-sensitive

// lluma_crypto::account  (mirrors receipt_sign/receipt_verify at account.rs:71–94)
pub fn issue_request_sign(sk: &AccountSecretKey, body: &IssueRequestBody) -> Result<IssueSignature>;
pub fn issue_request_verify(pk: &AccountPublicKey, body: &IssueRequestBody, sig: &IssueSignature) -> Result<()>;
```

- **Domain string:** `b"lluma-issue-request-v1"`; sign Ed25519 over `domain ‖ postcard(body)` — identical construction to `receipt_sign`.
- `blinded_batch_hash` binds the debit to this exact batch (an attacker who captures the request cannot strip the signature and attach their own blinded messages).
- `key_id` prevents cross-epoch replay; `request_id` + `ts_unix_s` handle same-epoch replay (§5.3).
- **RNG note (restate verbatim in GLM's brief):** the token path uses `blind_rsa_signatures::DefaultRng` (rand_core 0.10 split); the Ed25519/account path uses rand_core 0.6 `OsRng`. Do not assume one shared RNG. (ADR-0001; bit us in #1.)

### 5.2 Endpoints

**`GET /v1/key-config`** → `KeyConfigResponse { key_id: [u8;32], issuer_public_key: IssuerPublicKey, epoch: u64, denomination: u64 }`.
- `key_id = BLAKE3(issuer_public_key DER)`, **full 32 bytes, no truncation** (avoids per-epoch collision analysis; display truncation is a UI concern, same rule as `account_fingerprint`).
- Single fixed `denomination` **constant** — no denomination parameter anywhere (leak L6: variable denominations partition the anonymity set).
- **Client MUST recompute** `key_id == BLAKE3(pubkey)` from the returned pubkey rather than trust the server's claimed `key_id`, and pin/cache it. A per-user key-config is the L2-fatal attack; the harness asserts all clients receive byte-identical key-config.

**`POST /v1/issue`** → `IssueRequest { body: IssueRequestBody, blinded: Vec<BlindedTokenRequest>, auth_sig: IssueSignature }` → `IssueResponse { key_id: [u8;32], signatures: Vec<BlindSignature> }`.
- Handler order (§6) validates everything, then debits+signs atomically; signatures returned **positionally matching** the request order.
- Batch: client default **N = 10**; server hard cap **N ≤ 64** (each `token_issue` ≈ 1 ms RSA; unbounded batch is a CPU-DoS vector). `blinded.len()` must equal the count implied by `blinded_batch_hash` (recompute and compare).

**`POST /v1/redeem`** → `RedeemRequest { key_id: [u8;32], token: Token }` → `RedeemResponse { spend_id: SpendId }`.
- Carries **no identity** — this is the unlinkability guarantee expressed in the wire format.
- `token_verify(pk_for(key_id), &token)?` → else 422 `TokenInvalid`; `spend_id = token_spend_id(&token)`; `SpentSet::insert(spend_id)` atomic check-and-set → `AlreadySpent` → 409 `DoubleSpend`, echoing **only** `spend_id`.
- Response is `{spend_id}` **only** — no timestamps, counters, or server identifiers that could later be echoed into receipts (leak L4). Strict at-most-once: **no idempotency keying** (there is no identity to key on safely; a "replay returns ok" design would hand success to eavesdroppers). Retry-safety for the legitimate holder comes later from the AAD contract (spend_id bound into the e2e seal — #4/#5 wiring), not from #2.

**`POST /v1/admin/grant`** → `GrantRequest { account_id: AccountId, amount: u64 }` → seeds the trial-grant balance.
- Bound to **loopback** by default; shared secret from config (never logged). Minimal — no roles/quotas. Stand-in for #4's contribution-earned credits and trial-grant anti-Sybil policy (explicitly deferred to the broker).

### 5.3 Replay & idempotency

- **`/issue` replay = idempotency cache, not nonce-reject.** Replaying a captured `/issue` cannot steal tokens (no `BlindingState`), but it drains the victim's balance. The issuer keeps `(account_id, request_id) → cached IssueResponse` with a TTL. Duplicate `request_id` **with the same `blinded_batch_hash`** → replay the cached response (this doubles as safe client retry after a lost response). Same `request_id`, **different** hash → 409 `RequestIdConflict`. Reject `ts_unix_s` outside **±10 min** so the cache is bounded and eviction cannot reopen the replay window.
- **`/redeem` replay = rejected** (strict at-most-once, §5.2).

## 6. `/issue` handler ordering (atomicity)

1. Parse & length-check DTO (wrapped extractor rejection → generic 422; §7).
2. `issue_request_verify(&body.account, &body, &auth_sig)` → 403 on failure.
3. Check `ts_unix_s` within ±10 min → 422 if stale/future.
4. Recompute `BLAKE3(postcard(blinded)) == body.blinded_batch_hash` and `body.key_id == current key_id` → 422 on mismatch.
5. Check batch size `1 ≤ N ≤ 64` → 422.
6. Idempotency: look up `(account_id, request_id)`; on hit with matching hash → return cached response; on hit with differing hash → 409.
7. **Single atomic ledger op:** `CreditLedger::debit(account_id, N)` (must be atomic w.r.t. concurrent `/issue` for the same account — no check-then-debit overdraft race) → 402 `InsufficientCredits` if balance < N.
8. `token_issue(rng, &sk, &b)` for each `b` in order; on any signature failure, **refund** the debit and 500 (post-validation failure should be unreachable).
9. Cache the response under `(account_id, request_id)`; return it.

## 7. Error handling (L8-safe)

`IssuerError` via `thiserror`, mapped to HTTP status + a machine-readable `code`:

| Variant | Status | `code` |
|---|---|---|
| `InsufficientCredits` | 402 | `insufficient_credits` |
| `Unauthorized` (bad/absent sig, bad admin secret) | 403 | `unauthorized` |
| `TokenInvalid` | 422 | `token_invalid` |
| `DoubleSpend` | 409 | `double_spend` |
| `RequestIdConflict` | 409 | `request_id_conflict` |
| `BadRequest` (malformed, stale ts, batch bounds, hash mismatch) | 422 | `bad_request` |
| `Crypto(CryptoError)` | 500 | `internal` |

- Error bodies contain `{ code, message }` where `message` is a **static** string. **No variant may interpolate request bytes** (L8). `#[from] CryptoError` is allowed for control flow, but the inner blind/RSA `Display` string is **never** written to the wire (it can carry key/size detail) — map to opaque `internal` at the boundary.
- **axum's default `Json` rejection embeds the serde error**, which can echo request-body fragments — wrap all extractor rejections and return a generic 422 `bad_request`.
- No request/response **body logging** in any tower/tracing layer. (Extends #1's "redact Token Debug" work.)
- No `unwrap`/`expect` in library code (tests excepted).

## 8. Trait seams (the #4 hand-off)

```rust
pub trait CreditLedger: Send + Sync {
    fn balance(&self, account: &AccountId) -> u64;
    fn grant(&self, account: &AccountId, amount: u64);
    fn debit(&self, account: &AccountId, amount: u64) -> Result<(), IssuerError>; // atomic; 402 if short
}
pub enum InsertOutcome { Inserted, AlreadySpent }
pub trait SpentSet: Send + Sync {
    fn insert(&self, id: SpendId) -> InsertOutcome; // atomic check-and-set, single map-entry op
}
```

- `InMemoryLedger` (e.g. `Mutex<HashMap<AccountId,u64>>` or sharded/atomic) and `InMemorySpentSet` (`Mutex<HashSet<SpendId>>` or `DashMap`) — the only requirement is the atomicity above.
- #4's broker supplies durable, per-epoch implementations behind these exact interfaces (durable spent-set is a **#4 blocker for real deployment**, §11).

## 9. Testing (TDD, failing-first)

Marquee integration test (`tests/loop_e2e.rs`) spins up the real axum service on an ephemeral port and drives it with the real reqwest client.

**Unlinkability harness (the deliverable).** The honest statement: RFC 9474's proof is the guarantee; the harness catches *engineering* regressions. Two-account interleaved run:
- Accounts A and B each issue a batch through actual axum+reqwest, then redeem all tokens **shuffled**. A logging "malicious issuer" records full transcripts of both endpoints.
- **Byte-disjointness:** no substring ≥ 8 bytes shared between any issue-side record and any redeem-side record, excluding whitelisted public constants (`key_id`, issuer pubkey, denomination).
- **Derivability sweep:** for every redeemed `spend_id`, assert it ≠ `BLAKE3(x)` for every `x` the issuer saw at issue time (each blinded msg, each blind sig, account pubkeys, the batch hash) — catches e.g. a client bug where `token` = blind sig unmodified.
- **Structural sweep:** serialize every `/redeem` request+response and assert absence of both accounts' pubkey/`account_id` bytes and both `IssueSignature`s.
- (We deliberately **do not** assert "adversary can't beat chance" — a coded adversary trivially achieves chance, making the assertion theater.)

**Other required tests:**
- **Transport separation:** issue and redeem use **separate `reqwest::Client` instances** (no shared keep-alive/cookies/headers); redeem uses a fixed minimal header set. Assert the two clients are distinct in the harness wiring.
- **Full happy loop:** key-config → grant → blind×N → `/issue` → unblind×N → `/redeem`×N all succeed; client recomputes & pins `key_id`.
- **Double-spend:** second `/redeem` of the same token → 409.
- **Balance enforced:** issue beyond granted balance → 402; partial not allowed (atomic).
- **Idempotency:** replayed `/issue` (same `request_id` + hash) returns identical signatures and debits once; differing hash → 409; stale `ts` → 422.
- **Tamper:** mutated token → 422.
- **Cross-key isolation:** token from issuer-A fails `/redeem` at issuer-B (different key).
- **key-config integrity:** both accounts receive byte-identical key-config; client rejects a key-config whose `key_id ≠ BLAKE3(pubkey)`.
- **L8:** every error-response body contains no token/blinded/account bytes and no interpolated request data.
- **Restart hole (must demonstrate):** redeem a token → reload issuer (persisted key) → the **same token verifies and redeems again** (in-memory spent-set reset). This proves tokens survive restart *and* documents the respend hole (§11).

Property tests (`proptest`) where they add signal: `issue_request_sign/verify` round-trip + tamper; ledger never goes negative under concurrent debits; `SpentSet::insert` returns `AlreadySpent` exactly once per id.

## 10. Non-negotiables & compliance

- **Privacy invariant:** the issuer never sees prompt plaintext (prompts are not in #2 at all). No single record links IP↔identity↔token across issue/redeem beyond what network timing gives — and that residue is #3's relay to close (§11).
- BLAKE3 for `key_id`, `blinded_batch_hash`, `spend_id`.
- Typed errors via `thiserror`; no `unwrap`/`expect` in library crates.
- `cargo test` (all crates touched) and `cargo clippy --all-targets -- -D warnings` green before any task is called done.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## 11. Leak-register addenda (record in ADR-0001; carry to #3/#4)

- **L1 addendum:** #2's direct-to-issuer `/redeem` is **test topology**. #3 must route redemption via the relay/OHTTP, and issue-vs-redeem must never share a TCP connection or HTTP client (§9 transport separation).
- **L2 addendum:** clients pin key-config (§5.2). A per-user key-config service is the attack; #3/#4 should consider serving key-config **through the relay** so the issuer cannot target key-configs by IP.
- **For #4:** durable per-epoch spent-set (**deployment blocker** — the §9 restart test demonstrates the hole), atomic redeem↔accept-work coupling, host idempotency on `spend_id` (existing carry-forward ticket), and a real trial-grant / anti-Sybil policy replacing `/v1/admin/grant`.

## 12. Non-goals / YAGNI

- No durable ledger or spent-set (in-memory only; #4).
- No OHTTP/relay wrapping of issuance (network unlinkability; #3).
- No token→session-key exchange at redeem (that is the host handshake; #5). `/redeem` proves verify + at-most-once only.
- No variable denominations, no key rotation logic beyond the `key_id`-in-redeem forward-compat hook (accepting epochs k and k−1 is a #3/#4 concern).
- No roles/quotas on `/admin/grant`.

## 13. Ruling provenance

Design decisions in §5–§9 were ruled by Fable (`protocol-crypto-architect`) on 2026-07-16, reviewing the initial brainstormed design against ADR-0001's leak register and the `lluma-crypto` APIs. Notable Fable changes from the first draft: purpose-typed issue-authorization signature instead of a generic `account_sign` (§5.1); hardened, non-vacuous unlinkability harness (§9); separate HTTP clients for issue vs redeem (§9); full-length `key_id` with client-side recompute/pin (§5.2); idempotency-cache replay model (§5.3); atomic handler ordering (§6); wrapped extractor rejections for L8 (§7); restart-respend hole demonstrated and flagged for #4 (§11).

## 14. Self-review checklist (pre-implementation)

- [ ] Every endpoint DTO has an exact-length-checked home in `lluma_core::proto::v1`.
- [ ] `IssueRequestBody`/`IssueSignature` in `wire.rs`; `issue_request_sign`/`verify` in `account.rs` mirror `receipt_sign` with a distinct domain string.
- [ ] `CreditLedger::debit` and `SpentSet::insert` are atomic; no check-then-act races.
- [ ] No error variant or log line can interpolate token/blinded/account bytes (L8).
- [ ] Client recomputes and pins `key_id`; issue and redeem use separate `reqwest::Client`s.
- [ ] The restart-respend hole is demonstrated by a test and flagged as a #4 blocker.
- [ ] RNG split (blind-rsa `DefaultRng` vs 0.6 `OsRng`) restated in the delegation brief.
