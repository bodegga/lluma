# Lluma Phase 1 · Sub-project #1 — `lluma-crypto` Design Spec

> The cryptographic trust foundation for Lluma's anonymity layer.
> A **Bodegga** project.

- **Status:** Proposed (pre-implementation)
- **Date:** 2026-07-15
- **Author:** Bodegga / Lluma
- **Parent design:** [`2026-07-14-lluma-design.md`](2026-07-14-lluma-design.md) (§3, §5, §8, §12, §14)
- **Primitive decisions:** [ADR-0001](../../architecture/adr-0001-lluma-crypto-primitives.md) — this spec does **not** re-litigate scheme/library choices; it consumes them.

---

## 1. Summary & role in Phase 1

Phase 1 (the anonymity MVP) is decomposed into five sub-projects, each its own spec → plan → build cycle:

1. **`lluma-crypto` — the trust foundation (THIS SPEC).** Blind tokens, OHTTP/HPKE encapsulation, ephemeral sessions, account identity, signed receipts, key backup. Pure functions, no I/O, no network.
2. Token issuance loop — `lluma-issuer` + client redemption.
3. Anonymous transport — `lluma-net` + `lluma-relay`.
4. Matchmaking + accounting — `lluma-broker`.
5. End-to-end slice — `lluma-host` + `lluma-client` + desktop wiring.

`lluma-crypto` is built first because every other sub-project depends on its correctness. It is designed by Fable (ADR-0001) and implemented against property tests written failing-first (§14 of the parent spec).

## 2. Scope

**In scope (this crate):**

- The public API in [ADR-0001 §7](../../architecture/adr-0001-lluma-crypto-primitives.md), grouped into four modules: `tokens`, `ohttp`, `e2e` (inner HPKE + sessions), `account` (identity, receipts, keystore/backup).
- A new `wire` module in `lluma-core` holding the byte-newtypes the crypto API consumes/produces (so `lluma-crypto` depends only on `lluma-core`).
- The `CryptoError` type (`thiserror`), and the full property-test suite from [ADR-0001 §8](../../architecture/adr-0001-lluma-crypto-primitives.md).

**Explicitly out of scope (later sub-projects):**

- Any network transport, HTTP handling, sockets, or service loop (sub-projects 2–4).
- The credit *ledger*, spent-set *storage*, matchmaking, reputation (sub-project 4 / broker).
- Persisting the keystore to disk, seed-phrase UI, or Tauri wiring (sub-project 5 / desktop).
- The Confidential/TEE tier and attestation (Phase 4).

`lluma-crypto` provides the primitive `token_spend_id()`; it does **not** own the spent-set. It provides `seal_keystore()`/`open_keystore()`; it does **not** touch the filesystem. Callers own all I/O and state.

## 3. Recommended stack (from ADR-0001, approved 2026-07-15)

| Layer | Choice | Crate |
|---|---|---|
| Credit tokens | RFC 9474 RSA blind sigs (RSABSSA-SHA384-PSS-Randomized, RSA-2048, ≥30-day epochs, single denomination) | `blind-rsa-signatures` |
| Oblivious transport | RFC 9458 OHTTP | `ohttp` (feature `rust-hpke`) |
| Inner E2E | RFC 9180 HPKE — DHKEM(X25519,HKDF-SHA256)+HKDF-SHA256+ChaCha20-Poly1305 | `hpke` |
| Sessions | Ephemeral X25519, per-request, memory-only, zeroized | `zeroize` |
| Account identity | Ed25519, BLAKE3 fingerprint handle | `ed25519-dalek` v2 |
| Backup | BIP-39 → BLAKE3-derive → Ed25519; keystore Argon2id (64 MiB, t=3) + XChaCha20-Poly1305 | `bip39`, `argon2`, `chacha20poly1305` |
| Content addressing | BLAKE3 everywhere (project rule) | `blake3` |

Double-spend id = `BLAKE3(nonce ‖ randomizer ‖ signature)`; verification is **public** (issuer public key only) so it decentralizes in Phase 3.

## 4. Streaming decision (deferred item)

RFC 9458 OHTTP is single-shot; streamed token responses (parent spec §5) need `draft-ietf-ohai-chunked-ohttp`, whose **write-side** is not yet stable in the `ohttp` crate.

**Decision:** the chunk API (`ohttp_seal_chunk`/`ohttp_open_chunk`, `response_seal_chunk`/`response_open_chunk`) is defined now exactly as ADR-0001 §7 specifies, but the MVP implementation emits/accepts a **single terminal chunk** (`last = true`). This keeps the trust-foundation crate small and auditable and avoids hand-implementing an unstable IETF draft in the most security-critical crate.

**Consequence:** true token-by-token streaming is a purely *additive* later change (multi-chunk sealing + reorder/truncation edge cases), not a rewrite. The fail-closed-on-truncation test ([ADR-0001 §8](../../architecture/adr-0001-lluma-crypto-primitives.md), the CVE-2026-48480 class) is still **mandatory** for the single-chunk path (a dropped final chunk must never read as complete).

## 5. Crate structure

```
crates/lluma-crypto/
├─ Cargo.toml
└─ src/
   ├─ lib.rs        # module wiring + re-exports; crate-level docs
   ├─ error.rs      # CryptoError (thiserror)
   ├─ tokens.rs     # RFC 9474 blind tokens: keygen/blind/issue/unblind/verify/spend_id
   ├─ ohttp.rs      # RFC 9458 encapsulate/decapsulate + chunk seal/open (single-chunk MVP)
   ├─ e2e.rs        # host/session keygen, e2e seal/open, response chunk seal/open
   └─ account.rs    # mnemonic, derive_keypair_from_seed, fingerprint, receipt sign/verify, keystore

crates/lluma-core/src/wire.rs   # NEW: byte-newtypes shared across the protocol
```

`lluma-core::wire` (new) holds: `IssuerPublicKey`, `IssuerSecretKey`, `BlindedTokenRequest`, `BlindSignature`, `BlindingState`, `Token`, `SpendId`, `OhttpKeyConfig`, `GatewaySecretKey`, `EncapsulatedRequest`, `HostPublicKey`/`HostSecretKey`, `SessionPublicKey`/`SessionSecretKey`, `SealedRequest`, `AccountPublicKey`/`AccountSecretKey`, `AccountId`, `UsageReceiptBody`, `ReceiptSignature`, `Mnemonic`, `KeystoreBlob`, and the response/context types. Secret-bearing newtypes derive `Zeroize`/`ZeroizeOnDrop` and do **not** derive `Debug`/`Serialize` for their secret bytes.

## 6. Interfaces

The complete public function surface is [ADR-0001 §7](../../architecture/adr-0001-lluma-crypto-primitives.md) and is normative for this spec — implement those exact signatures. Grouped: **tokens** (`issuer_keygen`, `token_blind`, `token_issue`, `token_unblind`, `token_verify`, `token_spend_id`), **ohttp** (`ohttp_keygen`, `ohttp_encapsulate`, `ohttp_decapsulate`, `ohttp_seal_chunk`, `ohttp_open_chunk`), **e2e/sessions** (`host_keygen`, `session_keygen`, `e2e_seal`, `e2e_open`, `response_seal_chunk`, `response_open_chunk`), **account** (`account_mnemonic_new`, `derive_keypair_from_seed`, `account_fingerprint`, `receipt_sign`, `receipt_verify`, `seal_keystore`, `open_keystore`).

All fallible paths return `Result<T, CryptoError>`; no `unwrap`/`expect` outside tests.

## 7. Testing

TDD, failing-first. Encode all 16 properties/invariants from [ADR-0001 §8](../../architecture/adr-0001-lluma-crypto-primitives.md): token round-trip/tamper/epoch-isolation/spend-id, OHTTP+E2E round-trip/AAD-binding/truncation-fail-closed/reorder-fail/freshness, account seed-determinism/keystore-round-trip/wrong-passphrase/receipt round-trip, and the in-process **no-party-sees-both** invariant harness (§16 of that list). Use `proptest` for properties and RFC/draft known-answer vectors where published.

## 8. Deployment constraint carried forward (leak L1)

Not a crate concern, but it must be recorded and enforced by the sub-projects that follow: **in the solo-operator MVP the relay must run separately from the broker+issuer (separate host, no shared logs, documented no-log policy).** No amount of correct cryptography in this crate protects the invariant if one operator co-locates the IP-seeing party (relay) with the metadata-seeing party (broker). This drives the ≥2-VPS deployment topology for Phase 1.

## 9. Non-goals / YAGNI

- No HD key tree (SLIP-0010) — one account key; BLAKE3 `derive_key` context strings give domain separation and room for future subkeys.
- No variable token denominations (would partition the anonymity set — leak L6).
- No post-quantum KEM in MVP — X-Wing upgrade path documented in ADR-0001, deferred to Phase 4.
- No cloud escrow / social recovery in MVP — self-custodial seed phrase + passphrase keystore only.

## 10. Self-review checklist (pre-implementation)

- [ ] Every ADR-0001 §7 signature has a home in one of the four modules.
- [ ] Every ADR-0001 §8 test is listed as a task before its implementation.
- [ ] Secret newtypes are zeroize-on-drop and never `Debug`/`Serialize` their secrets.
- [ ] No filesystem, socket, or global-state access anywhere in the crate.
- [ ] `CryptoError` has no variant that can embed prompt/secret plaintext (leak L8).
