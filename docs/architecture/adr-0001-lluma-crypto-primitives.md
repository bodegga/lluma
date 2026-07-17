# ADR-0001: `lluma-crypto` primitives — blind tokens, OHTTP, sessions, accounts, key backup

- **Status:** Proposed (DRAFT — recommendation memo for human sign-off)
- **Date:** 2026-07-15
- **Deciders:** Bodegga / Lluma (pending human approval)
- **Scope:** cryptographic primitive and library selection for the `lluma-crypto` crate
  (Phase 1). Pure functions over byte types; no I/O, no network (spec §12).
- **Inputs:** design spec §3, §5, §8, §12, §14 (`docs/superpowers/specs/2026-07-14-lluma-design.md`);
  `docs/PHASE1-FOLLOWUPS.md` privacy-invariant note.

---

## 0. Threat model and trust assumptions (restated)

**Invariant:** no single party ever holds both the originator's IP and the prompt
plaintext (spec §3).

Parties and what each may see:

| Party | May see | Must never see |
|---|---|---|
| Relay | originator IP, opaque ciphertext | plaintext, chosen host, account identity |
| Broker / Issuer (one operator in MVP) | ciphertext, routing metadata, account pubkeys + credit ledger (contribution side), **blinded** token requests | originator IP, plaintext, account↔spent-token linkage |
| Host | prompt plaintext (Open tier), a valid spend token | originator IP, account identity, the originator's other requests |
| Consumer (client) | everything of its own | — |

Trust assumptions:

- Adversaries are **honest-but-curious individually and may collude pairwise**, except:
  the invariant is *architecturally void* if **relay and broker are operated by the same
  party that also logs**. Crypto cannot fix that; see §6 leak L1. In MVP the solo operator
  runs broker + issuer; the relay must be operationally separated (separate box, no shared
  logs, documented no-log policy; community-run relays ASAP in Phase 3).
- The issuer is trusted for *credit integrity* (it can inflate credits) but **not** for
  *anonymity* — blindness must hold even against a malicious issuer colluding with the
  broker and hosts.
- No novel crypto: IETF-standardized primitives and reviewed Rust implementations only.

---

## 1. Decision: blind-signature / unlinkable-token scheme

Requirement (spec §3, §8): a bearer proves "I hold credits" such that (a) issuance and
redemption are cryptographically unlinkable, and (b) double-spend is preventable.

### Options

**1A. RSA blind signatures — RFC 9474 (Chaum), crate `blind-rsa-signatures` (jedisct1)**

- *Unlinkability:* **perfect (information-theoretic) blinding** — the blinded message is
  uniformly random independent of the token; holds even against an unbounded issuer.
- *Double-spend:* tokens are one-time bearer values; verifier keeps a **spent-set** of
  `BLAKE3(token)` keyed per issuer-key epoch; set is garbage-collected at epoch expiry.
- *Token size:* ~320 B (32 B nonce + 32 B msg randomizer + 256 B RSA-2048 sig).
- *Verification:* **public** — anyone holding the issuer *public* key verifies offline
  (RSA verify, tens of µs). Issuance is one RSA sign (~1 ms) — trivial at MVP scale.
- *Standardization:* RFC 9474; it is Privacy Pass token type 2 (RFC 9578) and the basis of
  Apple Private Access Tokens — heavily deployed.
- *Rust ecosystem:* `blind-rsa-signatures` (Frank Denis), implements RFC 9474 including
  its test vectors; actively maintained.

**1B. VOPRF-based Privacy Pass — RFC 9497 + RFC 9578 type 1, crate `voprf` (facebook/voprf)**

- *Unlinkability:* computational (DDH-type assumption on P-384). Fine in practice.
- *Token size:* small (~150 B). Issuance/verification fast (EC ops).
- *Fatal drawback for us:* **privately verifiable** — only the holder of the OPRF secret
  key can verify a token. Every redemption must round-trip to the issuer. Acceptable while
  issuer = broker (MVP), but it hard-couples verification to one secret-holding party and
  **blocks Phase 3 decentralization** (hosts/multiple brokers can't verify offline).
- *Ecosystem:* `voprf` crate implements RFC 9497; solid but no formal audit noted.

**1C. Blind BLS (pairing-based, e.g. `blstrs`/`arkworks`)**

- Tiny tokens (~96 B), publicly verifiable, signatures aggregate.
- *Fatal drawback:* **no IETF standard for the blind variant**; we would be assembling a
  bespoke blind-signing protocol (rogue-key subtleties, hash-to-curve domain separation)
  — this violates the "no novel crypto" rule. Pairing verification is also the slowest of
  the three (~1–2 ms). Reject.

### Recommendation: **1A — RFC 9474 RSA blind signatures**, `blind-rsa-signatures` crate

Why it fits a solo-operator MVP that must decentralize: public verifiability means the
broker (and later any host or federated broker) verifies tokens with only the issuer's
*public* key + a shared spent-set; the issuer is offline-issuance-only. Perfect blinding
means even the MVP's "issuer = broker = same operator" cannot link redemption to issuance.
Parameters:

- **RSABSSA-SHA384-PSS-Randomized** (the RFC 9474 recommended variant; the message
  randomizer defends low-entropy messages — ours is a random 32-byte nonce anyway).
- **RSA-2048 issuer keys with epoch rotation** (Privacy Pass type-2 compatible). Epochs
  are long (≥ 30 days) — see leak L2 (key epochs partition the anonymity set).
- **Single denomination** (1 token = 1 request-unit of the pricing schedule, spec §8).
  Variable denominations would partition the anonymity set per denomination.
- Spent-set key = `BLAKE3(nonce ‖ randomizer ‖ signature)` (project rule: BLAKE3 for all
  content addressing).

---

## 2. Decision: OHTTP / oblivious relaying primitive

Requirement (spec §3, §5): relay sees IP + ciphertext only; broker sees ciphertext +
routing metadata only; response **streams** back E2E-encrypted.

Role mapping to RFC 9458: relay = Oblivious Relay Resource; **broker = Oblivious Gateway
Resource**. The prompt is additionally E2E-encrypted to the host's published key *inside*
the OHTTP payload (nested encryption), so the broker decapsulates OHTTP and still sees
only the inner ciphertext + routing metadata (`model-id`, net-coords, token).

### Options

**2A. `ohttp` crate (Martin Thomson / Mozilla) — RFC 9458 + RFC 9180**

- Reviewed, spec-authored-adjacent implementation; interops with deployed OHTTP.
- Supports a pure-Rust `rust-hpke` backend (avoids the NSS build toolchain — relevant on
  our Windows dev boxes).
- *Streaming gap:* RFC 9458 proper is **single-shot request/response** — the whole
  response is one AEAD message, which does **not** fit spec §5's streamed tokens. The fix
  is **Chunked Oblivious HTTP** (draft-ietf-ohai-chunked-ohttp, at -08, Standards Track,
  Feb 2026): each response chunk is AEAD-sealed under keys exported from the HPKE context,
  with an authenticated final-chunk marker. The `ohttp` crate's `stream` feature tracks
  this draft but is read-side only and marked unstable today.

**2B. Hand-rolled encapsulation over the `hpke` crate (rozbb/rust-hpke, RFC 9180)**

- `rust-hpke` is pure Rust, passed a Cloudflare internal security review (v0.8, no issues
  found), supports X25519/P-256 KEMs, HKDF-SHA256, AES-GCM and ChaCha20-Poly1305 — and
  post-quantum hybrids (X-Wing) for later.
- We would re-specify RFC 9458's header/key-config/AAD framing ourselves. The crypto is
  still HPKE, but the framing is exactly where interop and subtle AAD-binding bugs live.
  More bespoke surface than necessary.

**2C. General mixnet/onion transport (Tor/Nym/I2P) instead of OHTTP**

- Stronger network-level anonymity but heavy operationally, high latency for interactive
  inference, and spec §13 already defers Tor/I2P to a Phase 4 "paranoid mode". Not a
  substitute for the application-layer encapsulation contract. Reject for Phase 1.

### Recommendation: **2A — `ohttp` crate with the `rust-hpke` backend**, plus chunked responses

- **Request path:** RFC 9458 encapsulation via `ohttp` (key config, media types,
  header-bound AAD) — nothing bespoke.
- **Response path (streaming):** adopt **draft-ietf-ohai-chunked-ohttp** chunk framing.
  Use the crate's `stream` support where it suffices; where the write side is missing,
  implement the draft's chunk sealing in `lluma-crypto` *using the draft's exporter labels
  and its test vectors* (framing per published draft ≠ novel crypto), and upstream/replace
  when the crate stabilizes. **Mandatory test:** dropped/truncated final chunk MUST fail
  closed — this exact bug was CVE-2026-48480 in Netty's chunked-OHTTP codec.
- **Inner E2E layer (client → host, and host → client response chunks):** RFC 9180 HPKE
  via `rust-hpke` directly (same implementation the OHTTP layer uses underneath — one
  HPKE codebase in the dependency tree).
- **Ciphersuite (both layers):** `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` +
  `ChaCha20-Poly1305`. Rationale: constant-time on every volunteer host without AES-NI
  assumptions (heterogeneous consumer hardware), pure-Rust, and the RustCrypto
  `chacha20poly1305` crate was audited (NCC Group, 2020). Key configs carry algorithm IDs,
  so we retain agility — flag for Phase 4: prompts are "harvest-now-decrypt-later"
  sensitive; `rust-hpke` already ships X-Wing (ML-KEM-768+X25519) hybrid as an upgrade
  path.
- **AAD discipline:** routing metadata the broker legitimately needs (model-id, tier,
  net-coords) travels as OHTTP-visible fields but is **bound as AAD of the inner E2E
  seal**, so the broker cannot swap routing metadata onto a different prompt undetected.

---

## 3. Decision: ephemeral session keys (spec §3.1)

**How it composes.** A "session" is a client-local bundle, generated fresh, never
persisted, never derived from the account key:

1. Client generates an ephemeral **X25519 session keypair** (`session_keygen`). The public
   half rides *inside* the E2E-sealed request so the host can seal response chunks back to
   it. The relay and broker never see it in plaintext.
2. HPKE Base-mode encapsulation already generates a **fresh sender ephemeral per seal** —
   so every request is fresh at the KEM layer for free; the session keypair only governs
   the response direction.
3. Tokens (§1) are pre-fetched in batches out of band; each request attaches one unspent
   token. Token, session key, and OHTTP encapsulation share **no derivation relationship**
   — unlinkability of each layer is independent.

**Where the key lives:** in client process memory only, wrapped in zeroize-on-drop types
(`zeroize` crate). Never written to disk, logs, or telemetry (PHASE1-FOLLOWUPS privacy
note). Dropped at session end or app exit.

**Recommendation beyond spec minimum:** rotate the response keypair **per request**, not
per session — it costs one X25519 keygen (~µs) and removes the within-session linkage that
a per-session key deliberately accepts. The spec's per-session wording remains the floor;
per-request is the default in the API.

**Leak call-out (L3):** if the same response public key were reused across sessions, the
host could link requests. The API makes reuse impossible by construction: `session_keygen`
is the only way to obtain a response key, and sealed requests embed it per call.

---

## 4. Account / identity model (contribution side) and the unlinkability bridge

**Account = locally generated long-lived Ed25519 keypair.** No PII, no server-side state
at creation. Human-visible handle = BLAKE3 fingerprint of the public key (canonical id =
full 32-byte `blake3(pubkey)`; display truncation is a `lluma-core` concern).
Library: `ed25519-dalek` v2 (the de-facto Rust Ed25519, widely reviewed and deployed;
v2 API prevents the classic key-reuse pitfalls).

**Strict side separation:**

- **Contribution side (identified):** hosts sign usage receipts with the account key; the
  broker keys the credit ledger and reputation to the account pubkey. Fine — a host's
  identity was never anonymous to the broker.
- **Consumption side (anonymous):** the account key is **never presented**. The consumer
  is an anonymous bearer of blind tokens + an ephemeral session key (§3).

### 4.1 Signed usage-receipt format

Canonical body (deterministic encoding in `lluma-core`, e.g. postcard with fixed field
order):

```text
UsageReceiptBody {
  version:        u8,            // 1
  host_account:   [u8; 32],      // host's Ed25519 pubkey (the earner)
  model_id:       ModelId,
  tier:           u8,            // Open / Confidential
  units:          u32,           // priced work units (schedule is config, spec §8)
  spend_id:       [u8; 32],      // BLAKE3 of the redeemed token (§1) — entitlement proof
  epoch:          u32,           // issuer key epoch of the spent token
  timestamp_h:    u32,           // hours since epoch, COARSE on purpose (leak L4)
}
```

Signature = Ed25519 over `b"lluma-usage-receipt-v1" ‖ canonical_bytes` (domain-separated).
The receipt deliberately contains **no session public key, no ciphertext hash, no
network coordinates, no fine timestamp** — nothing that narrows which consumer it was.

### 4.2 How redemption breaks the account↔token link

Redemption is the **only** bridge between the identified ledger and anonymous spending:

1. Client authenticates to the issuer *as the account* (Ed25519-signed request) and asks
   to convert N credits into N tokens, sending N **blinded** messages.
2. Issuer debits the ledger and blind-signs each message (RFC 9474).
3. RSA blinding is information-theoretically hiding: given the issuer's transcript
   (account pubkey, N blinded blobs, N blind sigs), **every possible set of N final tokens
   is equally consistent** — even an unbounded issuer colluding with broker and hosts
   cannot link a spent token back to the redeeming account. Residual linkage is only
   statistical (timing/count), addressed in leaks L2/L4.

### 4.3 No-party-sees-both check (confirmed by API construction)

- `token_issue` (issuer) takes `BlindedTokenRequest` — the account pubkey may accompany it
  at the service layer, but the request is blinded: the issuer observes the account and
  *blinded* material only, never a spendable token value.
- `token_verify` / `token_spend_id` (broker, hosts) take **only** `IssuerPublicKey` +
  `Token` — there is no parameter through which an account pubkey could arrive on the
  spend path.
- `UsageReceiptBody` contains the **host's** account and the token `spend_id`, never a
  consumer account. The only account pubkey adjacent to a spent token anywhere in the
  system is the *host's own*, which is public by design.
- Therefore no function signature in the crate can even express "consumer account +
  spendable token" in one place. Integration tests assert the same at the mock-party
  level (§7).

---

## 5. Key management / backup (self-custodial only)

Credits have real value and the ledger lives broker-side keyed to the account pubkey, so
**losing the device must not lose the account** — only the key needs backup.

**Hard constraint:** recovery is self-custodial or zero-knowledge only. **Never**
email/phone/PII recovery — that would re-key the "anonymous" economy to a real-world
identity (leak L5). An optional *encrypted cloud-escrow blob* (broker stores opaque
ciphertext it cannot open, keyed to the account it already knows) is acceptable later
polish; explicitly out of scope for this ADR's implementation slice.

### Design (all pure `lluma-crypto` functions)

1. **Seed phrase → account key.** BIP-39 mnemonic (crate: `bip39`, rust-bitcoin org),
   12 words / 128-bit entropy. Derivation:
   `mnemonic.to_seed("") → 64 B → blake3::derive_key("lluma v1 account ed25519", seed) →
   32 B → ed25519_dalek::SigningKey::from_bytes`. Deterministic, single-key, no HD tree
   needed (SLIP-0010 considered and rejected as unneeded complexity for one key; the
   BLAKE3 `derive_key` context string gives us domain separation and room for future
   subkeys, e.g. `"lluma v1 host tls"`).
2. **Keystore at rest.** Private material encrypted under a user passphrase:
   - KDF: **Argon2id** (crate: `argon2`, RustCrypto) — m = 64 MiB, t = 3, p = 1
     (wallet-grade, above OWASP minimum); parameters stored in the keystore header so they
     can be raised without a format break.
   - AEAD: **XChaCha20-Poly1305** (crate: `chacha20poly1305`, RustCrypto — NCC Group
     audit, 2020) with random 24-byte nonce; header (version, KDF params, salt, nonce)
     bound as AAD.
   - Plaintext = the 16-byte BIP-39 **entropy** (not the expanded key), so the app can
     re-display the phrase; the signing key is re-derived on open and held in
     zeroize-on-drop memory.
3. **Wrong passphrase fails closed** with a typed error (AEAD tag mismatch), never
   garbage-key output.

---

## 6. Linkage-leak register (places a design choice could leak identity↔content)

| # | Leak | Mitigation |
|---|---|---|
| L1 | Relay + broker same operator with logs ⇒ invariant void against operator | Operational separation in MVP; community relays Phase 3; no-log policy in signed builds |
| L2 | Issuer key epochs partition anonymity set; per-user keys would be fatal | One global key per epoch, epochs ≥ 30 days, keys published in a transparency log |
| L3 | Response-key reuse links requests | Per-request keypair by API construction (§3) |
| L4 | Timing/count correlation: redeem N tokens then immediately spend N | Batch pre-fetch at fixed sizes, client-side spend buffering/jitter, coarse (hourly) receipt timestamps |
| L5 | PII-based account recovery re-identifies the economy | Forbidden; self-custodial seed phrase + passphrase keystore only (§5) |
| L6 | Variable token denominations partition anonymity set | Single denomination (§1) |
| L7 | Routing metadata (model-id, coords) as a fingerprint | Coarse net-coords (Vivaldi, spec §4); model-id is low-cardinality by nature; revisit in Phase 3 |
| L8 | Prompt bytes in logs/errors | No error variant may embed plaintext (PHASE1-FOLLOWUPS); enforced by review + test |

---

## 7. Proposed `lluma-crypto` public API (shape only)

Pure functions; byte newtypes live in `lluma-core` (a new `wire` module); all fallible
paths return `Result<T, CryptoError>` (`thiserror`, no `unwrap`/`expect`). Secret types
are `zeroize`-on-drop.

```rust
// ── Blind entitlement tokens (RFC 9474, RSABSSA-SHA384-PSS-Randomized) ──────────

/// Issuer: generate an RSA-2048 issuance keypair for one key epoch.
pub fn issuer_keygen(rng: &mut (impl CryptoRng + RngCore)) -> Result<(IssuerSecretKey, IssuerPublicKey)>;

/// Client: create a random token nonce and blind it; returns secret blinding state + the request to send.
pub fn token_blind(rng: &mut impl CryptoRngCore, pk: &IssuerPublicKey) -> Result<(BlindingState, BlindedTokenRequest)>;

/// Issuer: blind-sign one request (service layer debits one credit before calling).
pub fn token_issue(rng: &mut impl CryptoRngCore, sk: &IssuerSecretKey, req: &BlindedTokenRequest) -> Result<BlindSignature>;

/// Client: unblind into a redeemable one-time bearer token; verifies before returning.
pub fn token_unblind(pk: &IssuerPublicKey, st: BlindingState, sig: &BlindSignature) -> Result<Token>;

/// Any verifier (broker/host): offline validity check against the epoch public key.
pub fn token_verify(pk: &IssuerPublicKey, token: &Token) -> Result<()>;

/// Any verifier: deterministic double-spend key = BLAKE3(token) for the epoch spent-set.
pub fn token_spend_id(token: &Token) -> SpendId; // [u8; 32]

// ── OHTTP encapsulation (RFC 9458 + draft-ietf-ohai-chunked-ohttp responses) ───

/// Broker (gateway): generate an OHTTP key config (X25519 / HKDF-SHA256 / ChaCha20-Poly1305).
pub fn ohttp_keygen(rng: &mut impl CryptoRngCore, key_id: u8) -> Result<(GatewaySecretKey, OhttpKeyConfig)>;

/// Client: encapsulate an (already E2E-sealed) request toward the gateway; returns capsule + response context.
pub fn ohttp_encapsulate(rng: &mut impl CryptoRngCore, cfg: &OhttpKeyConfig, request: &[u8]) -> Result<(EncapsulatedRequest, ClientResponseContext)>;

/// Broker: decapsulate; yields inner bytes + a context for sealing streamed response chunks.
pub fn ohttp_decapsulate(sk: &GatewaySecretKey, capsule: &EncapsulatedRequest) -> Result<(Vec<u8>, ServerResponseContext)>;

/// Broker: seal one response chunk; `last = true` seals the authenticated final-chunk marker.
pub fn ohttp_seal_chunk(ctx: &mut ServerResponseContext, chunk: &[u8], last: bool) -> Result<Vec<u8>>;

/// Client: open one chunk; returns (plaintext, is_final). Truncation without `is_final` MUST surface as an error upstream.
pub fn ohttp_open_chunk(ctx: &mut ClientResponseContext, chunk: &[u8]) -> Result<(Vec<u8>, bool)>;

// ── Inner E2E layer (RFC 9180 HPKE, client ↔ host) ─────────────────────────────

/// Host: generate the published host keypair (X25519).
pub fn host_keygen(rng: &mut impl CryptoRngCore) -> Result<(HostSecretKey, HostPublicKey)>;

/// Client: fresh ephemeral response keypair (per request; secret is zeroize-on-drop, memory-only).
pub fn session_keygen(rng: &mut impl CryptoRngCore) -> Result<(SessionSecretKey, SessionPublicKey)>;

/// Client: seal prompt + session pubkey to the host key, binding routing metadata as AAD.
pub fn e2e_seal(rng: &mut impl CryptoRngCore, host_pk: &HostPublicKey, aad: &[u8], prompt: &[u8], reply_to: &SessionPublicKey) -> Result<SealedRequest>;

/// Host: open a sealed request; returns (prompt, reply_to). AAD mismatch fails closed.
pub fn e2e_open(host_sk: &HostSecretKey, aad: &[u8], sealed: &SealedRequest) -> Result<(Vec<u8>, SessionPublicKey)>;

/// Host: seal one streamed response chunk to the client's session key (ordered, final-marked).
pub fn response_seal_chunk(ctx: &mut HostResponseContext, chunk: &[u8], last: bool) -> Result<Vec<u8>>;

/// Client: open one response chunk; returns (plaintext, is_final).
pub fn response_open_chunk(ctx: &mut SessionResponseContext, chunk: &[u8]) -> Result<(Vec<u8>, bool)>;

// ── Accounts, receipts, keystore (Ed25519 / BIP-39 / Argon2id + XChaCha20-Poly1305) ──

/// Generate fresh BIP-39 entropy (12 words) for a new account.
pub fn account_mnemonic_new(rng: &mut impl CryptoRngCore) -> Result<Mnemonic>;

/// Deterministically derive the long-lived Ed25519 account keypair from a mnemonic.
pub fn derive_keypair_from_seed(mnemonic: &Mnemonic) -> Result<(AccountSecretKey, AccountPublicKey)>;

/// Canonical account id / handle source = BLAKE3(pubkey).
pub fn account_fingerprint(pk: &AccountPublicKey) -> AccountId; // [u8; 32]

/// Host: sign a canonical usage-receipt body (domain-separated Ed25519).
pub fn receipt_sign(sk: &AccountSecretKey, body: &UsageReceiptBody) -> Result<ReceiptSignature>;

/// Broker: verify a usage receipt against the host's account pubkey.
pub fn receipt_verify(pk: &AccountPublicKey, body: &UsageReceiptBody, sig: &ReceiptSignature) -> Result<()>;

/// Encrypt mnemonic entropy under a passphrase (Argon2id → XChaCha20-Poly1305; header bound as AAD).
pub fn seal_keystore(rng: &mut impl CryptoRngCore, passphrase: &str, mnemonic: &Mnemonic) -> Result<KeystoreBlob>;

/// Decrypt a keystore blob; wrong passphrase / tamper → typed error, never a garbage key.
pub fn open_keystore(passphrase: &str, blob: &KeystoreBlob) -> Result<Mnemonic>;
```

Dependency set (all cited above): `blind-rsa-signatures`, `ohttp` (feature `rust-hpke`),
`hpke`, `ed25519-dalek`, `bip39`, `argon2`, `chacha20poly1305`, `blake3`, `zeroize`,
`rand_core`, `thiserror`.

---

## 8. Property-based tests to write first (TDD, spec §14)

Failing tests before any implementation; `proptest` for properties, plus known-answer
tests (KATs) from RFC 9474, RFC 9180, RFC 9458, and draft-ietf-ohai-chunked-ohttp.

**Tokens**
1. *Round trip:* ∀ rng seeds: blind → issue → unblind → `token_verify` = Ok.
2. *Tamper:* any single-bit flip in a valid token ⇒ verify fails.
3. *Epoch isolation:* token from epoch-k key fails verify under epoch-(k+1) key.
4. *Spend-id determinism + uniqueness:* same token ⇒ same `SpendId`; distinct tokens ⇒
   distinct `SpendId` (no collisions across large random sample).
5. *Blindness proxy:* the issuer transcript (blinded request + blind sig) shares no
   substring/derivable bytes with the final token nonce; two blindings of the same nonce
   under different rng are distinct (mechanical proxies — the real guarantee is RFC 9474's
   proof, KAT-pinned).

**OHTTP / E2E**
6. *Round trip:* ∀ payloads: encapsulate → decapsulate = identity; e2e_seal → e2e_open =
   identity, including empty and max-size payloads.
7. *Streaming round trip under arbitrary chunking:* ∀ payloads, ∀ split points: seal
   chunks → open chunks reassembles exactly, `is_final` on the last only.
8. *Truncation fails closed:* dropping the final chunk (or any suffix) can never yield a
   "complete" stream (CVE-2026-48480 class).
9. *Reorder/replay fails:* swapping or repeating any two chunks ⇒ error.
10. *AAD binding:* modifying routing metadata (AAD) after e2e_seal ⇒ open fails.
11. *Freshness/unlinkability proxy:* two encapsulations of the identical request produce
    distinct `enc` values and ciphertexts; ciphertext contains no plaintext substring.

**Accounts / keystore**
12. *Seed determinism:* same mnemonic ⇒ same keypair across runs/platforms; distinct
    mnemonics ⇒ distinct keys.
13. *Keystore round trip:* ∀ passphrases (incl. empty, Unicode): seal → open = identity.
14. *Wrong passphrase / tamper:* open with any different passphrase, or any blob bit-flip
    (header or ciphertext) ⇒ typed error.
15. *Receipt round trip + tamper:* sign → verify Ok; any body field mutation ⇒ verify fails;
    signature from a different account key ⇒ verify fails.

**Invariant harness (integration, in-process mocks — spec §14)**
16. Run issuer + relay + broker + host + client mocks; assert from recorded views:
    relay saw no plaintext; broker saw no plaintext and no originator IP; host saw no IP
    and no account pubkey; **no party's view contains both a consumer account pubkey and a
    spendable/spent token**; two sessions from one client are byte-unlinkable at every
    non-client party.

---

## 9. Recommended stack (summary for approval)

**Tokens:** RFC 9474 RSA blind signatures (RSABSSA-SHA384-PSS-Randomized, RSA-2048,
≥30-day key epochs, single denomination) via the `blind-rsa-signatures` crate — perfectly
blinding, publicly verifiable (so verification decentralizes in Phase 3), Privacy Pass
type-2 compatible; double-spend via a per-epoch spent-set keyed by BLAKE3(token).
**Transport privacy:** RFC 9458 Oblivious HTTP via the `ohttp` crate on its pure-Rust
`rust-hpke` backend, with streamed responses per draft-ietf-ohai-chunked-ohttp (write-side
chunk sealing implemented in `lluma-crypto` against the draft's vectors until the crate
stabilizes; truncation fails closed); inner client↔host E2E layer is plain RFC 9180 HPKE
(`hpke` crate); ciphersuite everywhere = DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 +
ChaCha20-Poly1305, with a documented X-Wing post-quantum upgrade path.
**Sessions:** memory-only zeroized X25519 response keypairs, fresh **per request**.
**Identity:** contribution-only Ed25519 account key (`ed25519-dalek`), BLAKE3 fingerprint
handle, domain-separated signed usage receipts with coarse timestamps; consumption is
bearer-token-only, and redemption's RSA blinding is the cryptographic bridge that
unlinks account from spend.
**Backup:** BIP-39 12-word phrase (`bip39`) → BLAKE3-derive-key → Ed25519; keystore =
Argon2id (64 MiB, t=3) + XChaCha20-Poly1305 (`argon2`, `chacha20poly1305`); recovery is
self-custodial only — no PII recovery ever.
All primitives are IETF-standardized (or Standards-Track drafts) with maintained,
reviewed Rust implementations; the crate is pure functions with typed `thiserror` errors
and property tests written first.

---

## References

- RFC 9474 — RSA Blind Signatures; crate: [jedisct1/rust-blind-rsa-signatures](https://github.com/jedisct1/rust-blind-rsa-signatures)
- RFC 9497 — OPRF/VOPRF; crate: [facebook/voprf](https://github.com/facebook/voprf) (considered, not selected)
- RFC 9576/9578 — Privacy Pass architecture / issuance (token type compatibility)
- RFC 9458 — Oblivious HTTP; crate: [martinthomson/ohttp](https://github.com/martinthomson/ohttp)
- [draft-ietf-ohai-chunked-ohttp-08](https://datatracker.ietf.org/doc/draft-ietf-ohai-chunked-ohttp/) — Chunked Oblivious HTTP (streaming responses)
- [CVE-2026-48480](https://advisories.gitlab.com/maven/io.netty.incubator/netty-incubator-codec-ohttp/CVE-2026-48480/) — missing final-chunk enforcement (encoded as test §8.8)
- RFC 9180 — HPKE; crate: [rozbb/rust-hpke](https://github.com/rozbb/rust-hpke) (Cloudflare internal review of v0.8: no issues found)
- BIP-39; crates: `bip39`, `ed25519-dalek` v2, `argon2` (RustCrypto), `chacha20poly1305` (RustCrypto, NCC Group audit 2020), `blake3`, `zeroize`
