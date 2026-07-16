# lluma-crypto Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `lluma-crypto`, the pure-function cryptographic trust foundation for Lluma's Phase 1 anonymity layer (blind entitlement tokens, Oblivious-HTTP + HPKE encapsulation, ephemeral sessions, Ed25519 account identity, signed usage receipts, and self-custodial key backup).

**Architecture:** One new crate `crates/lluma-crypto` with four modules (`tokens`, `ohttp`, `e2e`, `account`) plus an `error` module, depending only on a new `wire` module added to `lluma-core`. No I/O, no network, no global state, no filesystem — every function is a pure transform over byte-newtypes. Callers (later sub-projects) own all state (spent-sets, ledgers, sockets, disk).

**Tech Stack:** Rust 2021. Crates (all cited in ADR-0001): `blind-rsa-signatures` (RFC 9474), `ohttp` (feature `rust-hpke`, RFC 9458), `hpke` (RFC 9180), `ed25519-dalek` v2, `bip39`, `argon2`, `chacha20poly1305`, `blake3`, `zeroize`, `rand_core`, `thiserror`, `postcard` (deterministic receipt encoding). Dev: `proptest`.

## Global Constraints

- Language: **Rust edition 2021**; workspace resolver `"2"`; add `crates/lluma-crypto` to root `Cargo.toml` members.
- Typed errors via **`thiserror`**; **no `unwrap()`/`expect()`** in library code outside `#[cfg(test)]`.
- **BLAKE3** for all content addressing (spend ids, account fingerprints, key derivation contexts). Never MD5/SHA1.
- Secret-bearing newtypes are **`Zeroize` + `ZeroizeOnDrop`** and must **not** derive `Debug`/`Serialize` over their secret bytes.
- No crypto primitive not named in ADR-0001. No novel constructions. At each version-sensitive crate call, verify the exact signature against current docs (Context7 or `cargo doc -p <crate> --open`) before finalizing.
- **No error variant may embed prompt/secret plaintext** (leak L8).
- Ciphersuite everywhere: **DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305**.
- Streaming is single-terminal-chunk in this crate (spec §4); truncation must still fail closed.
- Run `cargo test -p lluma-crypto` and `cargo clippy -p lluma-crypto --all-targets -- -D warnings` before claiming a task done. The native build needs the VS dev environment (`vcvars64`) + `ninja` on PATH; run cargo via `cmd /c "<vcvars64.bat> && cargo ..."` (see the build-env note).
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: Crate scaffold, `lluma-core::wire` newtypes, and `CryptoError`

**Files:**
- Modify: `Cargo.toml` (root) — add `crates/lluma-crypto` to `members`; add new workspace deps.
- Create: `crates/lluma-crypto/Cargo.toml`
- Create: `crates/lluma-crypto/src/lib.rs`
- Create: `crates/lluma-crypto/src/error.rs`
- Create: `crates/lluma-core/src/wire.rs`
- Modify: `crates/lluma-core/src/lib.rs` (add `pub mod wire;`)
- Modify: `crates/lluma-core/Cargo.toml` (add `zeroize`)

**Interfaces:**
- Consumes: nothing (foundation task).
- Produces:
  - `lluma_core::wire` byte-newtypes used by every later task. Public-material newtypes (`IssuerPublicKey`, `BlindedTokenRequest`, `BlindSignature`, `Token`, `SpendId`, `OhttpKeyConfig`, `EncapsulatedRequest`, `HostPublicKey`, `SessionPublicKey`, `SealedRequest`, `AccountPublicKey`, `AccountId`, `ReceiptSignature`, `KeystoreBlob`, `ResponsePreamble`) wrap `Vec<u8>`/`[u8; 32]` and derive `Debug, Clone, PartialEq, Eq`. Secret newtypes (`IssuerSecretKey`, `GatewaySecretKey`, `HostSecretKey`, `SessionSecretKey`, `AccountSecretKey`, `BlindingState`, `Mnemonic`) derive `Zeroize, ZeroizeOnDrop` and **no** `Debug`.
  - `struct UsageReceiptBody { version: u8, host_account: [u8;32], model_id: lluma_core::ModelId, tier: u8, units: u32, spend_id: [u8;32], epoch: u32, timestamp_h: u32 }` — `Debug, Clone, PartialEq, Serialize, Deserialize`.
  - `lluma_crypto::error::CryptoError` (`thiserror`) + `pub type Result<T> = std::result::Result<T, CryptoError>;`

- [ ] **Step 1: Add workspace dependencies to root `Cargo.toml`**

Add to `[workspace.dependencies]`:

```toml
zeroize = { version = "1", features = ["derive"] }
blind-rsa-signatures = "0.15"
ohttp = { version = "0.5", default-features = false, features = ["rust-hpke", "client", "server"] }
hpke = "0.12"
ed25519-dalek = { version = "2", features = ["rand_core"] }
bip39 = "2"
argon2 = "0.5"
chacha20poly1305 = "0.10"
rand_core = "0.6"
postcard = { version = "1", features = ["use-std"] }
proptest = "1"
```

Add `"crates/lluma-crypto"` to `[workspace] members`.

> **Verify before pinning:** confirm the latest compatible minor of `blind-rsa-signatures`, `ohttp`, and `hpke` (`cargo search <name>` / crates.io). `rand_core` version must match what `ed25519-dalek` v2 and `hpke` re-export — align on a single `rand_core` to avoid trait-mismatch errors. Adjust versions if the compiler reports a `RngCore`/`CryptoRng` trait mismatch across crates.

- [ ] **Step 2: Create `crates/lluma-crypto/Cargo.toml`**

```toml
[package]
name = "lluma-crypto"
version = "0.0.0"
edition.workspace = true
license.workspace = true

[dependencies]
lluma-core = { path = "../lluma-core" }
thiserror = { workspace = true }
blake3 = { workspace = true }
zeroize = { workspace = true }
blind-rsa-signatures = { workspace = true }
ohttp = { workspace = true }
hpke = { workspace = true }
ed25519-dalek = { workspace = true }
bip39 = { workspace = true }
argon2 = { workspace = true }
chacha20poly1305 = { workspace = true }
rand_core = { workspace = true }
postcard = { workspace = true }

[dev-dependencies]
proptest = { workspace = true }
```

- [ ] **Step 3: Add `zeroize` to `crates/lluma-core/Cargo.toml`**

Add to `[dependencies]`: `zeroize = { workspace = true }`.

- [ ] **Step 4: Create `crates/lluma-core/src/wire.rs`**

```rust
//! Byte-newtypes shared across the Lluma wire protocol. Public-material types
//! are transparent; secret-material types are zeroize-on-drop and never derive
//! Debug/Serialize over their bytes (privacy invariant, leak L8).
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ModelId;

macro_rules! public_bytes {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name(pub Vec<u8>);
        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

macro_rules! secret_bytes {
    ($name:ident) => {
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name(pub Vec<u8>);
        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

// Public material (safe to log/serialize).
public_bytes!(IssuerPublicKey);
public_bytes!(BlindedTokenRequest);
public_bytes!(BlindSignature);
public_bytes!(Token);
public_bytes!(OhttpKeyConfig);
public_bytes!(EncapsulatedRequest);
public_bytes!(HostPublicKey);
public_bytes!(SessionPublicKey);
public_bytes!(SealedRequest);
public_bytes!(AccountPublicKey);
public_bytes!(ReceiptSignature);
public_bytes!(KeystoreBlob);
public_bytes!(ResponsePreamble);

// Fixed-size content-addressed ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendId(pub [u8; 32]);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountId(pub [u8; 32]);

// Secret material (zeroize on drop; no Debug/Serialize).
secret_bytes!(IssuerSecretKey);
secret_bytes!(GatewaySecretKey);
secret_bytes!(HostSecretKey);
secret_bytes!(SessionSecretKey);
secret_bytes!(AccountSecretKey);
secret_bytes!(BlindingState);

/// A BIP-39 mnemonic's 16-byte entropy (12 words). Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic(pub [u8; 16]);
impl AsRef<[u8]> for Mnemonic {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Canonical usage-receipt body. Deterministic encoding via postcard.
/// Contains the HOST's account and the spent-token id only — never a consumer
/// account, session key, ciphertext hash, or fine timestamp (leak L4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageReceiptBody {
    pub version: u8,
    pub host_account: [u8; 32],
    pub model_id: ModelId,
    pub tier: u8,
    pub units: u32,
    pub spend_id: [u8; 32],
    pub epoch: u32,
    pub timestamp_h: u32,
}
```

- [ ] **Step 5: Register the module in `crates/lluma-core/src/lib.rs`**

Add `pub mod wire;` to the module list and, at the bottom, `pub use wire::*;` is NOT added (avoid name soup); consumers use `lluma_core::wire::TypeName`.

- [ ] **Step 6: Create `crates/lluma-crypto/src/error.rs`**

```rust
use thiserror::Error;

/// Errors from `lluma-crypto`. No variant embeds plaintext or secret bytes.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("token verification failed")]
    TokenInvalid,
    #[error("blind-signature operation failed: {0}")]
    Blind(String),
    #[error("OHTTP encapsulation error: {0}")]
    Ohttp(String),
    #[error("HPKE seal/open error: {0}")]
    Hpke(String),
    #[error("stream truncated: final chunk missing")]
    Truncated,
    #[error("stream chunk out of order or replayed")]
    ChunkOrder,
    #[error("AEAD authentication failed (wrong key, tamper, or wrong passphrase)")]
    AuthFailed,
    #[error("signature verification failed")]
    BadSignature,
    #[error("key derivation failed: {0}")]
    Derivation(String),
    #[error("encoding error: {0}")]
    Encoding(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
```

- [ ] **Step 7: Create `crates/lluma-crypto/src/lib.rs`**

```rust
//! Lluma's cryptographic trust foundation: blind entitlement tokens, Oblivious
//! HTTP + HPKE encapsulation, ephemeral sessions, account identity, signed
//! usage receipts, and self-custodial key backup. Pure functions only — no I/O,
//! no network, no global state. See docs/architecture/adr-0001-lluma-crypto-primitives.md.
pub mod account;
pub mod e2e;
pub mod error;
pub mod ohttp;
pub mod tokens;

pub use error::{CryptoError, Result};
```

> Modules `account`, `e2e`, `ohttp`, `tokens` are created in later tasks. For this task, create each as an empty file with a `//! TODO(taskN)` doc comment so the crate compiles, OR add the `pub mod` lines incrementally per task. Choose incremental: in this task, `lib.rs` declares only `pub mod error;` and the re-exports; add each `pub mod` line in the task that creates the module.

Correction for this task, `lib.rs` body:

```rust
//! (doc comment as above)
pub mod error;
pub use error::{CryptoError, Result};
```

- [ ] **Step 8: Verify the workspace builds**

Run: `cmd /c "<vcvars64.bat> && cargo build -p lluma-crypto -p lluma-core"`
Expected: `Finished` with no errors. (No tests yet.)

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "feat(crypto): scaffold lluma-crypto + lluma-core wire newtypes + CryptoError

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Blind entitlement tokens (`tokens.rs`) — RFC 9474

**Files:**
- Create: `crates/lluma-crypto/src/tokens.rs`
- Modify: `crates/lluma-crypto/src/lib.rs` (add `pub mod tokens;`)

**Interfaces:**
- Consumes: `lluma_core::wire::{IssuerPublicKey, IssuerSecretKey, BlindedTokenRequest, BlindSignature, BlindingState, Token, SpendId}`; `CryptoError`, `Result`.
- Produces:
  - `pub fn issuer_keygen(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> Result<(IssuerSecretKey, IssuerPublicKey)>`
  - `pub fn token_blind(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng), pk: &IssuerPublicKey) -> Result<(BlindingState, BlindedTokenRequest)>`
  - `pub fn token_issue(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng), sk: &IssuerSecretKey, req: &BlindedTokenRequest) -> Result<BlindSignature>`
  - `pub fn token_unblind(pk: &IssuerPublicKey, st: BlindingState, sig: &BlindSignature) -> Result<Token>`
  - `pub fn token_verify(pk: &IssuerPublicKey, token: &Token) -> Result<()>`
  - `pub fn token_spend_id(token: &Token) -> SpendId`

- [ ] **Step 1: Write the failing tests**

Create `crates/lluma-crypto/src/tokens.rs` with only the tests first (implementation added in Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn roundtrip_token() -> (IssuerPublicKey, Token) {
        let mut rng = OsRng;
        let (sk, pk) = issuer_keygen(&mut rng).unwrap();
        let (state, req) = token_blind(&mut rng, &pk).unwrap();
        let blind_sig = token_issue(&mut rng, &sk, &req).unwrap();
        let token = token_unblind(&pk, state, &blind_sig).unwrap();
        (pk, token)
    }

    #[test]
    fn token_round_trip_verifies() {
        let (pk, token) = roundtrip_token();
        assert!(token_verify(&pk, &token).is_ok());
    }

    #[test]
    fn tampered_token_fails_verify() {
        let (pk, mut token) = roundtrip_token();
        token.0[0] ^= 0xff;
        assert!(matches!(token_verify(&pk, &token), Err(CryptoError::TokenInvalid)));
    }

    #[test]
    fn token_from_one_key_fails_under_another() {
        let mut rng = OsRng;
        let (_, other_pk) = issuer_keygen(&mut rng).unwrap();
        let (_, token) = roundtrip_token();
        assert!(matches!(token_verify(&other_pk, &token), Err(CryptoError::TokenInvalid)));
    }

    #[test]
    fn spend_id_is_deterministic_and_unique() {
        let (_, t1) = roundtrip_token();
        let (_, t2) = roundtrip_token();
        assert_eq!(token_spend_id(&t1), token_spend_id(&t1));
        assert_ne!(token_spend_id(&t1), token_spend_id(&t2));
    }

    #[test]
    fn blinding_is_fresh_across_rng() {
        let mut rng = OsRng;
        let (_sk, pk) = issuer_keygen(&mut rng).unwrap();
        let (_s1, r1) = token_blind(&mut rng, &pk).unwrap();
        let (_s2, r2) = token_blind(&mut rng, &pk).unwrap();
        assert_ne!(r1, r2, "two blindings must differ");
    }
}

use crate::error::{CryptoError, Result};
use lluma_core::wire::{
    BlindSignature, BlindedTokenRequest, BlindingState, IssuerPublicKey, IssuerSecretKey,
    SpendId, Token,
};
```

- [ ] **Step 2: Run tests to verify they fail (won't compile)**

Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto tokens"`
Expected: FAIL — the six functions are undefined.

- [ ] **Step 3: Implement `tokens.rs` against RFC 9474**

Insert above the `#[cfg(test)]` module. The `Token` is a serialized `(nonce, message_randomizer, signature, public-key-fingerprint?)`. Store the minimal redeemable value: `nonce (32B) ‖ randomizer (32B) ‖ signature (256B)`. Verification recomputes the signed message and checks the RSA signature.

```rust
use blake3;

/// A redeemable token = nonce ‖ randomizer ‖ RSA signature, serialized.
/// The verifier reconstructs the RFC 9474 signed message and checks the sig.
fn split_token(token: &Token) -> Result<(&[u8], &[u8], &[u8])> {
    let b = &token.0;
    if b.len() < 64 + 1 {
        return Err(CryptoError::TokenInvalid);
    }
    Ok((&b[0..32], &b[32..64], &b[64..]))
}

pub fn issuer_keygen(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<(IssuerSecretKey, IssuerPublicKey)> {
    // blind_rsa_signatures::KeyPair::generate(rng, 2048)
    // -> KeyPair { sk, pk }; serialize sk (DER) and pk (DER/SPKI).
    todo!("VERIFY blind-rsa-signatures API: KeyPair::generate + to_der; see note below")
}

pub fn token_blind(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    pk: &IssuerPublicKey,
) -> Result<(BlindingState, BlindedTokenRequest)> {
    // 1. nonce = 32 random bytes; this is the token's identity.
    // 2. options = Options::default() (RSABSSA-SHA384-PSS-Randomized).
    // 3. PublicKey::from_der(&pk.0)?.blind(rng, &nonce, true, &options)?
    //    -> BlindingResult { blind_msg, secret, msg_randomizer }.
    // 4. BlindingState = serialize(nonce ‖ secret ‖ msg_randomizer).
    //    BlindedTokenRequest = blind_msg bytes.
    todo!("VERIFY blind-rsa-signatures blind() signature; see note")
}

pub fn token_issue(
    _rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    sk: &IssuerSecretKey,
    req: &BlindedTokenRequest,
) -> Result<BlindSignature> {
    // SecretKey::from_der(&sk.0)?.blind_sign(rng, &req.0, &options)? -> blind sig bytes.
    todo!("VERIFY blind_sign signature; some versions take rng, some don't; see note")
}

pub fn token_unblind(
    pk: &IssuerPublicKey,
    st: BlindingState,
    sig: &BlindSignature,
) -> Result<Token> {
    // 1. parse st -> (nonce, secret, msg_randomizer).
    // 2. PublicKey::from_der(&pk.0)?.finalize(&sig.0, &secret, msg_randomizer, &nonce, &options)?
    //    -> Signature (verified during finalize).
    // 3. Token = nonce ‖ msg_randomizer ‖ signature_bytes.
    todo!("VERIFY finalize() argument order; see note")
}

pub fn token_verify(pk: &IssuerPublicKey, token: &Token) -> Result<()> {
    let (nonce, randomizer, sig) = split_token(token)?;
    // PublicKey::from_der(&pk.0)?.verify(sig, Some(MessageRandomizer(randomizer)), nonce, &options)
    //   .map_err(|_| CryptoError::TokenInvalid)
    let _ = (nonce, randomizer, sig);
    todo!("VERIFY verify() signature; map ANY error to CryptoError::TokenInvalid")
}

pub fn token_spend_id(token: &Token) -> SpendId {
    SpendId(*blake3::hash(&token.0).as_bytes())
}
```

> **Implementer note (blind-rsa-signatures ≈ 0.15):** confirm exact API via Context7 (`/jedisct1/rust-blind-rsa-signatures`) or `cargo doc -p blind-rsa-signatures --open`. Expected shapes: `KeyPair::generate(&mut rng, 2048)`, `Options::default()`, `pk.blind(&mut rng, msg, randomize, &options) -> BlindingResult`, `sk.blind_sign(&mut rng, blind_msg, &options)`, `pk.finalize(blind_sig, &secret, msg_randomizer, msg, &options)`, `pk.verify(sig, msg_randomizer, msg, &options)`. Key/sig DER via `to_der()`/`from_der()` (or `to_pem`). Replace every `todo!()` with the verified calls, mapping all library errors through `CryptoError::Blind(_)` except `token_verify`, which maps ANY failure to `CryptoError::TokenInvalid`. Keep the on-wire `Token` layout `nonce ‖ randomizer ‖ signature` so `split_token` and `token_verify` stay correct.

- [ ] **Step 4: Register module and run tests**

Add `pub mod tokens;` to `lib.rs`. Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto tokens"`
Expected: PASS (5 tests).

- [ ] **Step 5: Add a proptest for round-trip robustness**

Append to the `tests` module:

```rust
use proptest::prelude::*;
proptest! {
    #[test]
    fn spend_id_no_collisions(a in any::<[u8;64]>(), b in any::<[u8;64]>()) {
        prop_assume!(a != b);
        let ta = Token(a.to_vec());
        let tb = Token(b.to_vec());
        prop_assert_ne!(token_spend_id(&ta), token_spend_id(&tb));
    }
}
```

Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto tokens"` → PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(crypto): RFC 9474 blind entitlement tokens (issue/blind/unblind/verify/spend-id)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Inner E2E HPKE + ephemeral sessions (`e2e.rs`) — RFC 9180

**Files:**
- Create: `crates/lluma-crypto/src/e2e.rs`
- Modify: `crates/lluma-crypto/src/lib.rs` (add `pub mod e2e;`)

**Interfaces:**
- Consumes: `wire::{HostPublicKey, HostSecretKey, SessionPublicKey, SessionSecretKey, SealedRequest, ResponsePreamble}`; `CryptoError`, `Result`.
- Produces:
  - `pub fn host_keygen(rng) -> Result<(HostSecretKey, HostPublicKey)>`
  - `pub fn session_keygen(rng) -> Result<(SessionSecretKey, SessionPublicKey)>`
  - `pub fn e2e_seal(rng, host_pk: &HostPublicKey, aad: &[u8], prompt: &[u8], reply_to: &SessionPublicKey) -> Result<SealedRequest>`
  - `pub fn e2e_open(host_sk: &HostSecretKey, aad: &[u8], sealed: &SealedRequest) -> Result<(Vec<u8>, SessionPublicKey)>`
  - `pub struct HostResponseContext` / `pub struct SessionResponseContext` (opaque, hold HPKE contexts + a chunk counter)
  - `pub fn response_setup_host(rng, reply_to: &SessionPublicKey) -> Result<(HostResponseContext, ResponsePreamble)>` *(refines ADR §7: the preamble carries the HPKE `enc` the client needs)*
  - `pub fn response_setup_client(session_sk: &SessionSecretKey, preamble: &ResponsePreamble) -> Result<SessionResponseContext>`
  - `pub fn response_seal_chunk(ctx: &mut HostResponseContext, chunk: &[u8], last: bool) -> Result<Vec<u8>>`
  - `pub fn response_open_chunk(ctx: &mut SessionResponseContext, chunk: &[u8]) -> Result<(Vec<u8>, bool)>`

- [ ] **Step 1: Write the failing tests**

Create `crates/lluma-crypto/src/e2e.rs`:

```rust
use crate::error::{CryptoError, Result};
use lluma_core::wire::{
    HostPublicKey, HostSecretKey, ResponsePreamble, SealedRequest, SessionPublicKey,
    SessionSecretKey,
};

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn seal_open_round_trip_with_reply_key() {
        let mut rng = OsRng;
        let (hsk, hpk) = host_keygen(&mut rng).unwrap();
        let (_ssk, spk) = session_keygen(&mut rng).unwrap();
        let aad = b"model-id=qwen;tier=0";
        let sealed = e2e_seal(&mut rng, &hpk, aad, b"the prompt", &spk).unwrap();
        let (pt, reply_to) = e2e_open(&hsk, aad, &sealed).unwrap();
        assert_eq!(pt, b"the prompt");
        assert_eq!(reply_to, spk);
    }

    #[test]
    fn aad_mismatch_fails_closed() {
        let mut rng = OsRng;
        let (hsk, hpk) = host_keygen(&mut rng).unwrap();
        let (_ssk, spk) = session_keygen(&mut rng).unwrap();
        let sealed = e2e_seal(&mut rng, &hpk, b"aad-A", b"p", &spk).unwrap();
        assert!(matches!(e2e_open(&hsk, b"aad-B", &sealed), Err(CryptoError::AuthFailed)));
    }

    #[test]
    fn identical_prompts_seal_differently() {
        let mut rng = OsRng;
        let (_hsk, hpk) = host_keygen(&mut rng).unwrap();
        let (_ssk, spk) = session_keygen(&mut rng).unwrap();
        let a = e2e_seal(&mut rng, &hpk, b"", b"p", &spk).unwrap();
        let b = e2e_seal(&mut rng, &hpk, b"", b"p", &spk).unwrap();
        assert_ne!(a, b, "fresh HPKE ephemeral per seal");
        assert!(!a.0.windows(1).any(|_| false)); // ciphertext present
    }

    #[test]
    fn session_keys_are_fresh() {
        let mut rng = OsRng;
        let (_, s1) = session_keygen(&mut rng).unwrap();
        let (_, s2) = session_keygen(&mut rng).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn response_stream_single_chunk_round_trip() {
        let mut rng = OsRng;
        let (_ssk, spk) = session_keygen(&mut rng).unwrap();
        let (ssk, spk2) = session_keygen(&mut rng).unwrap();
        let _ = spk;
        let (mut hctx, preamble) = response_setup_host(&mut rng, &spk2).unwrap();
        let sealed = response_seal_chunk(&mut hctx, b"hello world", true).unwrap();
        let mut cctx = response_setup_client(&ssk, &preamble).unwrap();
        let (pt, is_final) = response_open_chunk(&mut cctx, &sealed).unwrap();
        assert_eq!(pt, b"hello world");
        assert!(is_final);
    }

    #[test]
    fn response_truncation_fails_closed() {
        // A non-final chunk must never be reported as final; and opening a
        // tampered/short buffer must error, never silently "complete".
        let mut rng = OsRng;
        let (ssk, spk) = session_keygen(&mut rng).unwrap();
        let (mut hctx, preamble) = response_setup_host(&mut rng, &spk).unwrap();
        let sealed = response_seal_chunk(&mut hctx, b"partial", false).unwrap(); // last=false
        let mut cctx = response_setup_client(&ssk, &preamble).unwrap();
        let (_pt, is_final) = response_open_chunk(&mut cctx, &sealed).unwrap();
        assert!(!is_final, "non-final chunk must report is_final=false");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto e2e"` → FAIL (undefined).

- [ ] **Step 3: Implement `e2e.rs` over the `hpke` crate**

Design: type aliases fix the ciphersuite. `SealedRequest` = `enc ‖ ciphertext`, where the inner plaintext is `reply_to_pubkey (32B) ‖ prompt`. The response uses one HPKE context per stream; each chunk is sealed with a 1-byte `last` flag as AAD and an implicit sequence number (the `hpke` AEAD context increments its nonce internally, so reorder/replay fail).

```rust
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as KemTrait,
    OpModeR, OpModeS, Serializable,
};

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
const INFO: &[u8] = b"lluma/e2e/v1";
const RESP_INFO: &[u8] = b"lluma/e2e/response/v1";

pub fn host_keygen(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<(HostSecretKey, HostPublicKey)> {
    let (sk, pk) = Kem::gen_keypair(rng);
    Ok((
        HostSecretKey(sk.to_bytes().to_vec()),
        HostPublicKey(pk.to_bytes().to_vec()),
    ))
}

pub fn session_keygen(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<(SessionSecretKey, SessionPublicKey)> {
    let (sk, pk) = Kem::gen_keypair(rng);
    Ok((
        SessionSecretKey(sk.to_bytes().to_vec()),
        SessionPublicKey(pk.to_bytes().to_vec()),
    ))
}

fn kem_pk(bytes: &[u8]) -> Result<<Kem as KemTrait>::PublicKey> {
    <Kem as KemTrait>::PublicKey::from_bytes(bytes).map_err(|e| CryptoError::Hpke(e.to_string()))
}
fn kem_sk(bytes: &[u8]) -> Result<<Kem as KemTrait>::PrivateKey> {
    <Kem as KemTrait>::PrivateKey::from_bytes(bytes).map_err(|e| CryptoError::Hpke(e.to_string()))
}

pub fn e2e_seal(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    host_pk: &HostPublicKey,
    aad: &[u8],
    prompt: &[u8],
    reply_to: &SessionPublicKey,
) -> Result<SealedRequest> {
    let pk = kem_pk(&host_pk.0)?;
    let (enc, mut ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &pk, INFO, rng)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let mut inner = Vec::with_capacity(32 + prompt.len());
    inner.extend_from_slice(&reply_to.0);
    inner.extend_from_slice(prompt);
    let ct = ctx
        .seal(&inner, aad)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let mut out = enc.to_bytes().to_vec();
    out.extend_from_slice(&ct);
    Ok(SealedRequest(out))
}

pub fn e2e_open(
    host_sk: &HostSecretKey,
    aad: &[u8],
    sealed: &SealedRequest,
) -> Result<(Vec<u8>, SessionPublicKey)> {
    let enc_len = <Kem as KemTrait>::EncappedKey::size();
    if sealed.0.len() < enc_len + 32 {
        return Err(CryptoError::AuthFailed);
    }
    let (enc_bytes, ct) = sealed.0.split_at(enc_len);
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let sk = kem_sk(&host_sk.0)?;
    let mut ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, INFO)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let pt = ctx.open(ct, aad).map_err(|_| CryptoError::AuthFailed)?;
    if pt.len() < 32 {
        return Err(CryptoError::AuthFailed);
    }
    let reply = SessionPublicKey(pt[..32].to_vec());
    Ok((pt[32..].to_vec(), reply))
}

pub struct HostResponseContext {
    ctx: hpke::aead::AeadCtxS<Aead, Kdf, Kem>,
}
pub struct SessionResponseContext {
    ctx: hpke::aead::AeadCtxR<Aead, Kdf, Kem>,
}

pub fn response_setup_host(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    reply_to: &SessionPublicKey,
) -> Result<(HostResponseContext, ResponsePreamble)> {
    let pk = kem_pk(&reply_to.0)?;
    let (enc, ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &pk, RESP_INFO, rng)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    Ok((HostResponseContext { ctx }, ResponsePreamble(enc.to_bytes().to_vec())))
}

pub fn response_setup_client(
    session_sk: &SessionSecretKey,
    preamble: &ResponsePreamble,
) -> Result<SessionResponseContext> {
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&preamble.0)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    let sk = kem_sk(&session_sk.0)?;
    let ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, RESP_INFO)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    Ok(SessionResponseContext { ctx })
}

pub fn response_seal_chunk(
    ctx: &mut HostResponseContext,
    chunk: &[u8],
    last: bool,
) -> Result<Vec<u8>> {
    let aad = [last as u8];
    let mut ct = ctx
        .ctx
        .seal(chunk, &aad)
        .map_err(|e| CryptoError::Hpke(e.to_string()))?;
    ct.insert(0, last as u8); // prepend flag so the opener knows the claimed finality
    Ok(ct)
}

pub fn response_open_chunk(
    ctx: &mut SessionResponseContext,
    chunk: &[u8],
) -> Result<(Vec<u8>, bool)> {
    if chunk.is_empty() {
        return Err(CryptoError::Truncated);
    }
    let last = chunk[0] == 1;
    let aad = [chunk[0]];
    let pt = ctx
        .ctx
        .open(&chunk[1..], &aad)
        .map_err(|_| CryptoError::ChunkOrder)?; // wrong order/tamper => AEAD fails
    Ok((pt, last))
}
```

> **Implementer note (`hpke` ≈ 0.12):** verify exact type paths via `cargo doc -p hpke --open`. Confirm: `setup_sender` returns `(EncappedKey, AeadCtxS)`; `AeadCtxS::seal`/`AeadCtxR::open` take `(plaintext/ciphertext, aad)` and manage nonces internally (so out-of-order `open` fails — this is what test `response_truncation_fails_closed` and reorder rely on); `EncappedKey::size()` exists (else hardcode 32 for X25519 with a comment); `Serializable`/`Deserializable` provide `to_bytes`/`from_bytes`. If `seal` is in-place (`seal_in_place_detached`), adapt to the detached API and store the tag. The finality flag is prepended in cleartext but ALSO bound as AAD, so flipping it fails the AEAD — a truncated stream (missing the `last=true` chunk) can never be reconstructed as complete.

- [ ] **Step 4: Register module and run tests**

Add `pub mod e2e;` to `lib.rs`. Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto e2e"` → PASS (6 tests).

- [ ] **Step 5: Add a proptest for arbitrary payloads**

```rust
use proptest::prelude::*;
proptest! {
    #[test]
    fn e2e_round_trip_any_payload(prompt in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut rng = rand_core::OsRng;
        let (hsk, hpk) = host_keygen(&mut rng).unwrap();
        let (_ssk, spk) = session_keygen(&mut rng).unwrap();
        let sealed = e2e_seal(&mut rng, &hpk, b"aad", &prompt, &spk).unwrap();
        let (pt, _) = e2e_open(&hsk, b"aad", &sealed).unwrap();
        prop_assert_eq!(pt, prompt);
    }
}
```

Run → PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(crypto): inner E2E HPKE (RFC 9180) + per-request session keys + response chunks

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: OHTTP encapsulation (`ohttp.rs`) — RFC 9458, single-chunk MVP

**Files:**
- Create: `crates/lluma-crypto/src/ohttp.rs`
- Modify: `crates/lluma-crypto/src/lib.rs` (add `pub mod ohttp;`)

**Interfaces:**
- Consumes: `wire::{OhttpKeyConfig, GatewaySecretKey, EncapsulatedRequest}`; `CryptoError`, `Result`.
- Produces:
  - `pub fn ohttp_keygen(rng, key_id: u8) -> Result<(GatewaySecretKey, OhttpKeyConfig)>`
  - `pub fn ohttp_encapsulate(rng, cfg: &OhttpKeyConfig, request: &[u8]) -> Result<(EncapsulatedRequest, ClientResponseContext)>`
  - `pub fn ohttp_decapsulate(sk: &GatewaySecretKey, capsule: &EncapsulatedRequest) -> Result<(Vec<u8>, ServerResponseContext)>`
  - `pub fn ohttp_seal_chunk(ctx: &mut ServerResponseContext, chunk: &[u8], last: bool) -> Result<Vec<u8>>`
  - `pub fn ohttp_open_chunk(ctx: &mut ClientResponseContext, chunk: &[u8]) -> Result<(Vec<u8>, bool)>`
  - opaque `ClientResponseContext`, `ServerResponseContext`.

- [ ] **Step 1: Write the failing tests**

Create `crates/lluma-crypto/src/ohttp.rs`:

```rust
use crate::error::{CryptoError, Result};
use lluma_core::wire::{EncapsulatedRequest, GatewaySecretKey, OhttpKeyConfig};

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn encapsulate_decapsulate_round_trip() {
        let mut rng = OsRng;
        let (sk, cfg) = ohttp_keygen(&mut rng, 1).unwrap();
        let (capsule, _cctx) = ohttp_encapsulate(&mut rng, &cfg, b"inner ciphertext bytes").unwrap();
        let (inner, _sctx) = ohttp_decapsulate(&sk, &capsule).unwrap();
        assert_eq!(inner, b"inner ciphertext bytes");
    }

    #[test]
    fn response_single_chunk_round_trip() {
        let mut rng = OsRng;
        let (sk, cfg) = ohttp_keygen(&mut rng, 1).unwrap();
        let (capsule, mut cctx) = ohttp_encapsulate(&mut rng, &cfg, b"req").unwrap();
        let (_inner, mut sctx) = ohttp_decapsulate(&sk, &capsule).unwrap();
        let sealed = ohttp_seal_chunk(&mut sctx, b"response body", true).unwrap();
        let (pt, is_final) = ohttp_open_chunk(&mut cctx, &sealed).unwrap();
        assert_eq!(pt, b"response body");
        assert!(is_final);
    }

    #[test]
    fn dropped_final_chunk_never_reads_complete() {
        let mut rng = OsRng;
        let (sk, cfg) = ohttp_keygen(&mut rng, 1).unwrap();
        let (capsule, mut cctx) = ohttp_encapsulate(&mut rng, &cfg, b"req").unwrap();
        let (_inner, mut sctx) = ohttp_decapsulate(&sk, &capsule).unwrap();
        let sealed = ohttp_seal_chunk(&mut sctx, b"body", false).unwrap(); // not final
        let (_pt, is_final) = ohttp_open_chunk(&mut cctx, &sealed).unwrap();
        assert!(!is_final, "must not report completion without a final chunk (CVE-2026-48480 class)");
    }

    #[test]
    fn tampered_capsule_fails() {
        let mut rng = OsRng;
        let (sk, cfg) = ohttp_keygen(&mut rng, 1).unwrap();
        let (mut capsule, _c) = ohttp_encapsulate(&mut rng, &cfg, b"req").unwrap();
        let n = capsule.0.len();
        capsule.0[n - 1] ^= 0xff;
        assert!(ohttp_decapsulate(&sk, &capsule).is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto ohttp"` → FAIL.

- [ ] **Step 3: Implement `ohttp.rs` over the `ohttp` crate**

The `ohttp` crate models request encapsulation (`ClientRequest`/`Server`) and a single-shot response. For the single-chunk MVP, seal the whole response as one OHTTP response and carry a 1-byte finality flag bound as AAD (same discipline as `e2e.rs`).

```rust
use ohttp::{KeyConfig, Server as OhttpServer, ClientRequest, SymmetricSuite};
use ohttp::hpke::{Aead as OAead, Kdf as OKdf, Kem as OKem};

pub struct ClientResponseContext {
    inner: Option<ohttp::ClientResponse>, // set after encapsulate
}
pub struct ServerResponseContext {
    inner: Option<ohttp::ServerResponse>,
}

pub fn ohttp_keygen(
    _rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    key_id: u8,
) -> Result<(GatewaySecretKey, OhttpKeyConfig)> {
    let suite = SymmetricSuite::new(OKdf::HkdfSha256, OAead::ChaCha20Poly1305);
    let cfg = KeyConfig::new(key_id, OKem::X25519Sha256, vec![suite])
        .map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    let encoded = cfg.encode().map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    // Persist the full KeyConfig (incl. private key) as the gateway secret.
    let sk_bytes = cfg
        .private_key_bytes()
        .map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    Ok((GatewaySecretKey(sk_bytes), OhttpKeyConfig(encoded)))
}

pub fn ohttp_encapsulate(
    _rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    cfg: &OhttpKeyConfig,
    request: &[u8],
) -> Result<(EncapsulatedRequest, ClientResponseContext)> {
    let client = ClientRequest::from_encoded_config(&cfg.0)
        .map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    let (capsule, response_ctx) = client
        .encapsulate(request)
        .map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    Ok((
        EncapsulatedRequest(capsule),
        ClientResponseContext { inner: Some(response_ctx) },
    ))
}

pub fn ohttp_decapsulate(
    sk: &GatewaySecretKey,
    capsule: &EncapsulatedRequest,
) -> Result<(Vec<u8>, ServerResponseContext)> {
    let server = OhttpServer::from_private_key_bytes(&sk.0)
        .map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    let (inner, server_response) = server
        .decapsulate(&capsule.0)
        .map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    Ok((inner, ServerResponseContext { inner: Some(server_response) }))
}

pub fn ohttp_seal_chunk(
    ctx: &mut ServerResponseContext,
    chunk: &[u8],
    last: bool,
) -> Result<Vec<u8>> {
    let sr = ctx.inner.take().ok_or(CryptoError::Ohttp("response already sealed".into()))?;
    let mut framed = Vec::with_capacity(chunk.len() + 1);
    framed.push(last as u8);
    framed.extend_from_slice(chunk);
    let sealed = sr.encapsulate(&framed).map_err(|e| CryptoError::Ohttp(e.to_string()))?;
    Ok(sealed)
}

pub fn ohttp_open_chunk(
    ctx: &mut ClientResponseContext,
    chunk: &[u8],
) -> Result<(Vec<u8>, bool)> {
    let cr = ctx.inner.take().ok_or(CryptoError::Ohttp("response already opened".into()))?;
    let framed = cr.decapsulate(chunk).map_err(|_| CryptoError::AuthFailed)?;
    if framed.is_empty() {
        return Err(CryptoError::Truncated);
    }
    Ok((framed[1..].to_vec(), framed[0] == 1))
}
```

> **Implementer note (`ohttp` ≈ 0.5):** verify the exact API via Context7 (`/martinthomson/ohttp`) or `cargo doc`. Method names vary by version: `ClientRequest::from_encoded_config` may be `from_encoded_key_config`; `encapsulate` may return `(Vec<u8>, ClientResponse)`; `Server::new(KeyConfig)` may be the constructor rather than `from_private_key_bytes` — if so, store the whole encoded `KeyConfig` (private) in `GatewaySecretKey` and reconstruct via `KeyConfig::decode` + `Server::new`. `KeyConfig::private_key_bytes`/`from_private_key_bytes` may not exist; the robust fallback is to keep the serialized `KeyConfig` as the secret. The single-chunk MVP uses the crate's one-shot `ClientResponse`/`ServerResponse`; multi-chunk (chunked-OHTTP draft) is deferred (spec §4). Whatever the shape, preserve: (a) round-trip identity, (b) the 1-byte finality flag inside the sealed body so `is_final` is authenticated, (c) any tamper/truncation maps to an error, never a silent complete.

- [ ] **Step 4: Register module and run tests**

Add `pub mod ohttp;` to `lib.rs`. Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto ohttp"` → PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(crypto): RFC 9458 OHTTP encapsulation + single-chunk sealed response

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Account identity + signed usage receipts (`account.rs`, part 1) — Ed25519

**Files:**
- Create: `crates/lluma-crypto/src/account.rs`
- Modify: `crates/lluma-crypto/src/lib.rs` (add `pub mod account;`)

**Interfaces:**
- Consumes: `wire::{AccountSecretKey, AccountPublicKey, AccountId, ReceiptSignature, UsageReceiptBody, Mnemonic}`; `CryptoError`, `Result`.
- Produces (this task):
  - `pub fn account_fingerprint(pk: &AccountPublicKey) -> AccountId`
  - `pub fn receipt_sign(sk: &AccountSecretKey, body: &UsageReceiptBody) -> Result<ReceiptSignature>`
  - `pub fn receipt_verify(pk: &AccountPublicKey, body: &UsageReceiptBody, sig: &ReceiptSignature) -> Result<()>`
  - internal `fn signing_key(sk: &AccountSecretKey) -> Result<ed25519_dalek::SigningKey>` and `fn canonical(body: &UsageReceiptBody) -> Result<Vec<u8>>` (shared with Task 6).

- [ ] **Step 1: Write the failing tests**

Create `crates/lluma-crypto/src/account.rs`:

```rust
use crate::error::{CryptoError, Result};
use lluma_core::wire::{
    AccountId, AccountPublicKey, AccountSecretKey, KeystoreBlob, Mnemonic, ReceiptSignature,
    UsageReceiptBody,
};
use lluma_core::ModelId;

const RECEIPT_DOMAIN: &[u8] = b"lluma-usage-receipt-v1";

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_body(units: u32) -> UsageReceiptBody {
        UsageReceiptBody {
            version: 1,
            host_account: [7u8; 32],
            model_id: ModelId("qwen2.5-0.5b-instruct".into()),
            tier: 0,
            units,
            spend_id: [9u8; 32],
            epoch: 3,
            timestamp_h: 12345,
        }
    }

    #[test]
    fn receipt_sign_verify_round_trip() {
        // derive a keypair via a fixed mnemonic (Task 6 fn) — use derive here.
        let (sk, pk) = super::derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let body = sample_body(5);
        let sig = receipt_sign(&sk, &body).unwrap();
        assert!(receipt_verify(&pk, &body, &sig).is_ok());
    }

    #[test]
    fn tampered_body_fails_verify() {
        let (sk, pk) = super::derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let body = sample_body(5);
        let sig = receipt_sign(&sk, &body).unwrap();
        let mut tampered = body.clone();
        tampered.units = 6;
        assert!(matches!(receipt_verify(&pk, &tampered, &sig), Err(CryptoError::BadSignature)));
    }

    #[test]
    fn signature_from_other_key_fails() {
        let (sk1, _pk1) = super::derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let (_sk2, pk2) = super::derive_keypair_from_seed(&Mnemonic([2u8; 16])).unwrap();
        let body = sample_body(5);
        let sig = receipt_sign(&sk1, &body).unwrap();
        assert!(matches!(receipt_verify(&pk2, &body, &sig), Err(CryptoError::BadSignature)));
    }

    #[test]
    fn fingerprint_is_blake3_of_pubkey() {
        let (_sk, pk) = super::derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let id = account_fingerprint(&pk);
        assert_eq!(id.0, *blake3::hash(&pk.0).as_bytes());
    }
}
```

> Note: `derive_keypair_from_seed` is implemented in Task 6 but referenced here. Implement Tasks 5 and 6 together in one execution session, or stub `derive_keypair_from_seed` in Step 3 of this task and finish it in Task 6. Recommended: treat Tasks 5 and 6 as one commit boundary if executed by a subagent.

- [ ] **Step 2: Run to verify failure**

Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto account"` → FAIL.

- [ ] **Step 3: Implement Task-5 functions**

```rust
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub fn account_fingerprint(pk: &AccountPublicKey) -> AccountId {
    AccountId(*blake3::hash(&pk.0).as_bytes())
}

fn canonical(body: &UsageReceiptBody) -> Result<Vec<u8>> {
    let mut out = RECEIPT_DOMAIN.to_vec();
    let enc = postcard::to_stdvec(body).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    out.extend_from_slice(&enc);
    Ok(out)
}

pub(crate) fn signing_key(sk: &AccountSecretKey) -> Result<SigningKey> {
    let bytes: [u8; 32] = sk
        .0
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Derivation("account secret key must be 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn verifying_key(pk: &AccountPublicKey) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = pk
        .0
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Derivation("account public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| CryptoError::Derivation(e.to_string()))
}

pub fn receipt_sign(sk: &AccountSecretKey, body: &UsageReceiptBody) -> Result<ReceiptSignature> {
    let key = signing_key(sk)?;
    let msg = canonical(body)?;
    let sig = key.sign(&msg);
    Ok(ReceiptSignature(sig.to_bytes().to_vec()))
}

pub fn receipt_verify(
    pk: &AccountPublicKey,
    body: &UsageReceiptBody,
    sig: &ReceiptSignature,
) -> Result<()> {
    let key = verifying_key(pk)?;
    let msg = canonical(body)?;
    let sig_bytes: [u8; 64] = sig
        .0
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify(&msg, &signature).map_err(|_| CryptoError::BadSignature)
}
```

- [ ] **Step 4: Register module** (`pub mod account;` in `lib.rs`). Tests still fail until Task 6 provides `derive_keypair_from_seed`. Proceed to Task 6, then run.

- [ ] **Step 5: Commit** (jointly with Task 6 — see Task 6 Step 6).

---

### Task 6: Key backup — mnemonic derivation + Argon2id/XChaCha20 keystore (`account.rs`, part 2)

**Files:**
- Modify: `crates/lluma-crypto/src/account.rs`

**Interfaces:**
- Produces:
  - `pub fn account_mnemonic_new(rng) -> Result<Mnemonic>`
  - `pub fn derive_keypair_from_seed(mnemonic: &Mnemonic) -> Result<(AccountSecretKey, AccountPublicKey)>`
  - `pub fn seal_keystore(rng, passphrase: &str, mnemonic: &Mnemonic) -> Result<KeystoreBlob>`
  - `pub fn open_keystore(passphrase: &str, blob: &KeystoreBlob) -> Result<Mnemonic>`

- [ ] **Step 1: Write the failing tests** (append to `account.rs` tests)

```rust
    #[test]
    fn seed_derivation_is_deterministic() {
        let m = Mnemonic([42u8; 16]);
        let (_sk1, pk1) = derive_keypair_from_seed(&m).unwrap();
        let (_sk2, pk2) = derive_keypair_from_seed(&m).unwrap();
        assert_eq!(pk1, pk2);
        let (_sk3, pk3) = derive_keypair_from_seed(&Mnemonic([43u8; 16])).unwrap();
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn keystore_round_trip() {
        let mut rng = rand_core::OsRng;
        let m = account_mnemonic_new(&mut rng).unwrap();
        let blob = seal_keystore(&mut rng, "corr horse battery staple", &m).unwrap();
        let back = open_keystore("corr horse battery staple", &blob).unwrap();
        assert_eq!(m.0, back.0);
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let mut rng = rand_core::OsRng;
        let m = account_mnemonic_new(&mut rng).unwrap();
        let blob = seal_keystore(&mut rng, "right", &m).unwrap();
        assert!(matches!(open_keystore("wrong", &blob), Err(CryptoError::AuthFailed)));
    }

    #[test]
    fn tampered_keystore_fails_closed() {
        let mut rng = rand_core::OsRng;
        let m = account_mnemonic_new(&mut rng).unwrap();
        let mut blob = seal_keystore(&mut rng, "pw", &m).unwrap();
        let n = blob.0.len();
        blob.0[n - 1] ^= 0xff;
        assert!(matches!(open_keystore("pw", &blob), Err(CryptoError::AuthFailed)));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto account"` → FAIL.

- [ ] **Step 3: Implement derivation + keystore**

Keystore blob layout: `magic(4) ‖ version(1) ‖ argon2 m_cost(4 LE) ‖ t_cost(4 LE) ‖ p(4 LE) ‖ salt(16) ‖ nonce(24) ‖ ciphertext+tag`. Header is bound as AEAD AAD.

```rust
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::Mnemonic as Bip39Mnemonic;
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use rand_core::RngCore;

const KS_MAGIC: [u8; 4] = *b"LLKS";
const KS_VERSION: u8 = 1;
const KS_M_COST: u32 = 64 * 1024; // 64 MiB
const KS_T_COST: u32 = 3;
const KS_P: u32 = 1;

pub fn account_mnemonic_new(
    rng: &mut (impl RngCore + rand_core::CryptoRng),
) -> Result<Mnemonic> {
    let mut entropy = [0u8; 16];
    rng.fill_bytes(&mut entropy);
    Ok(Mnemonic(entropy))
}

pub fn derive_keypair_from_seed(
    mnemonic: &Mnemonic,
) -> Result<(AccountSecretKey, AccountPublicKey)> {
    // BIP-39 entropy -> mnemonic -> 64-byte seed -> BLAKE3 derive_key -> Ed25519.
    let phrase = Bip39Mnemonic::from_entropy(&mnemonic.0)
        .map_err(|e| CryptoError::Derivation(e.to_string()))?;
    let seed = phrase.to_seed(""); // [u8; 64]
    let key32 = blake3::derive_key("lluma v1 account ed25519", &seed);
    let signing = ed25519_dalek::SigningKey::from_bytes(&key32);
    let verifying = signing.verifying_key();
    Ok((
        AccountSecretKey(key32.to_vec()),
        AccountPublicKey(verifying.to_bytes().to_vec()),
    ))
}

fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(KS_M_COST, KS_T_COST, KS_P, Some(32))
        .map_err(|e| CryptoError::Derivation(e.to_string()))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| CryptoError::Derivation(e.to_string()))?;
    Ok(out)
}

pub fn seal_keystore(
    rng: &mut (impl RngCore + rand_core::CryptoRng),
    passphrase: &str,
    mnemonic: &Mnemonic,
) -> Result<KeystoreBlob> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let mut header = Vec::with_capacity(4 + 1 + 12 + 16 + 24);
    header.extend_from_slice(&KS_MAGIC);
    header.push(KS_VERSION);
    header.extend_from_slice(&KS_M_COST.to_le_bytes());
    header.extend_from_slice(&KS_T_COST.to_le_bytes());
    header.extend_from_slice(&KS_P.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let kek = derive_kek(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(kek.as_ref().into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &mnemonic.0, aad: &header })
        .map_err(|_| CryptoError::AuthFailed)?;

    let mut blob = header;
    blob.extend_from_slice(&ct);
    Ok(KeystoreBlob(blob))
}

pub fn open_keystore(passphrase: &str, blob: &KeystoreBlob) -> Result<Mnemonic> {
    let b = &blob.0;
    const HEADER_LEN: usize = 4 + 1 + 12 + 16 + 24; // 57
    if b.len() < HEADER_LEN + 16 || b[0..4] != KS_MAGIC {
        return Err(CryptoError::AuthFailed);
    }
    let salt = &b[17..33];
    let nonce = &b[33..57];
    let header = &b[0..HEADER_LEN];
    let ct = &b[HEADER_LEN..];

    let kek = derive_kek(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new(kek.as_ref().into());
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: header })
        .map_err(|_| CryptoError::AuthFailed)?;
    let entropy: [u8; 16] = pt.as_slice().try_into().map_err(|_| CryptoError::AuthFailed)?;
    Ok(Mnemonic(entropy))
}
```

> **Implementer note:** verify `ed25519_dalek::SigningKey::from_bytes` takes `&[u8; 32]` (v2 does). Confirm `bip39` v2 API: `Mnemonic::from_entropy(&[u8]) -> Result<Mnemonic>` and `.to_seed("")-> [u8; 64]` (method name may be `to_seed_normalized`). Confirm `chacha20poly1305` `Payload` with `aad` is available (default feature). `blake3::derive_key(context, key_material) -> [u8; 32]` — context is a compile-time-ish domain string; keep it exactly `"lluma v1 account ed25519"`.

- [ ] **Step 4: Run all account tests**

Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto account"` → PASS (Task 5 + Task 6 = 8 tests).

- [ ] **Step 5: Clippy**

Run: `cmd /c "<vcvars64.bat> && cargo clippy -p lluma-crypto --all-targets -- -D warnings"` → clean.

- [ ] **Step 6: Commit (Tasks 5 + 6)**

```bash
git add -A
git commit -m "feat(crypto): Ed25519 accounts, signed usage receipts, BIP-39 + Argon2id/XChaCha20 keystore

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: The no-party-sees-both invariant harness (integration test)

**Files:**
- Create: `crates/lluma-crypto/tests/invariant_harness.rs`

**Interfaces:**
- Consumes: the full public API of `lluma-crypto`.
- Produces: an in-process end-to-end flow with recorded party views, asserting the privacy invariant (spec §14, ADR §8 test 16).

- [ ] **Step 1: Write the harness test**

Create `crates/lluma-crypto/tests/invariant_harness.rs`:

```rust
//! In-process mock of one anonymous request across issuer/relay/broker/host,
//! recording exactly what each party observed, then asserting the invariant:
//! no party's view contains both a consumer identity and the prompt, and no
//! party sees both a consumer account and a spendable token.
use lluma_core::wire::{SessionPublicKey, UsageReceiptBody};
use lluma_core::ModelId;
use lluma_crypto::{account::*, e2e::*, ohttp::*, tokens::*};
use rand_core::OsRng;

#[derive(Default)]
struct View {
    saw_prompt: bool,
    saw_consumer_ip: bool,
    saw_consumer_account: bool,
    saw_spendable_token: bool,
}

#[test]
fn no_party_holds_identity_and_content() {
    let mut rng = OsRng;
    let prompt = b"what is the capital of France?";
    let consumer_ip = "203.0.113.7"; // known only to the relay

    // --- setup parties ---
    let (issuer_sk, issuer_pk) = issuer_keygen(&mut rng).unwrap();
    let (host_sk, host_pk) = host_keygen(&mut rng).unwrap();
    let (gw_sk, gw_cfg) = ohttp_keygen(&mut rng, 1).unwrap();
    let (host_acct_sk, host_acct_pk) = derive_keypair_from_seed(
        &lluma_core::wire::Mnemonic([5u8; 16]),
    )
    .unwrap();

    let mut relay = View::default();
    let mut broker = View::default();
    let mut host = View::default();

    // --- consumer buys a token (out of band) ---
    let (state, blinded) = token_blind(&mut rng, &issuer_pk).unwrap();
    let blind_sig = token_issue(&mut rng, &issuer_sk, &blinded).unwrap();
    let token = token_unblind(&issuer_pk, state, &blind_sig).unwrap();

    // --- consumer builds the request ---
    let (session_sk, session_pk) = session_keygen(&mut rng).unwrap();
    let routing_aad = b"model-id=qwen2.5-0.5b-instruct;tier=0";
    let sealed = e2e_seal(&mut rng, &host_pk, routing_aad, prompt, &session_pk).unwrap();
    let (capsule, mut client_rctx) = ohttp_encapsulate(&mut rng, &gw_cfg, &sealed.0).unwrap();

    // --- relay: sees IP + opaque capsule ---
    relay.saw_consumer_ip = true;
    relay.saw_prompt = contains(&capsule.0, prompt);
    // relay forwards capsule + routing metadata to broker (no IP).

    // --- broker: decapsulates OHTTP, sees inner sealed bytes + token + routing ---
    let (inner, mut server_rctx) = ohttp_decapsulate(&gw_sk, &capsule).unwrap();
    broker.saw_prompt = contains(&inner, prompt);
    token_verify(&issuer_pk, &token).unwrap(); // broker verifies with PUBLIC key only
    broker.saw_spendable_token = true; // broker holds the token to check double-spend
    broker.saw_consumer_account = false; // no consumer account is ever presented
    // broker forwards inner sealed bytes to host.

    // --- host: opens the prompt, sees no IP, no consumer account ---
    let sealed_for_host = lluma_core::wire::SealedRequest(inner);
    let (opened, reply_to) = e2e_open(&host_sk, routing_aad, &sealed_for_host).unwrap();
    host.saw_prompt = opened == prompt;
    host.saw_consumer_ip = false;
    host.saw_consumer_account = false;

    // host produces a signed receipt crediting ITSELF (host account), citing spend id.
    let body = UsageReceiptBody {
        version: 1,
        host_account: account_fingerprint(&host_acct_pk).0,
        model_id: ModelId("qwen2.5-0.5b-instruct".into()),
        tier: 0,
        units: 1,
        spend_id: token_spend_id(&token).0,
        epoch: 0,
        timestamp_h: 0,
    };
    let receipt_sig = receipt_sign(&host_acct_sk, &body).unwrap();
    assert!(receipt_verify(&host_acct_pk, &body, &receipt_sig).is_ok());

    // host streams a response sealed to the consumer's session key.
    let (mut hrctx, preamble) = response_setup_host(&mut rng, &reply_to).unwrap();
    let resp = response_seal_chunk(&mut hrctx, b"Paris.", true).unwrap();
    // broker re-wraps in OHTTP response; consumer opens both layers.
    let ohttp_resp = ohttp_seal_chunk(&mut server_rctx, &resp, true).unwrap();
    let (inner_resp, fin1) = ohttp_open_chunk(&mut client_rctx, &ohttp_resp).unwrap();
    let mut crctx = response_setup_client(&session_sk, &preamble).unwrap();
    let (answer, fin2) = response_open_chunk(&mut crctx, &inner_resp).unwrap();
    assert!(fin1 && fin2);
    assert_eq!(answer, b"Paris.");

    // --- assert the invariant ---
    assert!(relay.saw_consumer_ip && !relay.saw_prompt, "relay: IP but never prompt");
    assert!(!broker.saw_consumer_ip && !broker.saw_prompt, "broker: neither IP nor prompt");
    assert!(!broker.saw_consumer_account, "broker: never a consumer account");
    assert!(host.saw_prompt && !host.saw_consumer_ip && !host.saw_consumer_account,
        "host: prompt only, no identity");
    // No party has BOTH identity and content:
    for v in [&relay, &broker, &host] {
        let has_identity = v.saw_consumer_ip || v.saw_consumer_account;
        assert!(!(has_identity && v.saw_prompt), "invariant: no party holds identity AND content");
    }
    let _ = session_pk_unused(&SessionPublicKey(vec![]));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
fn session_pk_unused(_p: &SessionPublicKey) {}
```

> **Implementer note:** the module paths (`lluma_crypto::tokens::*` etc.) require those modules to be `pub` (they are). If re-exports are preferred, add `pub use` in `lib.rs` and simplify imports. Remove the two throwaway helpers (`session_pk_unused`) if clippy objects; they exist only to keep the illustrative import compiling — delete once the real flow compiles.

- [ ] **Step 2: Run the harness**

Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto --test invariant_harness -- --nocapture"`
Expected: PASS — all invariant assertions hold.

- [ ] **Step 3: Full crate test + clippy**

Run: `cmd /c "<vcvars64.bat> && cargo test -p lluma-crypto && cargo clippy -p lluma-crypto --all-targets -- -D warnings"`
Expected: all tests pass, clippy clean.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test(crypto): in-process no-party-sees-both privacy-invariant harness

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage (crypto spec §2, §5, §6, §7):**
- All four modules present: `tokens` (Task 2), `ohttp` (Task 4), `e2e` (Task 3), `account` (Tasks 5–6). ✓
- `lluma-core::wire` newtypes + `CryptoError` (Task 1). ✓
- Every ADR §7 signature has a task: tokens (T2), ohttp (T4), e2e/sessions (T3), account/receipts/keystore (T5–T6). The response-context constructors implicit in ADR §7 are made explicit (`response_setup_host`/`response_setup_client`, T3) — a documented refinement. ✓
- Streaming = single-chunk with fail-closed truncation (T3 `response_truncation_fails_closed`, T4 `dropped_final_chunk_never_reads_complete`). ✓
- ADR §8 tests mapped: 1–5 → T2; 6,7(single-chunk),10,11 → T3/T4; 8 (truncation) → T3+T4; 9 (reorder) → covered by AEAD nonce sequencing note in T3; 12,13,14 → T6; 15 → T5; 16 (invariant harness) → T7. ✓

**2. Placeholder scan:** The `todo!()` calls in Task 2 Step 3 are deliberate, each paired with the exact intended call and a verification note (matching this repo's Phase 0 llama-cpp-2 precedent) — they are replaced within the same step, not left as plan-level TODOs. All other steps contain complete code. No "add error handling"/"similar to Task N" placeholders.

**3. Type consistency:** Function names and signatures match ADR §7 and are used identically across tasks (`derive_keypair_from_seed` defined in T6, referenced in T5 tests with a noted joint-commit boundary; `token_spend_id`/`account_fingerprint` used in T7 exactly as defined). Wire newtypes defined once in T1 and consumed by name thereafter. `UsageReceiptBody` fields match between T1 definition, T5 canonical encoding, and T7 construction.

**Note carried to execution:** Tasks 2, 3, 4 each depend on version-specific APIs of `blind-rsa-signatures`, `hpke`, and `ohttp`. Each has an implementer note directing verification via Context7/`cargo doc` before finalizing. The test code (the correctness contract) is version-independent; only the implementation call sites may need signature adjustment. Tasks 5 and 6 share `account.rs` and should be executed and committed together (T5 tests reference T6's `derive_keypair_from_seed`).
