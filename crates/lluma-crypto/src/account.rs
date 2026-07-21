//! Account identity, signed usage receipts, and self-custodial key backup.
//!
//! Task 5 (Ed25519 account identity + signed usage receipts) and Task 6
//! (BIP-39 mnemonic derivation + Argon2id / XChaCha20-Poly1305 keystore)
//! share this file because Task 5's tests reference `derive_keypair_from_seed`,
//! which Task 6 defines. See `.superpowers/sdd/task-5-brief.md` and
//! `task-6-brief.md`.

use crate::error::{CryptoError, Result};
use lluma_core::wire::{
    AccountId, AccountPublicKey, AccountSecretKey, HeartbeatBody, HostRegisterBody,
    IssueRequestBody, IssueSignature, KeystoreBlob, Mnemonic, ReceiptSignature, UsageReceiptBody,
};

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::Mnemonic as Bip39Mnemonic;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};

const RECEIPT_DOMAIN: &[u8] = b"lluma-usage-receipt-v1";
const ISSUE_REQUEST_DOMAIN: &[u8] = b"lluma-issue-request-v1";
const HOST_REGISTER_DOMAIN: &[u8] = b"lluma-host-register-v1";
const HEARTBEAT_DOMAIN: &[u8] = b"lluma-heartbeat-v1";
const SNAPSHOT_DOMAIN: &[u8] = b"lluma-registry-snapshot-v1";

// Keystore blob layout:
//   magic(4) ‖ version(1) ‖ argon2 m_cost(4 LE) ‖ t_cost(4 LE) ‖ p(4 LE)
//   ‖ salt(16) ‖ nonce(24) ‖ ciphertext+tag
// The header (everything up to and including the nonce) is bound as AEAD AAD.
const KS_MAGIC: [u8; 4] = *b"LLKS";
const KS_VERSION: u8 = 1;
const KS_M_COST: u32 = 64 * 1024; // 64 MiB, expressed in KiB (argon2 unit)
const KS_T_COST: u32 = 3;
const KS_P: u32 = 1;
const KS_SALT_LEN: usize = 16;
const KS_NONCE_LEN: usize = 24;
// magic + version + m_cost + t_cost + p + salt + nonce
const KS_HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + KS_SALT_LEN + KS_NONCE_LEN; // 57

/// BLAKE3 content-addressed account id from an Ed25519 public key.
pub fn account_fingerprint(pk: &AccountPublicKey) -> AccountId {
    AccountId(*blake3::hash(&pk.0).as_bytes())
}

/// Domain-separated canonical bytes signed for a usage receipt:
/// `b"lluma-usage-receipt-v1" ‖ postcard(body)`.
fn canonical(body: &UsageReceiptBody) -> Result<Vec<u8>> {
    let mut out = RECEIPT_DOMAIN.to_vec();
    let enc = postcard::to_stdvec(body).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    out.extend_from_slice(&enc);
    Ok(out)
}

pub(crate) fn signing_key(sk: &AccountSecretKey) -> Result<SigningKey> {
    let bytes: [u8; 32] =
        sk.0.as_slice()
            .try_into()
            .map_err(|_| CryptoError::Derivation("account secret key must be 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn verifying_key(pk: &AccountPublicKey) -> Result<VerifyingKey> {
    let bytes: [u8; 32] =
        pk.0.as_slice()
            .try_into()
            .map_err(|_| CryptoError::Derivation("account public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| CryptoError::Derivation(e.to_string()))
}

/// Sign a usage receipt with the host's Ed25519 secret key.
pub fn receipt_sign(sk: &AccountSecretKey, body: &UsageReceiptBody) -> Result<ReceiptSignature> {
    let key = signing_key(sk)?;
    let msg = canonical(body)?;
    let sig = key.sign(&msg);
    Ok(ReceiptSignature(sig.to_bytes().to_vec()))
}

/// Verify a usage receipt signature. Any mismatch returns `BadSignature`.
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
    key.verify(&msg, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

/// Domain-separated canonical bytes signed for an issue request:
/// `b"lluma-issue-request-v1" ‖ postcard(body)`. Distinct from
/// `RECEIPT_DOMAIN` — never shared.
fn issue_canonical(body: &IssueRequestBody) -> Result<Vec<u8>> {
    let mut out = ISSUE_REQUEST_DOMAIN.to_vec();
    let enc = postcard::to_stdvec(body).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    out.extend_from_slice(&enc);
    Ok(out)
}

/// Sign an `IssueRequestBody` with the consumer's Ed25519 account secret key.
/// Deterministic — no RNG (matches `receipt_sign`).
pub fn issue_request_sign(
    sk: &AccountSecretKey,
    body: &IssueRequestBody,
) -> Result<IssueSignature> {
    let key = signing_key(sk)?;
    let msg = issue_canonical(body)?;
    Ok(IssueSignature(key.sign(&msg).to_bytes().to_vec()))
}

/// Verify an issue-request signature. Any mismatch returns `BadSignature`.
pub fn issue_request_verify(
    pk: &AccountPublicKey,
    body: &IssueRequestBody,
    sig: &IssueSignature,
) -> Result<()> {
    let key = verifying_key(pk)?;
    let msg = issue_canonical(body)?;
    let sig_bytes: [u8; 64] = sig
        .0
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify(&msg, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

/// Domain-separated canonical bytes signed for a host-register request:
/// `b"lluma-host-register-v1" ‖ postcard(body)`. Distinct from the receipt
/// and issue-request domains — never shared.
fn host_register_canonical(body: &HostRegisterBody) -> Result<Vec<u8>> {
    let mut out = HOST_REGISTER_DOMAIN.to_vec();
    let enc = postcard::to_stdvec(body).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    out.extend_from_slice(&enc);
    Ok(out)
}

/// Sign a `HostRegisterBody` with the host's Ed25519 account secret key.
/// Deterministic — no RNG (matches `receipt_sign`).
pub fn host_register_sign(
    sk: &AccountSecretKey,
    body: &HostRegisterBody,
) -> Result<ReceiptSignature> {
    let key = signing_key(sk)?;
    let msg = host_register_canonical(body)?;
    Ok(ReceiptSignature(key.sign(&msg).to_bytes().to_vec()))
}

/// Verify a host-register signature. Any mismatch returns `BadSignature`.
pub fn host_register_verify(
    pk: &AccountPublicKey,
    body: &HostRegisterBody,
    sig: &ReceiptSignature,
) -> Result<()> {
    let key = verifying_key(pk)?;
    let msg = host_register_canonical(body)?;
    let sig_bytes: [u8; 64] = sig
        .0
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify(&msg, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

/// Domain-separated canonical bytes signed for a heartbeat:
/// `b"lluma-heartbeat-v1" ‖ postcard(body)`. Distinct from the other domains
/// — never shared.
fn heartbeat_canonical(body: &HeartbeatBody) -> Result<Vec<u8>> {
    let mut out = HEARTBEAT_DOMAIN.to_vec();
    let enc = postcard::to_stdvec(body).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    out.extend_from_slice(&enc);
    Ok(out)
}

/// Sign a `HeartbeatBody` with the host's Ed25519 account secret key.
/// Deterministic — no RNG (matches `receipt_sign`).
pub fn heartbeat_sign(
    sk: &AccountSecretKey,
    body: &HeartbeatBody,
) -> Result<ReceiptSignature> {
    let key = signing_key(sk)?;
    let msg = heartbeat_canonical(body)?;
    Ok(ReceiptSignature(key.sign(&msg).to_bytes().to_vec()))
}

/// Verify a heartbeat signature. Any mismatch returns `BadSignature`.
pub fn heartbeat_verify(
    pk: &AccountPublicKey,
    body: &HeartbeatBody,
    sig: &ReceiptSignature,
) -> Result<()> {
    let key = verifying_key(pk)?;
    let msg = heartbeat_canonical(body)?;
    let sig_bytes: [u8; 64] = sig
        .0
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify(&msg, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

/// Domain-separated canonical bytes signed for a registry snapshot:
/// `b"lluma-registry-snapshot-v1" ‖ snapshot_bytes`. The signed message is the
/// raw padded snapshot bucket, NOT a postcard body — distinct domain prefix
/// keeps it non-interchangeable with the body-signed domains.
fn snapshot_canonical(snapshot_bytes: &[u8]) -> Vec<u8> {
    let mut out = SNAPSHOT_DOMAIN.to_vec();
    out.extend_from_slice(snapshot_bytes);
    out
}

/// Sign raw registry-snapshot bytes with the broker's Ed25519 account secret
/// key. Deterministic — no RNG (matches `receipt_sign`).
pub fn snapshot_sign(
    sk: &AccountSecretKey,
    snapshot_bytes: &[u8],
) -> Result<ReceiptSignature> {
    let key = signing_key(sk)?;
    let msg = snapshot_canonical(snapshot_bytes);
    Ok(ReceiptSignature(key.sign(&msg).to_bytes().to_vec()))
}

/// Verify a registry-snapshot signature. Any mismatch returns `BadSignature`.
pub fn snapshot_verify(
    pk: &AccountPublicKey,
    snapshot_bytes: &[u8],
    sig: &ReceiptSignature,
) -> Result<()> {
    let key = verifying_key(pk)?;
    let msg = snapshot_canonical(snapshot_bytes);
    let sig_bytes: [u8; 64] = sig
        .0
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify(&msg, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

// ---- Anti-Sybil proof-of-work (Fable ruling; #4 Task 1, controller-authored) ----
//
// PoW = `blake3(DOMAIN ‖ account_pk[32] ‖ nonce[8] ‖ epoch_salt[32])` must have
// at least `difficulty_bits` leading zero bits. All variable inputs are
// fixed-width (typed in the signature), so concatenation is unambiguous with no
// length prefixes. The DOMAIN is per-purpose so one solve cannot serve both the
// trial-registration and host-registration gates. `epoch_salt` is a single
// global value per epoch (published; verifier accepts k and k−1) — never
// per-requester, which would be a linkage tag. Verification is one hash and all
// inputs are public, so there is no timing side channel to worry about.

/// PoW domain for issuer trial registration.
pub const POW_TRIAL_DOMAIN: &[u8] = b"lluma-pow-trial-v1";
/// PoW domain for host registration.
pub const POW_HOST_DOMAIN: &[u8] = b"lluma-pow-host-v1";

/// Count leading zero **bits** in a 32-byte BLAKE3 digest (big-endian).
fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut bits = 0u32;
    for &b in h.iter() {
        if b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

/// Verify a proof-of-work under `domain`: the BLAKE3 digest of
/// `domain ‖ account_pk ‖ nonce ‖ epoch_salt` must have `>= difficulty_bits`
/// leading zero bits. Returns `true` iff the work is sufficient.
pub fn pow_verify(
    domain: &[u8],
    account_pk: &[u8; 32],
    nonce: &[u8; 8],
    epoch_salt: &[u8; 32],
    difficulty_bits: u32,
) -> bool {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(account_pk);
    hasher.update(nonce);
    hasher.update(epoch_salt);
    let h = *hasher.finalize().as_bytes();
    leading_zero_bits(&h) >= difficulty_bits
}

/// Solve a proof-of-work by scanning a little-endian `u64` nonce until
/// `pow_verify` holds. Client/test helper — the broker only ever verifies.
pub fn pow_solve(
    domain: &[u8],
    account_pk: &[u8; 32],
    epoch_salt: &[u8; 32],
    difficulty_bits: u32,
) -> [u8; 8] {
    let mut n: u64 = 0;
    loop {
        let nonce = n.to_le_bytes();
        if pow_verify(domain, account_pk, &nonce, epoch_salt, difficulty_bits) {
            return nonce;
        }
        n = n.wrapping_add(1);
    }
}

/// Generate 16 bytes of fresh BIP-39 entropy (a 12-word mnemonic's seed).
pub fn account_mnemonic_new(
    // Pass a cryptographically secure RNG (`OsRng`) in production; a seeded RNG
    // is for tests only.
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Mnemonic> {
    let mut entropy = [0u8; 16];
    rng.fill_bytes(&mut entropy);
    Ok(Mnemonic(entropy))
}

/// Deterministically derive an Ed25519 keypair from a BIP-39 mnemonic.
///
/// Path: BIP-39 entropy → mnemonic phrase → 64-byte seed (`to_seed("")`) →
/// `blake3::derive_key("lluma v1 account ed25519", &seed)` (32 bytes) →
/// `ed25519_dalek::SigningKey`. The `AccountSecretKey` stores the derived
/// 32-byte key. The BLAKE3 context string is fixed exactly as above.
pub fn derive_keypair_from_seed(
    mnemonic: &Mnemonic,
) -> Result<(AccountSecretKey, AccountPublicKey)> {
    let phrase = Bip39Mnemonic::from_entropy(&mnemonic.0)
        .map_err(|e| CryptoError::Derivation(e.to_string()))?;
    let seed = phrase.to_seed(""); // [u8; 64]
    let key32 = blake3::derive_key("lluma v1 account ed25519", &seed);
    let signing = SigningKey::from_bytes(&key32);
    let verifying = signing.verifying_key();
    Ok((
        AccountSecretKey(key32.to_vec()),
        AccountPublicKey(verifying.to_bytes().to_vec()),
    ))
}

/// Argon2id key-encryption-key derivation (m=64 MiB, t=3, p=1, 32-byte output).
fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(KS_M_COST, KS_T_COST, KS_P, Some(32))
        .map_err(|e| CryptoError::Derivation(e.to_string()))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| CryptoError::Derivation(e.to_string()))?;
    Ok(out)
}

/// Parse a BIP-39 mnemonic phrase (English, 12 words / 16 bytes entropy) into a
/// [`Mnemonic`]. Any invalid phrase or non-16-byte entropy is a `Derivation`
/// error.
pub fn mnemonic_from_phrase(phrase: &str) -> Result<Mnemonic> {
    let m = Bip39Mnemonic::parse_normalized(phrase.trim())
        .map_err(|e| CryptoError::Derivation(e.to_string()))?;
    let entropy = m.to_entropy();
    let e16: [u8; 16] = entropy
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Derivation("expected a 12-word (128-bit) mnemonic".into()))?;
    Ok(Mnemonic(e16))
}

/// Render a [`Mnemonic`] back to its 12-word BIP-39 phrase (for user backup).
pub fn mnemonic_to_phrase(mnemonic: &Mnemonic) -> Result<String> {
    let m = Bip39Mnemonic::from_entropy(&mnemonic.0)
        .map_err(|e| CryptoError::Derivation(e.to_string()))?;
    Ok(m.to_string())
}

/// Seal arbitrary bytes under a passphrase into an authenticated blob, using the
/// same header layout, Argon2id KEK, and XChaCha20-Poly1305 AEAD as the
/// keystore. Used for the encrypted local token store as well as the keystore.
pub fn seal_bytes(
    // Pass a cryptographically secure RNG (`OsRng`) in production; a seeded RNG
    // is for tests only.
    rng: &mut (impl RngCore + CryptoRng),
    passphrase: &str,
    plaintext: &[u8],
) -> Result<KeystoreBlob> {
    let mut salt = [0u8; KS_SALT_LEN];
    let mut nonce = [0u8; KS_NONCE_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let mut header = Vec::with_capacity(KS_HEADER_LEN);
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
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;

    let mut blob = header;
    blob.extend_from_slice(&ct);
    Ok(KeystoreBlob(blob))
}

/// Open a blob sealed by [`seal_bytes`], returning the plaintext. Wrong
/// passphrase or any tamper returns `CryptoError::AuthFailed`.
pub fn open_bytes(passphrase: &str, blob: &KeystoreBlob) -> Result<Vec<u8>> {
    let b = &blob.0;
    if b.len() < KS_HEADER_LEN + 16 || b[0..4] != KS_MAGIC {
        return Err(CryptoError::AuthFailed);
    }
    let version = b[4];
    let m_cost = u32::from_le_bytes([b[5], b[6], b[7], b[8]]);
    let t_cost = u32::from_le_bytes([b[9], b[10], b[11], b[12]]);
    let p_cost = u32::from_le_bytes([b[13], b[14], b[15], b[16]]);
    if version != KS_VERSION || m_cost != KS_M_COST || t_cost != KS_T_COST || p_cost != KS_P {
        return Err(CryptoError::Encoding(
            "unsupported keystore version/params".into(),
        ));
    }
    let salt = &b[17..33];
    let nonce = &b[33..57];
    let header = &b[0..KS_HEADER_LEN];
    let ct = &b[KS_HEADER_LEN..];

    let kek = derive_kek(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new(kek.as_ref().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: header,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)
}

/// Seal a mnemonic under a passphrase into an authenticated keystore blob.
pub fn seal_keystore(
    // Pass a cryptographically secure RNG (`OsRng`) in production; a seeded RNG
    // is for tests only.
    rng: &mut (impl RngCore + CryptoRng),
    passphrase: &str,
    mnemonic: &Mnemonic,
) -> Result<KeystoreBlob> {
    seal_bytes(rng, passphrase, &mnemonic.0)
}

/// Open a sealed keystore. Wrong passphrase or any tamper returns
/// `CryptoError::AuthFailed` — never a garbage mnemonic.
pub fn open_keystore(passphrase: &str, blob: &KeystoreBlob) -> Result<Mnemonic> {
    // Delegates to `open_bytes` (which gates version + stored Argon2 params
    // before deriving, and always derives with the compile-time v1 constants),
    // then enforces the 16-byte mnemonic shape.
    let pt = open_bytes(passphrase, blob)?;
    let entropy: [u8; 16] = pt
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok(Mnemonic(entropy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lluma_core::ModelId;

    #[test]
    fn seal_bytes_round_trips_and_rejects_wrong_pass() {
        let mut rng = rand_core::OsRng;
        let blob = seal_bytes(&mut rng, "pw", b"hello world payload").unwrap();
        assert_eq!(open_bytes("pw", &blob).unwrap(), b"hello world payload");
        assert!(open_bytes("nope", &blob).is_err());
    }

    #[test]
    fn seal_bytes_handles_empty_and_large() {
        let mut rng = rand_core::OsRng;
        for payload in [vec![], vec![0u8; 1], vec![7u8; 4096]] {
            let blob = seal_bytes(&mut rng, "pw", &payload).unwrap();
            assert_eq!(open_bytes("pw", &blob).unwrap(), payload);
        }
    }

    #[test]
    fn keystore_still_round_trips_after_refactor() {
        let mut rng = rand_core::OsRng;
        let m = Mnemonic([5u8; 16]);
        let blob = seal_keystore(&mut rng, "pw", &m).unwrap();
        assert_eq!(open_keystore("pw", &blob).unwrap().0, m.0);
    }

    #[test]
    fn mnemonic_phrase_round_trips_and_matches_key_derivation() {
        let m = Mnemonic([0x3cu8; 16]);
        let phrase = mnemonic_to_phrase(&m).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
        let back = mnemonic_from_phrase(&phrase).unwrap();
        assert_eq!(back.0, m.0);
        // Same phrase ⇒ same derived account.
        let (_sk1, pk1) = derive_keypair_from_seed(&m).unwrap();
        let (_sk2, pk2) = derive_keypair_from_seed(&back).unwrap();
        assert_eq!(pk1.0, pk2.0);
    }

    #[test]
    fn mnemonic_from_phrase_rejects_garbage() {
        assert!(mnemonic_from_phrase("not a real mnemonic phrase at all nope").is_err());
    }

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
        assert!(matches!(
            receipt_verify(&pk, &tampered, &sig),
            Err(CryptoError::BadSignature)
        ));
    }

    #[test]
    fn signature_from_other_key_fails() {
        let (sk1, _pk1) = super::derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let (_sk2, pk2) = super::derive_keypair_from_seed(&Mnemonic([2u8; 16])).unwrap();
        let body = sample_body(5);
        let sig = receipt_sign(&sk1, &body).unwrap();
        assert!(matches!(
            receipt_verify(&pk2, &body, &sig),
            Err(CryptoError::BadSignature)
        ));
    }

    #[test]
    fn fingerprint_is_blake3_of_pubkey() {
        let (_sk, pk) = super::derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let id = account_fingerprint(&pk);
        assert_eq!(id.0, *blake3::hash(&pk.0).as_bytes());
    }

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
        assert!(matches!(
            open_keystore("wrong", &blob),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn tampered_keystore_fails_closed() {
        let mut rng = rand_core::OsRng;
        let m = account_mnemonic_new(&mut rng).unwrap();
        let mut blob = seal_keystore(&mut rng, "pw", &m).unwrap();
        let n = blob.0.len();
        blob.0[n - 1] ^= 0xff;
        assert!(matches!(
            open_keystore("pw", &blob),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn keystore_rejects_wrong_version() {
        let mut rng = rand_core::OsRng;
        let m = account_mnemonic_new(&mut rng).unwrap();
        let mut blob = seal_keystore(&mut rng, "pw", &m).unwrap();
        // Flip the version byte (offset 4, after the 4-byte magic).
        blob.0[4] = 0xFF;
        assert!(open_keystore("pw", &blob).is_err());
    }

    fn sample_issue_body() -> IssueRequestBody {
        IssueRequestBody {
            version: 1,
            account: [7u8; 32],
            key_id: [9u8; 32],
            request_id: [11u8; 32],
            ts_unix_s: 1_700_000_000,
            blinded_batch_hash: [13u8; 32],
        }
    }

    #[test]
    fn issue_request_sign_verify_round_trip() {
        let (sk, pk) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let body = sample_issue_body();
        let sig = issue_request_sign(&sk, &body).unwrap();
        assert!(issue_request_verify(&pk, &body, &sig).is_ok());
    }

    #[test]
    fn issue_request_tampered_key_id_fails() {
        let (sk, pk) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let body = sample_issue_body();
        let sig = issue_request_sign(&sk, &body).unwrap();
        let mut tampered = body.clone();
        tampered.key_id[0] ^= 0xff;
        assert!(matches!(
            issue_request_verify(&pk, &tampered, &sig),
            Err(CryptoError::BadSignature)
        ));
    }

    #[test]
    fn issue_request_signature_from_other_account_fails() {
        let (sk1, _pk1) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let (_sk2, pk2) = derive_keypair_from_seed(&Mnemonic([2u8; 16])).unwrap();
        let body = sample_issue_body();
        let sig = issue_request_sign(&sk1, &body).unwrap();
        assert!(matches!(
            issue_request_verify(&pk2, &body, &sig),
            Err(CryptoError::BadSignature)
        ));
    }

    fn sample_host_register_body() -> HostRegisterBody {
        HostRegisterBody {
            version: 1,
            host_account: [7u8; 32],
            hpke_pk: vec![0xAA; 32],
            ingress_addr: "127.0.0.1:9000".into(),
            models: vec![ModelId("qwen2.5-0.5b-instruct".into())],
        }
    }

    #[test]
    fn host_register_sign_verify_round_trip() {
        let (sk, pk) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let body = sample_host_register_body();
        let sig = host_register_sign(&sk, &body).unwrap();
        assert!(host_register_verify(&pk, &body, &sig).is_ok());
    }

    #[test]
    fn host_register_tampered_fails() {
        let (sk, pk) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let body = sample_host_register_body();
        let sig = host_register_sign(&sk, &body).unwrap();
        let mut tampered = body.clone();
        tampered.ingress_addr = "127.0.0.1:9001".into();
        assert!(matches!(
            host_register_verify(&pk, &tampered, &sig),
            Err(CryptoError::BadSignature)
        ));
    }

    fn sample_heartbeat_body() -> HeartbeatBody {
        HeartbeatBody {
            version: 1,
            host_account: [7u8; 32],
            hb_counter: 42,
            load_bucket: 3,
            models: vec![ModelId("qwen2.5-0.5b-instruct".into())],
        }
    }

    #[test]
    fn heartbeat_sign_verify_round_trip() {
        let (sk, pk) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let body = sample_heartbeat_body();
        let sig = heartbeat_sign(&sk, &body).unwrap();
        assert!(heartbeat_verify(&pk, &body, &sig).is_ok());
    }

    #[test]
    fn heartbeat_wrong_key_fails() {
        let (sk1, _pk1) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let (_sk2, pk2) = derive_keypair_from_seed(&Mnemonic([2u8; 16])).unwrap();
        let body = sample_heartbeat_body();
        let sig = heartbeat_sign(&sk1, &body).unwrap();
        assert!(matches!(
            heartbeat_verify(&pk2, &body, &sig),
            Err(CryptoError::BadSignature)
        ));
    }

    #[test]
    fn snapshot_sign_verify_round_trip() {
        let (sk, pk) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let bytes = [0u8; 100];
        let sig = snapshot_sign(&sk, &bytes).unwrap();
        assert!(snapshot_verify(&pk, &bytes, &sig).is_ok());
    }

    #[test]
    fn snapshot_tampered_fails() {
        let (sk, pk) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let bytes = [0u8; 100];
        let sig = snapshot_sign(&sk, &bytes).unwrap();
        let mut tampered = bytes;
        tampered[10] ^= 0xff;
        assert!(matches!(
            snapshot_verify(&pk, &tampered, &sig),
            Err(CryptoError::BadSignature)
        ));
    }

    #[test]
    fn cross_domain_signature_rejected() {
        // A signature produced under the heartbeat domain must NOT verify under
        // the host-register domain, even if the overlapping body fields match —
        // the distinct domain prefix forces verification to fail.
        let (sk, _pk) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let (.., pk_other) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
        let hb = HeartbeatBody {
            version: 1,
            host_account: [7u8; 32],
            hb_counter: 0,
            load_bucket: 0,
            models: vec![],
        };
        let reg = HostRegisterBody {
            version: 1,
            host_account: [7u8; 32],
            hpke_pk: vec![],
            ingress_addr: String::new(),
            models: vec![],
        };
        let sig = heartbeat_sign(&sk, &hb).unwrap();
        assert!(matches!(
            host_register_verify(&pk_other, &reg, &sig),
            Err(CryptoError::BadSignature)
        ));
    }

    // ---- proof-of-work (controller) ----

    #[test]
    fn pow_solve_then_verify_accepts_and_rejects_harder() {
        // Keep the difficulty small so the test solves quickly and deterministically.
        let d = 12u32;
        let pk = [3u8; 32];
        let salt = [9u8; 32];
        let nonce = pow_solve(POW_TRIAL_DOMAIN, &pk, &salt, d);
        assert!(pow_verify(POW_TRIAL_DOMAIN, &pk, &nonce, &salt, d));
        // An impossible difficulty (>256, the max leading-zero bits of a 32-byte
        // digest) can never be satisfied — guaranteed rejection, no flakiness.
        assert!(!pow_verify(POW_TRIAL_DOMAIN, &pk, &nonce, &salt, 257));
    }

    #[test]
    fn pow_domain_separation_a_trial_solve_fails_under_host_domain() {
        let d = 12u32;
        let pk = [4u8; 32];
        let salt = [1u8; 32];
        let nonce = pow_solve(POW_TRIAL_DOMAIN, &pk, &salt, d);
        // Same nonce under the HOST domain is a different hash — must not verify
        // (per-purpose domain separation: one solve cannot serve both gates).
        assert!(!pow_verify(POW_HOST_DOMAIN, &pk, &nonce, &salt, d));
    }

    #[test]
    fn pow_rejects_wrong_salt_and_wrong_account() {
        let d = 12u32;
        let pk = [5u8; 32];
        let salt = [2u8; 32];
        let nonce = pow_solve(POW_HOST_DOMAIN, &pk, &salt, d);
        assert!(pow_verify(POW_HOST_DOMAIN, &pk, &nonce, &salt, d));
        // A different epoch_salt or account invalidates the work.
        assert!(!pow_verify(POW_HOST_DOMAIN, &pk, &nonce, &[3u8; 32], d));
        assert!(!pow_verify(POW_HOST_DOMAIN, &[6u8; 32], &nonce, &salt, d));
    }
}
