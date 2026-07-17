//! Account identity, signed usage receipts, and self-custodial key backup.
//!
//! Task 5 (Ed25519 account identity + signed usage receipts) and Task 6
//! (BIP-39 mnemonic derivation + Argon2id / XChaCha20-Poly1305 keystore)
//! share this file because Task 5's tests reference `derive_keypair_from_seed`,
//! which Task 6 defines. See `.superpowers/sdd/task-5-brief.md` and
//! `task-6-brief.md`.

use crate::error::{CryptoError, Result};
use lluma_core::wire::{
    AccountId, AccountPublicKey, AccountSecretKey, KeystoreBlob, Mnemonic, ReceiptSignature,
    UsageReceiptBody,
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

/// Seal a mnemonic under a passphrase into an authenticated keystore blob.
pub fn seal_keystore(
    // Pass a cryptographically secure RNG (`OsRng`) in production; a seeded RNG
    // is for tests only.
    rng: &mut (impl RngCore + CryptoRng),
    passphrase: &str,
    mnemonic: &Mnemonic,
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
                msg: &mnemonic.0,
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;

    let mut blob = header;
    blob.extend_from_slice(&ct);
    Ok(KeystoreBlob(blob))
}

/// Open a sealed keystore. Wrong passphrase or any tamper returns
/// `CryptoError::AuthFailed` — never a garbage mnemonic.
pub fn open_keystore(passphrase: &str, blob: &KeystoreBlob) -> Result<Mnemonic> {
    let b = &blob.0;
    if b.len() < KS_HEADER_LEN + 16 || b[0..4] != KS_MAGIC {
        return Err(CryptoError::AuthFailed);
    }
    // Gate on version + stored Argon2 params BEFORE deriving. The header
    // (incl. these params) is already bound as AEAD AAD in `seal_keystore`, so
    // a tampered param fails the tag check too; this explicit check also
    // rejects a well-formed-but-foreign blob whose version/params we don't
    // support, and it ensures we never feed attacker-controlled m/t/p into
    // Argon2 — we always derive with the compile-time v1 constants.
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
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: header,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;
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
}
