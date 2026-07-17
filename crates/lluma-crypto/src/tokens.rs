//! RFC 9474 blind entitlement tokens (RSABSSA-SHA384-PSS-Randomized).
//!
//! A consumer blinds a random nonce, an issuer signs the blinded value
//! without ever seeing the nonce, and the consumer unblinds the signature
//! into a `Token` it can later redeem. This is the privacy-preserving
//! entitlement primitive: the issuer cannot link the token it signed to the
//! token later spent (unlinkability), and the redeemer cannot forge tokens
//! without a valid blind signature from the issuer.
//!
//! ## RNG type note (deviation from the original task brief)
//!
//! `blind-rsa-signatures` 0.17 depends on `rsa` 0.10.x, which in turn depends
//! on `rand_core` 0.10.x — a different major version than the `rand_core` 0.6
//! used elsewhere in this crate (by `ed25519-dalek`/`hpke`). `rand_core` 0.10
//! also removed `OsRng` entirely (moved out to the `rand`/`getrandom`
//! crates), so there is no `rsa::rand_core::OsRng` to reach for.
//!
//! Consequently the functions below are generic over
//! `blind_rsa_signatures::reexports::rsa::rand_core::CryptoRng` (the 0.10.x
//! trait `blind-rsa-signatures` actually requires), not the workspace's
//! `rand_core` 0.6 `RngCore + CryptoRng` bound the brief originally specified.
//! Callers (including this module's tests) construct
//! `blind_rsa_signatures::DefaultRng` as their RNG.

use blind_rsa_signatures::reexports::rsa::rand_core::CryptoRng;
use blind_rsa_signatures::{
    BlindMessage, BlindSignature as RsaBlindSignature, BlindingResult,
    KeyPairSha384PSSRandomized as RsaKeyPair, MessageRandomizer,
    PublicKeySha384PSSRandomized as RsaPublicKey, Secret as RsaSecret,
    SecretKeySha384PSSRandomized as RsaSecretKey, Signature as RsaSignature,
};

use crate::error::{CryptoError, Result};
use lluma_core::wire::{
    BlindSignature, BlindedTokenRequest, BlindingState, IssuerPublicKey, IssuerSecretKey, SpendId,
    Token,
};

/// RSA-2048 blind-signature parameters throughout: nonce (32B), blinding
/// secret / RSA modulus size (256B), message randomizer (32B), blind message
/// (256B). Stored in `BlindingState` as `(nonce, blind_message, secret,
/// randomizer)` via `postcard` so the client can unblind later without
/// re-deriving anything from the (long since forgotten) blinding call.
type BlindStateTuple = ([u8; 32], Vec<u8>, Vec<u8>, [u8; 32]);

const MODULUS_BITS: usize = 2048;

/// A redeemable token = nonce ‖ randomizer ‖ RSA signature, serialized.
/// The verifier reconstructs the RFC 9474 signed message and checks the sig.
fn split_token(token: &Token) -> Result<(&[u8], &[u8], &[u8])> {
    let b = &token.0;
    if b.len() != 320 {
        return Err(CryptoError::TokenInvalid);
    }
    Ok((&b[0..32], &b[32..64], &b[64..]))
}

pub fn issuer_keygen(
    // Pass a cryptographically secure RNG (`OsRng`) in production; a seeded RNG
    // is for tests only.
    rng: &mut impl CryptoRng,
) -> Result<(IssuerSecretKey, IssuerPublicKey)> {
    let kp =
        RsaKeyPair::generate(rng, MODULUS_BITS).map_err(|e| CryptoError::Blind(e.to_string()))?;
    let sk_der = kp
        .sk
        .to_der()
        .map_err(|e| CryptoError::Blind(e.to_string()))?;
    let pk_der = kp
        .pk
        .to_der()
        .map_err(|e| CryptoError::Blind(e.to_string()))?;
    Ok((IssuerSecretKey(sk_der), IssuerPublicKey(pk_der)))
}

pub fn token_blind(
    rng: &mut impl CryptoRng,
    pk: &IssuerPublicKey,
) -> Result<(BlindingState, BlindedTokenRequest)> {
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    let rsa_pk = RsaPublicKey::from_der(&pk.0).map_err(|e| CryptoError::Blind(e.to_string()))?;
    let blinding = rsa_pk
        .blind(rng, nonce)
        .map_err(|e| CryptoError::Blind(e.to_string()))?;
    let randomizer = blinding.msg_randomizer.ok_or_else(|| {
        CryptoError::Blind(
            "RSABSSA-SHA384-PSS-Randomized blinding did not produce a message randomizer"
                .to_string(),
        )
    })?;

    let blind_message = blinding.blind_message.0;
    let secret = blinding.secret.0;
    let state_tuple: BlindStateTuple = (nonce, blind_message.clone(), secret, randomizer.0);
    let state_bytes =
        postcard::to_allocvec(&state_tuple).map_err(|e| CryptoError::Encoding(e.to_string()))?;

    Ok((
        BlindingState(state_bytes),
        BlindedTokenRequest(blind_message),
    ))
}

pub fn token_issue(
    rng: &mut impl CryptoRng,
    sk: &IssuerSecretKey,
    req: &BlindedTokenRequest,
) -> Result<BlindSignature> {
    let rsa_sk = RsaSecretKey::from_der(&sk.0).map_err(|e| CryptoError::Blind(e.to_string()))?;
    let sig = rsa_sk
        .blind_sign_with_rng(rng, &req.0)
        .map_err(|e| CryptoError::Blind(e.to_string()))?;
    Ok(BlindSignature(sig.0))
}

pub fn token_unblind(
    pk: &IssuerPublicKey,
    st: BlindingState,
    sig: &BlindSignature,
) -> Result<Token> {
    let (nonce, blind_message, secret, randomizer_bytes): BlindStateTuple =
        postcard::from_bytes(&st.0).map_err(|e| CryptoError::Encoding(e.to_string()))?;

    let rsa_pk = RsaPublicKey::from_der(&pk.0).map_err(|e| CryptoError::Blind(e.to_string()))?;
    let blinding_result = BlindingResult {
        blind_message: BlindMessage(blind_message),
        secret: RsaSecret(secret),
        msg_randomizer: Some(MessageRandomizer(randomizer_bytes)),
    };
    let blind_sig = RsaBlindSignature(sig.0.clone());

    let signature = rsa_pk
        .finalize(&blind_sig, &blinding_result, nonce)
        .map_err(|e| CryptoError::Blind(e.to_string()))?;

    let mut bytes = Vec::with_capacity(32 + 32 + signature.0.len());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&randomizer_bytes);
    bytes.extend_from_slice(&signature.0);
    Ok(Token(bytes))
}

pub fn token_verify(pk: &IssuerPublicKey, token: &Token) -> Result<()> {
    let (nonce, randomizer, sig_bytes) = split_token(token)?;
    let randomizer_arr: [u8; 32] = randomizer
        .try_into()
        .map_err(|_| CryptoError::TokenInvalid)?;
    let rsa_pk = RsaPublicKey::from_der(&pk.0).map_err(|_| CryptoError::TokenInvalid)?;
    let rsa_sig = RsaSignature(sig_bytes.to_vec());
    rsa_pk
        .verify(&rsa_sig, Some(MessageRandomizer(randomizer_arr)), nonce)
        .map_err(|_| CryptoError::TokenInvalid)
}

pub fn token_spend_id(token: &Token) -> SpendId {
    SpendId(*blake3::hash(&token.0).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    // `rand_core::OsRng` (workspace 0.6) cannot be used here: `blind-rsa-signatures`
    // 0.17's blinding/keygen calls require the 0.10.x `rand_core::CryptoRng` trait
    // from its own dependency tree. `blind_rsa_signatures::DefaultRng` implements
    // that trait (backed by the `rand` crate's OS-seeded generator), so we alias it
    // to `OsRng` to keep the rest of the test bodies exactly as specified.
    use blind_rsa_signatures::DefaultRng as OsRng;

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
        assert!(matches!(
            token_verify(&pk, &token),
            Err(CryptoError::TokenInvalid)
        ));
    }

    #[test]
    fn token_from_one_key_fails_under_another() {
        let mut rng = OsRng;
        let (_, other_pk) = issuer_keygen(&mut rng).unwrap();
        let (_, token) = roundtrip_token();
        assert!(matches!(
            token_verify(&other_pk, &token),
            Err(CryptoError::TokenInvalid)
        ));
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
}
