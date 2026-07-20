//! Signed bootstrap artifact + N-source consistency check (Fable ruling R7 /
//! ADR-0002 §3.4 / RFC 9576 Privacy Pass key-consistency). The client pins an
//! offline publishing key and refuses to act on a key-config that is not
//! attested by ≥2 byte-identical signed sources — so a per-client targeted
//! key-config (leak L2) requires corrupting multiple independent channels AND
//! the signing key.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use lluma_core::wire::OhttpKeyConfig;

use crate::error::NetError;

const BOOTSTRAP_DOMAIN: &[u8] = b"lluma-bootstrap-v1";

/// The public bootstrap: which relays to use and the gateway OHTTP key-config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bootstrap {
    pub relay_urls: Vec<String>,
    pub key_config: OhttpKeyConfig,
    pub key_id: u8,
    pub epoch: u64,
    pub not_after: u64,
}

/// Wire form of a signed bootstrap: `payload = postcard(Bootstrap)`, signed with
/// the publishing key over `BOOTSTRAP_DOMAIN ‖ payload`.
#[derive(Serialize, Deserialize)]
struct SignedBootstrap {
    payload: Vec<u8>,
    sig: Vec<u8>,
}

/// Produce a signed bootstrap blob (for the offline publisher / tests).
pub fn sign_bootstrap(sk: &SigningKey, b: &Bootstrap) -> Result<Vec<u8>, NetError> {
    let payload = postcard::to_stdvec(b).map_err(|_| NetError::Bootstrap)?;
    let mut msg = BOOTSTRAP_DOMAIN.to_vec();
    msg.extend_from_slice(&payload);
    let sig = sk.sign(&msg);
    let signed = SignedBootstrap {
        payload,
        sig: sig.to_bytes().to_vec(),
    };
    postcard::to_stdvec(&signed).map_err(|_| NetError::Bootstrap)
}

/// Verify ≥2 byte-identical signed sources under the pinned publishing key.
/// Fails closed on any signature failure, any decode failure, fewer than two
/// sources, or a lack of a 2-source agreement (publisher equivocation).
pub fn verify_bootstrap(
    sources: &[&[u8]],
    vk: &VerifyingKey,
    now_unix_s: u64,
) -> Result<Bootstrap, NetError> {
    if sources.len() < 2 {
        return Err(NetError::Bootstrap);
    }
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(sources.len());
    for src in sources {
        let signed: SignedBootstrap = postcard::from_bytes(src).map_err(|_| NetError::Bootstrap)?;
        let mut msg = BOOTSTRAP_DOMAIN.to_vec();
        msg.extend_from_slice(&signed.payload);
        let sig_bytes: [u8; 64] = signed
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| NetError::Bootstrap)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&msg, &sig).map_err(|_| NetError::Bootstrap)?;
        payloads.push(signed.payload);
    }
    // Require ≥2 byte-identical payloads (two independent channels agree).
    let first = &payloads[0];
    let agree = payloads.iter().filter(|p| p.as_slice() == first.as_slice()).count();
    if agree < 2 {
        return Err(NetError::Bootstrap);
    }
    let bootstrap: Bootstrap = postcard::from_bytes(first).map_err(|_| NetError::Bootstrap)?;
    // Freshness: refuse an expired bootstrap — it may pin a rotated/retired key.
    if now_unix_s > bootstrap.not_after {
        return Err(NetError::Bootstrap);
    }
    Ok(bootstrap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sample() -> Bootstrap {
        Bootstrap {
            relay_urls: vec!["http://127.0.0.1:9000".into()],
            key_config: OhttpKeyConfig(vec![1, 2, 3, 4]),
            key_id: 7,
            epoch: 1,
            not_after: 9_999_999_999,
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn two_identical_sources_verify() {
        let sk = key();
        let vk = sk.verifying_key();
        let b = sample();
        let blob = sign_bootstrap(&sk, &b).unwrap();
        let got = verify_bootstrap(&[&blob, &blob], &vk, 1_000).unwrap();
        assert_eq!(got, b);
    }

    #[test]
    fn expired_bootstrap_fails_closed() {
        let sk = key();
        let vk = sk.verifying_key();
        let mut b = sample();
        b.not_after = 100;
        let blob = sign_bootstrap(&sk, &b).unwrap();
        // now past not_after → rejected; now before → ok.
        assert!(matches!(
            verify_bootstrap(&[&blob, &blob], &vk, 200),
            Err(NetError::Bootstrap)
        ));
        assert!(verify_bootstrap(&[&blob, &blob], &vk, 50).is_ok());
    }

    #[test]
    fn single_source_fails_closed() {
        let sk = key();
        let vk = sk.verifying_key();
        let blob = sign_bootstrap(&sk, &sample()).unwrap();
        assert!(matches!(verify_bootstrap(&[&blob], &vk, 1_000), Err(NetError::Bootstrap)));
    }

    #[test]
    fn equivocation_two_different_payloads_fails() {
        // Publisher signs two DIFFERENT bootstraps (both valid signatures) — the
        // consistency check must reject: no 2-source agreement.
        let sk = key();
        let vk = sk.verifying_key();
        let a = sign_bootstrap(&sk, &sample()).unwrap();
        let mut other = sample();
        other.key_id = 8;
        let b = sign_bootstrap(&sk, &other).unwrap();
        assert!(matches!(verify_bootstrap(&[&a, &b], &vk, 1_000), Err(NetError::Bootstrap)));
    }

    #[test]
    fn wrong_key_fails_closed() {
        let sk = key();
        let blob = sign_bootstrap(&sk, &sample()).unwrap();
        let attacker_vk = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(matches!(
            verify_bootstrap(&[&blob, &blob], &attacker_vk, 1_000),
            Err(NetError::Bootstrap)
        ));
    }
}
