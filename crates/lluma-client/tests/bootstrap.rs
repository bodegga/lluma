//! Client-side bootstrap verification. Signs a bootstrap with a test registry
//! key and asserts the client accepts a genuine doc and rejects a wrong-key or
//! tampered one — the trust check that lets the app self-configure over an
//! untrusted relay.

use lluma_client::verify_bootstrap;
use lluma_core::proto::v1::SignedBootstrap;
use lluma_core::wire::{AccountSecretKey, BootstrapDoc, Mnemonic};
use lluma_crypto::account::{bootstrap_sign, derive_keypair_from_seed};

fn sample_doc() -> BootstrapDoc {
    BootstrapDoc {
        version: 1,
        relay_url: "https://relay.example.net".into(),
        gateway_kc: vec![0xAB; 48],
        issuer_key_id: [9u8; 32],
        issued_at_s: 1_700_000_000,
    }
}

fn sign(doc: &BootstrapDoc, sk: &AccountSecretKey) -> SignedBootstrap {
    let doc_bytes = postcard::to_stdvec(doc).unwrap();
    let sig = bootstrap_sign(sk, &doc_bytes).unwrap();
    SignedBootstrap { doc: doc_bytes, sig: sig.0 }
}

#[test]
fn accepts_genuine_bootstrap() {
    let (sk, pk) = derive_keypair_from_seed(&Mnemonic([77u8; 16])).unwrap();
    let sb = sign(&sample_doc(), &sk);
    let doc = verify_bootstrap(&pk, &sb).unwrap();
    assert_eq!(doc.relay_url, "https://relay.example.net");
    assert_eq!(doc.gateway_kc, vec![0xAB; 48]);
    assert_eq!(doc.issuer_key_id, [9u8; 32]);
}

#[test]
fn rejects_wrong_key() {
    let (sk, _pk) = derive_keypair_from_seed(&Mnemonic([77u8; 16])).unwrap();
    let (_sk2, wrong) = derive_keypair_from_seed(&Mnemonic([66u8; 16])).unwrap();
    let sb = sign(&sample_doc(), &sk);
    assert!(verify_bootstrap(&wrong, &sb).is_err());
}

#[test]
fn rejects_tampered_doc() {
    let (sk, pk) = derive_keypair_from_seed(&Mnemonic([77u8; 16])).unwrap();
    let mut sb = sign(&sample_doc(), &sk);
    sb.doc[5] ^= 0xff; // flip a byte inside the signed doc
    assert!(verify_bootstrap(&pk, &sb).is_err());
}

#[test]
fn rejects_tampered_signature() {
    let (sk, pk) = derive_keypair_from_seed(&Mnemonic([77u8; 16])).unwrap();
    let mut sb = sign(&sample_doc(), &sk);
    sb.sig[0] ^= 0xff;
    assert!(verify_bootstrap(&pk, &sb).is_err());
}
