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
        tunnel_url: None,
        pow_difficulty: None,
        epoch_salt: None,
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

#[test]
fn accepts_wss_tunnel_url_rejects_plain_ws() {
    let (sk, pk) = derive_keypair_from_seed(&Mnemonic([77u8; 16])).unwrap();
    // A genuine wss:// tunnel endpoint is accepted and surfaced.
    let mut doc = sample_doc();
    doc.tunnel_url = Some("wss://tunnel.example.net/v1/host/tunnel".into());
    let sb = sign(&doc, &sk);
    let out = verify_bootstrap(&pk, &sb).unwrap();
    assert_eq!(out.tunnel_url.as_deref(), Some("wss://tunnel.example.net/v1/host/tunnel"));
    // A plain ws:// tunnel endpoint (hijackable post-handshake) is rejected even
    // though the signature is genuine.
    let mut bad = sample_doc();
    bad.tunnel_url = Some("ws://tunnel.example.net/v1/host/tunnel".into());
    let sb_bad = sign(&bad, &sk);
    assert!(verify_bootstrap(&pk, &sb_bad).is_err());
}

/// The pre-`tunnel_url` shape of BootstrapDoc as a positional tuple. postcard is
/// not self-describing, so a struct and a tuple of the same field types encode
/// identically — this lets the test model an old-version client without a
/// second serde-deriving type.
type OldDoc = (u8, String, Vec<u8>, [u8; 32], u64);

#[test]
fn old_client_decodes_new_blob_ignoring_tunnel_url() {
    // ONE-WAY compat: a client built BEFORE tunnel_url (the 5-field shape) still
    // decodes a doc signed WITH it — postcard reads its known fields and ignores
    // the trailing bytes. This is why old deployed apps keep working after we
    // re-sign the blob with a tunnel_url.
    let doc = BootstrapDoc {
        tunnel_url: Some("wss://tunnel.example.net/v1/host/tunnel".into()),
        ..sample_doc()
    };
    let doc_bytes = postcard::to_stdvec(&doc).unwrap();
    let old: OldDoc = postcard::from_bytes(&doc_bytes).unwrap();
    assert_eq!(old.1, "https://relay.example.net"); // relay_url
    assert_eq!(old.4, 1_700_000_000); // issued_at_s
}

#[test]
fn new_client_cannot_decode_old_blob_deploy_order_guard() {
    // The REVERSE is NOT compatible: a client built WITH tunnel_url cannot decode
    // a 5-field OLD blob (postcard reads past the end). This pins the deploy rule
    // — publish the re-signed (6-field) blob BEFORE shipping a new client. If
    // someone "fixes" this to succeed, they've broken the documented ordering.
    let old: OldDoc = (
        1,
        "https://relay.example.net".into(),
        vec![0xAB; 48],
        [9u8; 32],
        1_700_000_000,
    );
    let old_bytes = postcard::to_stdvec(&old).unwrap();
    assert!(postcard::from_bytes::<BootstrapDoc>(&old_bytes).is_err());
}
