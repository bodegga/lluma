//! End-to-end (local) auto-connect fetch: serve a signed bootstrap from a real
//! localhost HTTP server (as the relay would) and drive `fetch_bootstrap` over
//! the wire — verifying against the pinned key, rejecting a wrong pinned key,
//! and rejecting a 404 (no bootstrap published).

use std::sync::Arc;

use axum::{routing::get, Router};
use lluma_client::fetch_bootstrap;
use lluma_core::proto::v1::SignedBootstrap;
use lluma_core::wire::{BootstrapDoc, Mnemonic};
use lluma_crypto::account::{bootstrap_sign, derive_keypair_from_seed};

async fn spawn_relay(blob: Option<Vec<u8>>) -> String {
    let blob = Arc::new(blob);
    let app = Router::new().route(
        "/v1/bootstrap",
        get({
            let blob = blob.clone();
            move || {
                let blob = blob.clone();
                async move {
                    match blob.as_ref() {
                        Some(b) => (axum::http::StatusCode::OK, b.clone()),
                        None => (axum::http::StatusCode::NOT_FOUND, Vec::new()),
                    }
                }
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    format!("http://{addr}")
}

fn signed_blob() -> (Vec<u8>, lluma_core::wire::AccountPublicKey) {
    let (sk, pk) = derive_keypair_from_seed(&Mnemonic([88u8; 16])).unwrap();
    let doc = BootstrapDoc {
        version: 1,
        relay_url: "https://relay.n.lluma.bodegga.net".into(),
        gateway_kc: vec![1, 2, 3, 4, 5, 6, 7, 8],
        issuer_key_id: [4u8; 32],
        issued_at_s: 1_721_500_000,
        tunnel_url: None,
    };
    let doc_bytes = postcard::to_stdvec(&doc).unwrap();
    let sig = bootstrap_sign(&sk, &doc_bytes).unwrap();
    let sb = SignedBootstrap { doc: doc_bytes, sig: sig.0 };
    (serde_json::to_vec(&sb).unwrap(), pk)
}

#[tokio::test]
async fn fetches_and_verifies_over_http() {
    let (blob, pk) = signed_blob();
    let url = spawn_relay(Some(blob)).await;
    let doc = fetch_bootstrap(&url, &pk).await.unwrap();
    assert_eq!(doc.relay_url, "https://relay.n.lluma.bodegga.net");
    assert_eq!(doc.gateway_kc, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(doc.issuer_key_id, [4u8; 32]);
}

#[tokio::test]
async fn rejects_wrong_pinned_key_over_http() {
    let (blob, _pk) = signed_blob();
    let (_sk2, wrong) = derive_keypair_from_seed(&Mnemonic([1u8; 16])).unwrap();
    let url = spawn_relay(Some(blob)).await;
    assert!(fetch_bootstrap(&url, &wrong).await.is_err(), "must reject a blob not signed by the pinned key");
}

#[tokio::test]
async fn errors_when_no_bootstrap_published() {
    let (_blob, pk) = signed_blob();
    let url = spawn_relay(None).await;
    assert!(fetch_bootstrap(&url, &pk).await.is_err(), "404 must be an error, not a silent default");
}
