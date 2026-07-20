//! `lluma-host` binary. Generates an HPKE host keypair on startup, prints the
//! public key (base64) for the broker's static directory, and serves `/v1/exec`
//! with an echo upstream (a real LLM adapter swaps in behind the `Upstream`
//! trait). No local GGUF (no C toolchain here) — this is the API-donor shape.

use std::env;
use std::sync::Arc;

use base64::Engine;

use lluma_host::{router, EchoUpstream, HostState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_target(true).with_level(true).init();

    let bind = env::var("LLUMA_HOST_BIND").unwrap_or_else(|_| "127.0.0.1:8783".to_string());
    let sentinel = env::var("LLUMA_HOST_SENTINEL").unwrap_or_else(|_| "ANSWER: ".to_string());

    let mut rng = rand_core::OsRng;
    let (host_sk, host_pk) = lluma_crypto::e2e::host_keygen(&mut rng)?;
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&host_pk.0);
    tracing::info!("host_pk (base64 — publish in the broker directory): {pk_b64}");

    let state = HostState {
        host_sk: Arc::new(host_sk),
        upstream: Arc::new(EchoUpstream {
            sentinel: sentinel.into_bytes(),
        }),
    };
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("lluma-host listening on {bind}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
