//! `lluma-relay` binary. Stateless; refuses to start without a gateway URL.

use std::env;
use std::net::SocketAddr;

use lluma_relay::{router, RateLimitConfig, RelayConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_target(true).with_level(true).init();

    let bind = env::var("LLUMA_RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8780".to_string());
    let gateway = env::var("LLUMA_RELAY_GATEWAY").unwrap_or_default();
    if gateway.is_empty() {
        eprintln!("error: LLUMA_RELAY_GATEWAY is required (the gateway URL to forward to)");
        std::process::exit(1);
    }
    let max_body: usize = env::var("LLUMA_RELAY_MAX_BODY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65536);
    let capacity: u32 = env::var("LLUMA_RELAY_RL_CAPACITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);
    let refill_per_sec: u32 = env::var("LLUMA_RELAY_RL_REFILL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    // Optional signed client bootstrap to mirror at GET /v1/bootstrap. The relay
    // never authors or signs this — it serves the operator-provided blob verbatim
    // (a client verifies its signature against its pinned registry key). Absent
    // file ⇒ endpoint returns 404, exactly as before.
    let bootstrap_blob = match env::var("LLUMA_BOOTSTRAP_FILE") {
        Ok(path) if !path.is_empty() => match std::fs::read(&path) {
            Ok(bytes) => {
                tracing::info!("loaded bootstrap blob from {path} ({} bytes)", bytes.len());
                Some(bytes)
            }
            Err(e) => {
                eprintln!("error: LLUMA_BOOTSTRAP_FILE={path} could not be read: {e}");
                std::process::exit(1);
            }
        },
        _ => None,
    };

    let cfg = RelayConfig {
        gateway_url: gateway,
        max_body_bytes: max_body,
        per_ip: RateLimitConfig { capacity, refill_per_sec },
        pow_difficulty: 0,
        bootstrap_blob,
    };
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("lluma-relay listening on {bind}");
    axum::serve(
        listener,
        router(cfg).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
