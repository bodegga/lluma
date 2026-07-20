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

    let cfg = RelayConfig {
        gateway_url: gateway,
        max_body_bytes: max_body,
        per_ip: RateLimitConfig { capacity, refill_per_sec },
        pow_difficulty: 0,
        bootstrap_blob: None,
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
