//! `lluma-gateway` binary. Generates an epoch OHTTP keypair on startup and
//! prints its key-config (base64) so it can be published in the signed bootstrap
//! (persistence across restarts is a #4 concern). Forwards only to the
//! configured origin over an SSRF-guarded allowlist.

use std::env;

use base64::Engine;

use lluma_gateway::{router, GatewayConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_target(true).with_level(true).init();

    let bind = env::var("LLUMA_GATEWAY_BIND").unwrap_or_else(|_| "127.0.0.1:8782".to_string());
    let origin = env::var("LLUMA_GATEWAY_ORIGIN").unwrap_or_default();
    if origin.is_empty() {
        eprintln!("error: LLUMA_GATEWAY_ORIGIN is required (the fixed origin URL)");
        std::process::exit(1);
    }
    let prefixes: Vec<String> = env::var("LLUMA_GATEWAY_PREFIXES")
        .unwrap_or_else(|_| "/v1/issue,/v1/redeem,/v1/key-config".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let key_id: u8 = env::var("LLUMA_GATEWAY_KEY_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    // ohttp keygen uses the rand_core 0.6 OsRng path.
    let mut rng = rand_core::OsRng;
    let (secret, key_config) = lluma_crypto::ohttp::ohttp_keygen(&mut rng, key_id)?;
    let kc_b64 = base64::engine::general_purpose::STANDARD.encode(&key_config.0);
    tracing::info!("gateway key_config (base64 — publish in the signed bootstrap): {kc_b64}");

    let state = GatewayConfig {
        secret,
        origin_url: origin,
        allowed_path_prefixes: prefixes,
    };
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("lluma-gateway listening on {bind}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
