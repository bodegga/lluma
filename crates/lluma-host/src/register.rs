//! Minimal broker registration + heartbeat client for a tunnel-mode host bin.
//! A NAT-bound host cannot accept inbound connections, so it registers with the
//! reserved sentinel ingress address (the broker routes it via the tunnel, never
//! dials it) and heartbeats to stay admitted. Registration is PoW-gated; the
//! signatures are the host's Ed25519 account key.
//!
//! These are outbound HTTP POSTs to the broker ingress — they work behind NAT,
//! exactly like the tunnel itself.

use std::time::Duration;

use lluma_core::proto::v1::{HeartbeatRequest, HostRegisterRequest};
use lluma_core::wire::{AccountSecretKey, HeartbeatBody, HostRegisterBody};
use lluma_core::ModelId;

/// Reserved ingress a tunnel host advertises (matches the broker's sentinel).
/// The broker returns `no_host` rather than ever dialing `.invalid`.
pub const TUNNEL_SENTINEL_ADDR: &str = "https://tunnel.invalid";

/// Inputs for registering + heartbeating a tunnel-mode host.
#[derive(Clone)]
pub struct RegisterConfig {
    /// Broker ingress base URL (e.g. `https://broker.example:8081`).
    pub broker_ingress: String,
    /// Current epoch PoW salt (operator-published).
    pub epoch_salt: [u8; 32],
    /// Registration PoW difficulty in leading zero bits (broker policy).
    pub pow_difficulty: u32,
    /// Heartbeat cadence in seconds (must be ≥ the broker's interval to admit).
    pub heartbeat_interval_s: u64,
    /// Advertised model labels.
    pub models: Vec<ModelId>,
}

#[derive(Debug)]
pub enum RegisterError {
    Sign,
    Transport,
    Rejected(u16),
}

fn http() -> Result<reqwest::Client, RegisterError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        // No redirects: register/heartbeat are signed to a specific origin
        // (derived from the registry-signed tunnel_url). A proxy misconfig must
        // never bounce a signed registration elsewhere (review R3, mirrors the
        // broker's redirect-none exec forwarder).
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| RegisterError::Transport)
}

/// Register this host (PoW-gated, tunnel sentinel ingress). Idempotent: a repeat
/// registration refreshes the existing row.
pub async fn register(
    cfg: &RegisterConfig,
    account_sk: &AccountSecretKey,
    host_account: [u8; 32],
    hpke_pk: &[u8],
) -> Result<(), RegisterError> {
    let body = HostRegisterBody {
        version: 1,
        host_account,
        hpke_pk: hpke_pk.to_vec(),
        ingress_addr: TUNNEL_SENTINEL_ADDR.into(),
        models: cfg.models.clone(),
    };
    let sig = lluma_crypto::account::host_register_sign(account_sk, &body)
        .map_err(|_| RegisterError::Sign)?;
    // PoW is a synchronous grind (up to minutes at high difficulty); run it off
    // the async runtime so it can't block a worker thread (review M1).
    let (salt, difficulty) = (cfg.epoch_salt, cfg.pow_difficulty);
    let nonce = tokio::task::spawn_blocking(move || {
        lluma_crypto::account::pow_solve(
            lluma_crypto::account::POW_HOST_DOMAIN,
            &host_account,
            &salt,
            difficulty,
        )
    })
    .await
    .map_err(|_| RegisterError::Transport)?;
    let req = HostRegisterRequest { body, sig: sig.0, pow_nonce: nonce.to_vec() };
    let bytes = serde_json::to_vec(&req).map_err(|_| RegisterError::Sign)?;
    post(&cfg.broker_ingress, "/v1/host/register", bytes).await
}

/// Send one heartbeat with the given monotonic counter.
pub async fn heartbeat(
    cfg: &RegisterConfig,
    account_sk: &AccountSecretKey,
    host_account: [u8; 32],
    hb_counter: u64,
) -> Result<(), RegisterError> {
    let body = HeartbeatBody {
        version: 1,
        host_account,
        hb_counter,
        load_bucket: 0,
        models: cfg.models.clone(),
    };
    let sig =
        lluma_crypto::account::heartbeat_sign(account_sk, &body).map_err(|_| RegisterError::Sign)?;
    let req = HeartbeatRequest { body, sig: sig.0 };
    let bytes = serde_json::to_vec(&req).map_err(|_| RegisterError::Sign)?;
    post(&cfg.broker_ingress, "/v1/heartbeat", bytes).await
}

async fn post(base: &str, path: &str, body: Vec<u8>) -> Result<(), RegisterError> {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let resp = http()?
        .post(&url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| RegisterError::Transport)?;
    let status = resp.status().as_u16();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(RegisterError::Rejected(status))
    }
}
