//! `lluma-host` binary. Two modes:
//!
//! - **Dial-in (default):** generate an HPKE host keypair, print the public key
//!   for the broker directory, and serve `/v1/exec` (echo upstream by default).
//!   The broker dials the host's public ingress.
//!
//! - **Tunnel (set `LLUMA_TUNNEL_URL`):** for a NAT-bound host. Generate an
//!   Ed25519 account key + HPKE key, PoW-register with the broker (sentinel
//!   ingress), heartbeat to stay admitted, and hold an OUTBOUND wss to the
//!   broker over which it serves pushed jobs. No inbound port.
//!
//! A real LLM adapter swaps in behind the `Upstream` trait; the default is echo.

use std::env;
use std::sync::Arc;

use base64::Engine;

use lluma_host::register::{self, RegisterConfig};
use lluma_host::tunnel::{self, TunnelConfig};
use lluma_host::{router, EchoUpstream, HostState, OpenAiUpstream, Upstream};
use lluma_core::ModelId;

fn b64d(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| format!("bad base64: {e}"))
}

fn env_b32(k: &str) -> Result<[u8; 32], String> {
    let v = env::var(k).map_err(|_| format!("missing required env {k}"))?;
    let bytes = b64d(&v)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| format!("{k} must be 32 bytes (base64)"))
}

/// Select the upstream from `LLUMA_OPENAI_BASE` (if set) or echo.
fn build_upstream() -> Arc<dyn Upstream> {
    match env::var("LLUMA_OPENAI_BASE") {
        Ok(base) if !base.trim().is_empty() => Arc::new(OpenAiUpstream::new(
            base,
            env::var("LLUMA_OPENAI_MODEL").unwrap_or_default(),
            env::var("LLUMA_OPENAI_API_KEY").unwrap_or_default(),
        )),
        _ => {
            let sentinel = env::var("LLUMA_HOST_SENTINEL").unwrap_or_else(|_| "ANSWER: ".to_string());
            Arc::new(EchoUpstream { sentinel: sentinel.into_bytes() })
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_target(true).with_level(true).init();

    // tokio-tungstenite's rustls build ships no default crypto provider, so a
    // wss handshake would panic without this. Install `ring` process-wide before
    // any TLS (dial-in mode never uses TLS, so this is harmless there).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut rng = rand_core::OsRng;
    let (host_sk, host_pk) = lluma_crypto::e2e::host_keygen(&mut rng)?;
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&host_pk.0);
    let upstream = build_upstream();

    match env::var("LLUMA_TUNNEL_URL") {
        // ---- Tunnel mode ----
        Ok(tunnel_url) if !tunnel_url.trim().is_empty() => {
            // Enforce wss:// (crypto-architect must-have 1: plain ws is
            // hijackable post-handshake — a MITM captures the authenticated
            // socket and steals free inference). Allow ws:// ONLY for loopback
            // or an explicit dev override. Copy this URL only from a bootstrap
            // you verified against the pinned registry key.
            {
                let u = reqwest::Url::parse(&tunnel_url)
                    .map_err(|_| "LLUMA_TUNNEL_URL is not a valid URL")?;
                let is_loopback = matches!(
                    u.host_str(),
                    Some("127.0.0.1") | Some("localhost") | Some("::1") | Some("[::1]")
                );
                let insecure_ok =
                    std::env::var("LLUMA_TUNNEL_INSECURE_WS").ok().as_deref() == Some("1")
                        || is_loopback;
                match u.scheme() {
                    "wss" => {}
                    "ws" if insecure_ok => {
                        tracing::warn!("tunnel over PLAIN ws (insecure) — loopback/dev only")
                    }
                    _ => {
                        return Err("LLUMA_TUNNEL_URL must be wss:// (set LLUMA_TUNNEL_INSECURE_WS=1 only for loopback tests)".into())
                    }
                }
            }
            let broker_ingress =
                env::var("LLUMA_BROKER_INGRESS").map_err(|_| "missing LLUMA_BROKER_INGRESS")?;
            let broker_key_id = env_b32("LLUMA_REGISTRY_PK_B64")?;
            let epoch_salt = env_b32("LLUMA_EPOCH_SALT_B64")?;
            let pow_difficulty: u32 =
                env::var("LLUMA_POW_DIFFICULTY").ok().and_then(|v| v.parse().ok()).unwrap_or(20);
            let heartbeat_interval_s: u64 =
                env::var("LLUMA_HEARTBEAT_INTERVAL_S").ok().and_then(|v| v.parse().ok()).unwrap_or(30);
            let model_id = env::var("LLUMA_MODEL_ID").unwrap_or_else(|_| "echo".to_string());

            // A fresh account identity each run (verify/ephemeral host). Persisting
            // it is a future nicety; the account only earns credits, holds no funds.
            let mnemonic = lluma_crypto::account::account_mnemonic_new(&mut rng)?;
            let (account_sk, account_pk) =
                lluma_crypto::account::derive_keypair_from_seed(&mnemonic)?;
            let host_account: [u8; 32] = account_pk
                .0
                .as_slice()
                .try_into()
                .map_err(|_| "account pubkey must be 32 bytes")?;

            let rcfg = RegisterConfig {
                broker_ingress,
                epoch_salt,
                pow_difficulty,
                heartbeat_interval_s,
                models: vec![ModelId(model_id)],
            };

            tracing::info!("tunnel mode: registering host {}", hex32(&host_account));
            register::register(&rcfg, &account_sk, host_account, &host_pk.0)
                .await
                .map_err(|e| format!("host register failed: {e:?}"))?;
            tracing::info!("registered; starting heartbeat loop + tunnel dial to {tunnel_url}");

            // Heartbeat loop (background): keeps the host admitted so exec can
            // route to it. The tunnel handshake only needs registration, but a
            // full exec needs ACTIVE (M spaced heartbeats).
            let hb_cfg = rcfg.clone();
            let hb_sk = account_sk.clone();
            let hb_pk = host_pk.0.clone();
            tokio::spawn(async move {
                let mut fails: u32 = 0;
                loop {
                    // Counter = wall-clock seconds so it stays monotonic across
                    // restarts (the broker rejects a non-increasing counter as a
                    // replay; a per-process counter from 1 would wedge). (review I1)
                    let counter = now_unix_s();
                    // First heartbeat fires immediately, then on the interval.
                    match register::heartbeat(&hb_cfg, &hb_sk, host_account, counter).await {
                        Ok(()) => fails = 0,
                        Err(e) => {
                            fails += 1;
                            tracing::warn!("heartbeat {counter} failed: {e:?}");
                            // The broker may have restarted/pruned our row — try
                            // to re-register after several consecutive failures.
                            if fails >= 3 {
                                tracing::info!("re-registering after {fails} failed heartbeats");
                                let _ = register::register(&hb_cfg, &hb_sk, host_account, &hb_pk)
                                    .await;
                                fails = 0;
                            }
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(hb_cfg.heartbeat_interval_s))
                        .await;
                }
            });

            let tcfg = TunnelConfig { url: tunnel_url, host_account, account_sk, broker_key_id };
            // Never returns (reconnects forever).
            tunnel::run(tcfg, Arc::new(host_sk), upstream).await;
            Ok(())
        }
        // ---- Dial-in mode (default) ----
        _ => {
            let bind = env::var("LLUMA_HOST_BIND").unwrap_or_else(|_| "127.0.0.1:8783".to_string());
            tracing::info!("host_pk (base64 — publish in the broker directory): {pk_b64}");
            let state = HostState { host_sk: Arc::new(host_sk), upstream };
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!("lluma-host listening on {bind}");
            axum::serve(listener, router(state)).await?;
            Ok(())
        }
    }
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn now_unix_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
