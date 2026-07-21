//! Co-located issuer + broker origin binary (ADR-0002 §7 / spec R6): one redb
//! store backs the issuer's durable ledger + spent-set AND the broker's registry,
//! receipts, counters, and trial accounting. The issuer's `issued_observer` is
//! wired to the broker's per-epoch counter so the `redeemed ≤ issued` tripwire is
//! fed on every issuance. Two independently-bound listeners (R9): the core
//! (client-facing via relay→gateway) and the ingress (host/operator).
//!
//! This binary is DEPLOYMENT WIRING over the tested library APIs; it is
//! compile-checked here but exercised only in a real deployment (gated). All
//! key/salt material is loaded from operator-supplied files — no ephemeral keys.
//!
//! Env:
//!   LLUMA_DB_PATH              redb file path (required)
//!   LLUMA_ADMIN_SECRET         operator admin secret (required)
//!   LLUMA_ISSUER_SK_DER_FILE   issuer RSA secret key, DER (required)
//!   LLUMA_ISSUER_PK_DER_FILE   issuer RSA public key, DER (required)
//!   LLUMA_REGISTRY_SK_FILE     32-byte Ed25519 registry secret key (required)
//!   LLUMA_EPOCH_SALT_FILE      32-byte global PoW epoch salt (required)
//!   LLUMA_EPOCH                token epoch (default 1)
//!   LLUMA_POW_DIFFICULTY       PoW leading-zero bits (default 20)
//!   LLUMA_CORE_BIND            core listener addr (default 127.0.0.1:8080)
//!   LLUMA_INGRESS_BIND         ingress listener addr (default 127.0.0.1:8081)
//!   LLUMA_ALLOW_ZERO_SALT=1    dev-only: permit an all-zero epoch salt

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use lluma_broker::config::BrokerConfig;
use lluma_broker::service::{ingress_router, router as core_router, BrokerState};
use lluma_broker::{counters, RedbLedger, RedbSpentSet, Store};
use lluma_core::wire::{AccountSecretKey, IssuerPublicKey, IssuerSecretKey};
use lluma_issuer::idem::IssueIdempotencyCache;
use lluma_issuer::keys::EpochKeys;
use lluma_issuer::ledger::CreditLedger;
use lluma_issuer::service::{router as issuer_router, AppState};
use lluma_issuer::spent_set::SpentSet;

fn env(k: &str) -> Result<String, String> {
    std::env::var(k).map_err(|_| format!("missing required env {k}"))
}
fn env_or(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_string())
}
fn read_file(k: &str) -> Result<Vec<u8>, String> {
    let p = env(k)?;
    std::fs::read(&p).map_err(|_| format!("cannot read file at {k}={p}"))
}

fn now_unix_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<(), String> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();

    let db_path = env("LLUMA_DB_PATH")?;
    let admin_secret = env("LLUMA_ADMIN_SECRET")?;
    let issuer_sk = IssuerSecretKey(read_file("LLUMA_ISSUER_SK_DER_FILE")?);
    let issuer_pk = IssuerPublicKey(read_file("LLUMA_ISSUER_PK_DER_FILE")?);
    let registry_sk_bytes = read_file("LLUMA_REGISTRY_SK_FILE")?;
    if registry_sk_bytes.len() != 32 {
        return Err("LLUMA_REGISTRY_SK_FILE must be exactly 32 bytes".into());
    }
    let registry_sk = AccountSecretKey(registry_sk_bytes);

    let salt_bytes = read_file("LLUMA_EPOCH_SALT_FILE")?;
    if salt_bytes.len() != 32 {
        return Err("LLUMA_EPOCH_SALT_FILE must be exactly 32 bytes".into());
    }
    let mut epoch_salt = [0u8; 32];
    epoch_salt.copy_from_slice(&salt_bytes);
    // Zero-salt guard: refuse to start on an all-zero global PoW salt (it would
    // make PoW trivially precomputable) unless a dev override is set.
    if epoch_salt == [0u8; 32] && env_or("LLUMA_ALLOW_ZERO_SALT", "0") != "1" {
        return Err("refusing to start: LLUMA_EPOCH_SALT_FILE is all-zero (set LLUMA_ALLOW_ZERO_SALT=1 only in dev)".into());
    }

    let epoch: u64 = env_or("LLUMA_EPOCH", "1").parse().map_err(|_| "bad LLUMA_EPOCH")?;
    let pow_difficulty: u32 =
        env_or("LLUMA_POW_DIFFICULTY", "20").parse().map_err(|_| "bad LLUMA_POW_DIFFICULTY")?;
    let core_bind = env_or("LLUMA_CORE_BIND", "127.0.0.1:8080");
    let ingress_bind = env_or("LLUMA_INGRESS_BIND", "127.0.0.1:8081");

    let store = Store::open(std::path::Path::new(&db_path)).map_err(|_| "cannot open redb store")?;

    let cfg = BrokerConfig {
        pow_difficulty,
        epoch_salt,
        epoch_salt_prev: None,
        epoch,
        allow_loopback_ingress: false,
        ..BrokerConfig::default()
    };

    // Issuer runs on the shared durable store (co-located, R6). Its issuance
    // bumps the broker's per-epoch `issued` counter BEFORE releasing signatures.
    let store_for_issued = store.clone();
    let issuer_state = AppState {
        keys: Arc::new(EpochKeys { epoch, secret: issuer_sk, public: issuer_pk.clone() }),
        ledger: Arc::new(RedbLedger::new(store.clone())) as Arc<dyn CreditLedger>,
        spent: Arc::new(RedbSpentSet::new(store.clone(), epoch)) as Arc<dyn SpentSet>,
        idem: Arc::new(IssueIdempotencyCache::new()),
        admin_secret: Arc::new(admin_secret.clone()),
        now_unix_s,
        issued_observer: Some(Arc::new(move |ep, n| {
            if let Err(e) = counters::bump_issued(&store_for_issued, ep, n) {
                tracing::error!(?e, "failed to bump issued counter");
            }
        })),
    };

    let broker_state = BrokerState::new(issuer_pk, store, cfg, registry_sk, admin_secret, now_unix_s);

    // Core listener: issuer endpoints (key-config/issue/redeem) + broker core
    // (exec, snapshot GET) — this is the origin the gateway forwards to.
    let core_app = issuer_router(issuer_state).merge(core_router(broker_state.clone()));
    // Ingress listener: host registration/heartbeat/receipt, trial, admin.
    let ingress_app = ingress_router(broker_state);

    let core_listener = tokio::net::TcpListener::bind(&core_bind)
        .await
        .map_err(|_| format!("cannot bind core {core_bind}"))?;
    let ingress_listener = tokio::net::TcpListener::bind(&ingress_bind)
        .await
        .map_err(|_| format!("cannot bind ingress {ingress_bind}"))?;

    tracing::info!(%core_bind, %ingress_bind, epoch, "lluma-broker (co-located origin) starting");

    let core = async move { axum::serve(core_listener, core_app).await };
    let ingress = async move { axum::serve(ingress_listener, ingress_app).await };
    tokio::select! {
        r = core => r.map_err(|_| "core server error".to_string())?,
        r = ingress => r.map_err(|_| "ingress server error".to_string())?,
    }
    Ok(())
}
