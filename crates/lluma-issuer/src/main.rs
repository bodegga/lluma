//! `main.rs` — the lluma-issuer binary (Task 9).
//!
//! Reads its configuration from environment variables, builds the in-memory
//! `AppState` over a persisted epoch keypair (atomic write), and serves the
//! axum router from a bound `TcpListener`.
//!
//! ## Design notes
//!
//! - **No `panic!`/`unwrap`/`expect` here** except on the genuinely infallible
//!   `now_unix_s` clock closure (where unwrapping `Duration` from `SystemTime`
//!   is replaced with a `unwrap_or(0)` fallback returning 0 on a clock that
//!   raced backwards past the epoch). The brief forbids panicking on missing
//!   configuration, so a missing `LLUMA_ISSUER_ADMIN_SECRET` is a clean
//!   `eprintln!` to stderr + `std::process::exit(1)` — never a panic.
//! - **No `anyhow`**: `main` returns `Result<(), Box<dyn std::error::Error>>`
//!   so library errors propagate naturally via `?`. The error's `Display`
//!   is server-side only (the process exit message); no request bytes ever
//!   reach stderr — `IssuerError::Internal`'s static message is the worst
//!   case here.
//! - **No body logging**: `tracing_subscriber::fmt` is initialized with its
//!   defaults — the default fmt layer never logs request/response bodies
//!   (only span fields the application explicitly attaches). The issuer's
//!   handlers (Task 7) record no body bytes anywhere. The single startup
//!   log line is the bind address so operators know where the service lives.
//!
//! ## Env
//!
//! - `LLUMA_ISSUER_BIND` (default `127.0.0.1:8781`) — `SocketAddr` to bind.
//! - `LLUMA_ISSUER_KEY_PATH` (default `./issuer-key.json`) — path to the
//!   persistent epoch keypair (created if absent).
//! - `LLUMA_ISSUER_EPOCH` (default `1`, parsed as `u64`) — epoch number
//!   passed to `keys::load_or_create` on a fresh file.
//! - `LLUMA_ISSUER_ADMIN_SECRET` (**required**, non-empty) — value the
//!   `/v1/admin/grant` handler compares the `x-admin-secret` header against.

use std::env;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use lluma_issuer::idem::IssueIdempotencyCache;
use lluma_issuer::keys;
use lluma_issuer::ledger::{CreditLedger, InMemoryLedger};
use lluma_issuer::service::{router, AppState};
use lluma_issuer::spent_set::{InMemorySpentSet, SpentSet};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the tracing fmt subscriber. The default subscriber does NOT
    // log request/response bodies — only the spans/events the application
    // emits. The issuer's handlers emit no body events (L8 invarint).
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .init();

    // ---- Configuration (env vars with safe defaults / required values) ----

    let bind = env::var("LLUMA_ISSUER_BIND").unwrap_or_else(|_| "127.0.0.1:8781".to_string());
    let key_path = env::var("LLUMA_ISSUER_KEY_PATH")
        .unwrap_or_else(|_| "./issuer-key.json".to_string());
    let epoch: u64 = env::var("LLUMA_ISSUER_EPOCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let admin_secret = env::var("LLUMA_ISSUER_ADMIN_SECRET").unwrap_or_default();
    if admin_secret.is_empty() {
        // Refuse to start without an admin secret — the brief forbids panicking
        // here. A static message to stderr + a nonzero exit code is the clean
        // operator-side failure mode.
        eprintln!("error: LLUMA_ISSUER_ADMIN_SECRET is required and must be non-empty");
        std::process::exit(1);
    }

    // ---- State construction ----

    // Atomic load-or-create of the persistent epoch keypair. On a brand-new
    // deploy this generates and persists an RSA-2048 key; on restart it
    // reloads the same key so previously issued tokens still verify.
    let epoch_keys = keys::load_or_create(Path::new(&key_path), epoch)?;

    let now_unix_s: fn() -> u64 = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };

    let state = AppState {
        keys: Arc::new(epoch_keys),
        ledger: Arc::new(InMemoryLedger::new()) as Arc<dyn CreditLedger>,
        spent: Arc::new(InMemorySpentSet::new()) as Arc<dyn SpentSet>,
        idem: Arc::new(IssueIdempotencyCache::new()),
        admin_secret: Arc::new(admin_secret),
        now_unix_s,
    };

    // ---- Serve ----

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    // A single startup log line — the bind address only. No ports of fields
    // derived from any request, no body.
    tracing::info!("lluma-issuer listening on {bind}");

    axum::serve(listener, router(state)).await?;
    Ok(())
}