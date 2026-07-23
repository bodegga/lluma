//! Broker HTTP surface — two independently-bound routers (R9 split ingress):
//!
//! - core (client-facing via relay→gateway): `POST /v1/exec` (redeem-and-forward),
//!   `POST /v1/register` (anti-Sybil trial — MUST be on the relay-routed path so a
//!   consumer never hands the broker `IP + account_pk`, leak L16), `GET /v1/snapshot`
//! - ingress (host/operator): `POST /v1/host/register`, `/v1/heartbeat`,
//!   `/v1/receipt`, and `GET /admin/invariant`
//!
//! A heartbeat/receipt/registration flood on the ingress listener therefore
//! cannot starve redeem on the core listener.
//!
//! The broker is the SOLE redeemer (ADR-0003): `/v1/exec` verifies the token and,
//! in ONE durable write transaction, spends `spend_id`, binds it to the selected
//! host (`SPEND_HOST`), and bumps the per-epoch `redeemed` counter — refusing +
//! rolling back if that trips the `redeemed ≤ issued` invariant — all BEFORE
//! forwarding. It sees ciphertext + spend_id + routing metadata, never the
//! originator IP (relay-only ingress) or the prompt plaintext (E2E-sealed).
//! Errors are uniform + detail-free (leak L8).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use redb::ReadableTable;

use lluma_core::proto::v1::{
    ExecRequest, HeartbeatRequest, HostExecRequest, HostRegisterRequest, ReceiptSubmit,
    TrialRegisterRequest,
};
use lluma_core::wire::{AccountSecretKey, IssuerPublicKey, SnapshotHeader};

use crate::config::BrokerConfig;
use crate::error::BrokerError;
use crate::store::{HostRow, Store, HOSTS, HOST_ACTIVE, SPENT, SPEND_HOST};
use crate::{counters, receipts, registry, snapshot, trial};

/// Shared broker state. Cloneable (all fields cheap/`Arc`).
#[derive(Clone)]
pub struct BrokerState {
    pub issuer_pk: Arc<IssuerPublicKey>,
    pub key_id: [u8; 32],
    pub store: Store,
    pub cfg: BrokerConfig,
    /// Dedicated registry Ed25519 secret key for signing snapshots (R10).
    pub registry_sk: Arc<AccountSecretKey>,
    /// The registry Ed25519 PUBLIC key (32 B), derived from `registry_sk`. Used
    /// as the `broker_key_id` a host binds into its tunnel-auth signature — the
    /// host already trusts this key via the signed bootstrap.
    pub registry_pk: [u8; 32],
    pub admin_secret: Arc<String>,
    /// Wall-clock source (injected for deterministic tests).
    pub now_unix_s: fn() -> u64,
    /// Forwarding client — **redirect-none** so a registered origin cannot 302
    /// to an internal address (SSRF; Fable MF7).
    pub http: reqwest::Client,
    /// Live reverse-tunnel sockets (host_account → socket). Empty for dial-in.
    pub tunnels: Arc<crate::tunnel::TunnelRegistry>,
}

impl BrokerState {
    pub fn new(
        issuer_pk: IssuerPublicKey,
        store: Store,
        cfg: BrokerConfig,
        registry_sk: AccountSecretKey,
        admin_secret: String,
        now_unix_s: fn() -> u64,
    ) -> Self {
        let key_id = *blake3::hash(&issuer_pk.0).as_bytes();
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        // Derive the registry public key (the tunnel `broker_key_id`). A bad
        // secret key would already have failed snapshot signing; fall back to
        // all-zero (which no genuine host can produce a matching sig for) rather
        // than panic in a library constructor.
        let registry_pk = lluma_crypto::account::account_public_from_secret(&registry_sk)
            .ok()
            .and_then(|pk| <[u8; 32]>::try_from(pk.0.as_slice()).ok())
            .unwrap_or([0u8; 32]);
        Self {
            issuer_pk: Arc::new(issuer_pk),
            key_id,
            store,
            cfg,
            registry_sk: Arc::new(registry_sk),
            registry_pk,
            admin_secret: Arc::new(admin_secret),
            now_unix_s,
            http,
            tunnels: crate::tunnel::TunnelRegistry::new(),
        }
    }
}

/// The core router: redeem, trial registration, and snapshot GET — all
/// client-facing via the relay→gateway path. Trial register lives here (NOT on
/// ingress) so a consumer's `account_pk` never lands at the broker alongside its
/// IP (leak L16); the gateway path-allowlist gates access.
pub fn router(state: BrokerState) -> Router {
    Router::new()
        .route("/v1/exec", post(exec))
        .route("/v1/register", post(trial_register))
        .route("/v1/snapshot", get(snapshot_get))
        .with_state(state)
}

/// The ingress router: host registration/heartbeat/receipt and operator
/// invariant status. Bind this on a SEPARATE listener from `router`.
pub fn ingress_router(state: BrokerState) -> Router {
    Router::new()
        .route("/v1/host/register", post(host_register))
        .route("/v1/heartbeat", post(host_heartbeat))
        .route("/v1/receipt", post(receipt_submit))
        // Reverse-tunnel WebSocket: a NAT-bound host holds this open outbound so
        // the broker can push exec jobs without dialing in. TLS-terminated by the
        // fronting proxy in prod (item C); path-routed on the ingress listener so
        // connection-counting is blunted (spec §Track 1).
        .route(crate::tunnel::TUNNEL_PATH, get(crate::tunnel::tunnel_ws))
        .route("/admin/invariant", get(admin_invariant))
        .with_state(state)
}

fn err(status: StatusCode, code: &'static str) -> Response {
    (status, Json(serde_json::json!({ "code": code, "message": code }))).into_response()
}

fn ok_code(code: &'static str) -> Response {
    (StatusCode::OK, Json(serde_json::json!({ "code": code }))).into_response()
}

// ---- core: redeem-and-forward ----

async fn exec(State(st): State<BrokerState>, body: Bytes) -> Response {
    let req: ExecRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "bad_request"),
    };
    if req.validate().is_err() || req.key_id != st.key_id {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "token_invalid");
    }
    if lluma_crypto::tokens::token_verify(st.issuer_pk.as_ref(), &req.token).is_err() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "token_invalid");
    }
    let spend_id = lluma_crypto::tokens::token_spend_id(&req.token);

    // Resolve the client-selected host (must be registered + ACTIVE) BEFORE
    // spending — do not burn a token if there is nowhere to serve it. Prefer a
    // live reverse-tunnel socket over dialing the ingress; a tunnel socket at
    // its in-flight cap fails as `no_host` here (never burns the token, never
    // dials the vestigial address of a NAT host). The reserved slot is held by
    // `Route::Tunnel`'s guard and released on every exit path below.
    let route = match resolve_active_host(&st.store, &req.host_account) {
        Ok(Some(addr)) => match crate::tunnel::reserve_tunnel(&st.tunnels, &req.host_account) {
            crate::tunnel::Reservation::Reserved(guard) => Route::Tunnel(guard),
            crate::tunnel::Reservation::AtCapacity => {
                return err(StatusCode::BAD_GATEWAY, "no_host")
            }
            // No live socket: a tunnel-mode host (sentinel address) has nowhere to
            // dial, so fail as `no_host` BEFORE spending rather than burning a
            // token on a bogus dial (review I1). A genuine dial-in host is dialed.
            crate::tunnel::Reservation::NoSocket => {
                if addr == crate::tunnel::TUNNEL_SENTINEL_ADDR {
                    return err(StatusCode::BAD_GATEWAY, "no_host");
                }
                Route::Http(addr)
            }
        },
        Ok(None) => return err(StatusCode::BAD_GATEWAY, "no_host"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };

    // Spend BEFORE forwarding, atomically: SPENT + SPEND_HOST + redeemed counter.
    // A tripped invariant (redeemed > issued) rolls the whole txn back (Err) so
    // the token is NOT recorded spent, and we refuse + alarm-log.
    // TODO(multi-epoch): key the counter by the TOKEN's epoch (derived from
    // key_id), not cfg.epoch. Sound for the single-epoch MVP (one accepted
    // key_id; issued is bumped at the matching issuer epoch), but a future key
    // rotation must derive the epoch here before accepting k/k-1 tokens (else
    // the false-trip that Fable's must-fix 5 prevented reappears).
    let epoch = st.cfg.epoch;
    let host_account = req.host_account;
    let spend_outcome = st.store.with_write(move |w| {
        let mut spent = w.open_table(SPENT).map_err(|_| BrokerError::Storage)?;
        if spent.get(&spend_id.0[..]).map_err(|_| BrokerError::Storage)?.is_some() {
            return Ok(SpendOutcome::AlreadySpent);
        }
        spent.insert(&spend_id.0[..], epoch).map_err(|_| BrokerError::Storage)?;
        drop(spent);
        let mut sh = w.open_table(SPEND_HOST).map_err(|_| BrokerError::Storage)?;
        sh.insert(&spend_id.0[..], &host_account[..]).map_err(|_| BrokerError::Storage)?;
        drop(sh);
        // Tripwire: if this redeem pushes redeemed past issued, fail the txn so
        // nothing commits (the spend is rolled back).
        if !counters::note_redeem_txn(w, epoch)? {
            return Err(BrokerError::Storage); // treated as tripwire below
        }
        Ok(SpendOutcome::Spent)
    });
    match spend_outcome {
        Ok(SpendOutcome::Spent) => {}
        Ok(SpendOutcome::AlreadySpent) => return err(StatusCode::CONFLICT, "double_spend"),
        Err(_) => {
            // Either a storage fault or the invariant tripwire — both fail closed.
            tracing::error!("exec redeem aborted (storage or redeemed>issued tripwire) — refusing");
            return err(StatusCode::CONFLICT, "refused");
        }
    }

    // Forward {spend_id, sealed} to the resolved host. Both paths preserve the
    // sealed envelope (aad = spend_id, HPKE to the host key) and receipts — the
    // broker never sees plaintext, the host never sees the originator IP.
    match route {
        // Reverse tunnel: push the job down the host's outbound socket and await
        // the sealed response (bounded by the tunnel request timeout). The
        // in-flight reservation is released when `guard` drops at end of scope.
        Route::Tunnel(guard) => {
            match crate::tunnel::dispatch(&guard, spend_id, req.sealed).await {
                Ok(resp) => match serde_json::to_vec(&resp) {
                    Ok(b) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], b)
                        .into_response(),
                    Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
                },
                Err(_) => err(StatusCode::BAD_GATEWAY, "upstream"),
            }
        }
        // Dial-in: POST to the host's public ingress (redirect-none client).
        Route::Http(ingress_addr) => {
            let hreq = HostExecRequest { spend_id, sealed: req.sealed };
            let hbody = match serde_json::to_vec(&hreq) {
                Ok(b) => b,
                Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            };
            let resp = match st
                .http
                .post(format!("{ingress_addr}/v1/exec"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(hbody)
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => return err(StatusCode::BAD_GATEWAY, "upstream"),
            };
            if !resp.status().is_success() {
                return err(StatusCode::BAD_GATEWAY, "upstream");
            }
            let rbytes = match resp.bytes().await {
                Ok(b) => b.to_vec(),
                Err(_) => return err(StatusCode::BAD_GATEWAY, "upstream"),
            };
            (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], rbytes).into_response()
        }
    }
}

enum SpendOutcome {
    Spent,
    AlreadySpent,
}

/// Where a resolved exec should be forwarded.
enum Route {
    /// A live reverse-tunnel socket with a reserved in-flight slot.
    Tunnel(crate::tunnel::InflightGuard),
    /// A dial-in host at this public ingress address.
    Http(String),
}

/// Resolve `host_account` to its registered ingress address iff it is ACTIVE.
fn resolve_active_host(store: &Store, host_account: &[u8; 32]) -> Result<Option<String>, BrokerError> {
    store.with_read(|r| {
        let t = r.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
        let bytes = t
            .get(&host_account[..])
            .map_err(|_| BrokerError::Storage)?
            .map(|v| v.value().to_vec());
        match bytes {
            Some(b) => {
                let row: HostRow = postcard::from_bytes(&b).map_err(|_| BrokerError::Storage)?;
                Ok((row.status == HOST_ACTIVE).then_some(row.ingress_addr))
            }
            None => Ok(None),
        }
    })
}


// ---- core: snapshot GET ----

async fn snapshot_get(State(st): State<BrokerState>) -> Response {
    let header = SnapshotHeader {
        epoch: st.cfg.epoch,
        issued_at_h: ((st.now_unix_s)() / 3600) as u32,
        issuer_key_id: st.key_id,
    };
    match snapshot::publish(&st.store, header, &st.registry_sk) {
        Ok(resp) => match serde_json::to_vec(&resp) {
            Ok(b) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], b).into_response(),
            Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        },
        Err(BrokerError::SnapshotTooLarge) => {
            // Fail closed + ALARM: the active-host set no longer fits the fixed
            // bucket. Never silently grow it (would leak host count, L4).
            tracing::error!("ALARM: snapshot exceeds fixed 64 KiB bucket — refusing to publish");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

// ---- ingress: host registration / heartbeat / receipt ----

async fn host_register(State(st): State<BrokerState>, body: Bytes) -> Response {
    let req: HostRegisterRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "bad_request"),
    };
    match registry::register(&st.store, &req, &st.cfg, (st.now_unix_s)()) {
        Ok(registry::RegisterOutcome::Registered) => ok_code("registered"),
        Ok(registry::RegisterOutcome::Updated) => ok_code("updated"),
        Ok(_) => err(StatusCode::UNPROCESSABLE_ENTITY, "rejected"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

async fn host_heartbeat(State(st): State<BrokerState>, body: Bytes) -> Response {
    let req: HeartbeatRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "bad_request"),
    };
    match registry::heartbeat(&st.store, &req, (st.now_unix_s)(), &st.cfg) {
        Ok(registry::HeartbeatOutcome::Accepted { .. }) => ok_code("accepted"),
        Ok(_) => err(StatusCode::UNPROCESSABLE_ENTITY, "rejected"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

async fn receipt_submit(State(st): State<BrokerState>, body: Bytes) -> Response {
    let req: ReceiptSubmit = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "bad_request"),
    };
    match receipts::ingest(&st.store, &req, &st.cfg) {
        Ok(receipts::IngestOutcome::Credited) => ok_code("credited"),
        Ok(receipts::IngestOutcome::AlreadyCredited) => ok_code("already_credited"),
        Ok(_) => err(StatusCode::UNPROCESSABLE_ENTITY, "rejected"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

// ---- ingress: anti-Sybil trial registration ----

async fn trial_register(State(st): State<BrokerState>, body: Bytes) -> Response {
    let req: TrialRegisterRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "bad_request"),
    };
    let day = (st.now_unix_s)() / 86_400;
    match trial::grant_trial(&st.store, &req, &st.cfg, day) {
        Ok(trial::TrialOutcome::Granted) => ok_code("granted"),
        // UNIFORM refusal (Fable should-fix 5): AlreadyGranted / BudgetExhausted /
        // BadPow / BadRequest all map to ONE indistinguishable response — no
        // per-account budget signal leaks.
        Ok(_) => err(StatusCode::TOO_MANY_REQUESTS, "unavailable"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

// ---- ingress: operator invariant status ----

/// Constant-time byte compare (length is allowed to leak; contents are not).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

async fn admin_invariant(State(st): State<BrokerState>, headers: HeaderMap) -> Response {
    let ok = headers
        .get("x-admin-secret")
        .and_then(|v| v.to_str().ok())
        .map(|v| ct_eq(v.as_bytes(), st.admin_secret.as_bytes()))
        .unwrap_or(false);
    if !ok {
        return err(StatusCode::FORBIDDEN, "forbidden");
    }
    match counters::read(&st.store, st.cfg.epoch) {
        Ok(c) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "epoch": st.cfg.epoch,
                "issued": c.issued,
                "redeemed": c.redeemed,
                "trial_granted": c.trial_granted,
                "invariant_holds": c.redeemed <= c.issued,
            })),
        )
            .into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}
