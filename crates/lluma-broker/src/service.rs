//! Broker HTTP surface — two independently-bound routers (R9 split ingress):
//!
//! - core: `POST /v1/exec` (redeem-and-forward), `GET /v1/snapshot`
//! - ingress: `POST /v1/host/register`, `/v1/heartbeat`, `/v1/receipt`, `/v1/register`
//!   (anti-Sybil trial), and `GET /admin/invariant`
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
    pub admin_secret: Arc<String>,
    /// Wall-clock source (injected for deterministic tests).
    pub now_unix_s: fn() -> u64,
    /// Forwarding client — **redirect-none** so a registered origin cannot 302
    /// to an internal address (SSRF; Fable MF7).
    pub http: reqwest::Client,
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
        Self {
            issuer_pk: Arc::new(issuer_pk),
            key_id,
            store,
            cfg,
            registry_sk: Arc::new(registry_sk),
            admin_secret: Arc::new(admin_secret),
            now_unix_s,
            http,
        }
    }
}

/// The core router: redeem + snapshot GET (client-facing via relay/gateway).
pub fn router(state: BrokerState) -> Router {
    Router::new()
        .route("/v1/exec", post(exec))
        .route("/v1/snapshot", get(snapshot_get))
        .with_state(state)
}

/// The ingress router: host registration/heartbeat/receipt, trial registration,
/// and operator invariant status. Bind this on a SEPARATE listener from `router`.
pub fn ingress_router(state: BrokerState) -> Router {
    Router::new()
        .route("/v1/host/register", post(host_register))
        .route("/v1/heartbeat", post(host_heartbeat))
        .route("/v1/receipt", post(receipt_submit))
        .route("/v1/register", post(trial_register))
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

    // Resolve the client-selected host to a registered ACTIVE ingress address
    // (before spending — do not burn a token if there is nowhere to serve it).
    let ingress_addr = match resolve_active_host(&st.store, &req.host_account) {
        Ok(Some(addr)) => addr,
        Ok(None) => return err(StatusCode::BAD_GATEWAY, "no_host"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };

    // Spend BEFORE forwarding, atomically: SPENT + SPEND_HOST + redeemed counter.
    // A tripped invariant (redeemed > issued) rolls the whole txn back (Err) so
    // the token is NOT recorded spent, and we refuse + alarm-log.
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

    // Forward {spend_id, sealed} to the resolved host (redirect-none client).
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

enum SpendOutcome {
    Spent,
    AlreadySpent,
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

async fn admin_invariant(State(st): State<BrokerState>, headers: HeaderMap) -> Response {
    let ok = headers
        .get("x-admin-secret")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == st.admin_secret.as_str())
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
