//! Broker `/v1/exec` — the redeem-and-forward path. The broker is the SOLE
//! redeemer (ADR-0003): it verifies the token, spends its `spend_id` in the
//! durable spent-set **before forwarding** (a double-spend must never reach a
//! host), resolves the host, and forwards `{spend_id, sealed}`. It sees
//! ciphertext + spend_id + routing metadata — never the originator IP (relay is
//! the only ingress) or the prompt plaintext (E2E-sealed to the host key).
//! Errors are uniform + detail-free (leak L8).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

use lluma_core::proto::v1::{ExecRequest, HostExecRequest};
use lluma_core::wire::IssuerPublicKey;
use lluma_issuer::spent_set::{InsertOutcome, SpentSet};

use crate::hosts::StaticHostDirectory;

#[derive(Clone)]
pub struct BrokerState {
    pub issuer_pk: Arc<IssuerPublicKey>,
    pub key_id: [u8; 32],
    pub spent: Arc<dyn SpentSet>,
    pub hosts: Arc<StaticHostDirectory>,
    pub http: reqwest::Client,
}

impl BrokerState {
    /// Build state; `key_id` is derived as `BLAKE3(issuer pubkey)`.
    pub fn new(
        issuer_pk: IssuerPublicKey,
        spent: Arc<dyn SpentSet>,
        hosts: StaticHostDirectory,
    ) -> Self {
        let key_id = *blake3::hash(&issuer_pk.0).as_bytes();
        Self {
            issuer_pk: Arc::new(issuer_pk),
            key_id,
            spent,
            hosts: Arc::new(hosts),
            // Bounded timeouts: a hung host must not pin an exec forever after
            // the token is already durably spent (Fable review).
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }
}

pub fn router(state: BrokerState) -> Router {
    Router::new().route("/v1/exec", post(exec)).with_state(state)
}

fn err(status: StatusCode, code: &'static str) -> Response {
    (status, Json(serde_json::json!({ "code": code, "message": code }))).into_response()
}

async fn exec(State(st): State<BrokerState>, body: Bytes) -> Response {
    // Parse (never surface serde text — L8).
    let req: ExecRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "bad_request"),
    };
    if req.validate().is_err() || req.key_id != st.key_id {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "token_invalid");
    }
    // Verify the blind-signed token under the issuer's public key.
    if lluma_crypto::tokens::token_verify(st.issuer_pk.as_ref(), &req.token).is_err() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "token_invalid");
    }
    // Spend BEFORE forwarding — the durable spent-set is the double-spend
    // arbiter; a replayed token must never reach a host.
    let spend_id = lluma_crypto::tokens::token_spend_id(&req.token);
    match st.spent.insert(spend_id) {
        InsertOutcome::AlreadySpent => return err(StatusCode::CONFLICT, "double_spend"),
        InsertOutcome::Inserted => {}
    }
    // Resolve the (single, for the slice) host and forward {spend_id, sealed}.
    let host = match st.hosts.first() {
        Some(h) => h,
        None => return err(StatusCode::BAD_GATEWAY, "no_host"),
    };
    let hreq = HostExecRequest {
        spend_id,
        sealed: req.sealed,
    };
    let hbody = match serde_json::to_vec(&hreq) {
        Ok(b) => b,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };
    let resp = match st
        .http
        .post(format!("{}/v1/exec", host.ingress_url))
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
    // Return the host's sealed ExecResponse opaquely (the broker cannot read it).
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        rbytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosts::HostEntry;
    use crate::spent::RedbSpentSet;
    use crate::store::Store;
    use lluma_core::proto::v1::ExecResponse;
    use lluma_core::wire::{AccountId, HostPublicKey, ResponsePreamble, SealedRequest, Token};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    static CTR: AtomicU64 = AtomicU64::new(0);
    fn tmp() -> std::path::PathBuf {
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!("lluma-broker-svc-{}-{}.redb", std::process::id(), n));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn real_token() -> (IssuerPublicKey, Token) {
        let mut rng = blind_rsa_signatures::DefaultRng;
        let (sk, pk) = lluma_crypto::tokens::issuer_keygen(&mut rng).unwrap();
        let (bs, req) = lluma_crypto::tokens::token_blind(&mut rng, &pk).unwrap();
        let sig = lluma_crypto::tokens::token_issue(&mut rng, &sk, &req).unwrap();
        let token = lluma_crypto::tokens::token_unblind(&pk, bs, &sig).unwrap();
        (pk, token)
    }

    async fn spawn(app: Router) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        format!("http://{addr}")
    }

    async fn mock_host(hits: Arc<AtomicU64>) -> String {
        let app = Router::new().route(
            "/v1/exec",
            post(move |_b: Bytes| {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Json(ExecResponse {
                        preamble: ResponsePreamble(vec![1, 2, 3]),
                        chunk: vec![4, 5, 6],
                    })
                }
            }),
        );
        spawn(app).await
    }

    fn exec_body(key_id: [u8; 32], token: &Token) -> Vec<u8> {
        serde_json::to_vec(&ExecRequest {
            key_id,
            token: token.clone(),
            sealed: SealedRequest(vec![9u8; 48]),
        })
        .unwrap()
    }

    fn dir(host_url: String) -> StaticHostDirectory {
        StaticHostDirectory::new(vec![HostEntry {
            host_account: AccountId([1; 32]),
            ingress_url: host_url,
            host_pk: HostPublicKey(vec![0; 32]),
        }])
    }

    #[tokio::test]
    async fn exec_forwards_then_double_spend_never_reaches_host() {
        let (pk, token) = real_token();
        let key_id = *blake3::hash(&pk.0).as_bytes();
        let hits = Arc::new(AtomicU64::new(0));
        let host_url = mock_host(hits.clone()).await;
        let spent = Arc::new(RedbSpentSet::new(Store::open(&tmp()).unwrap(), 1));
        let broker = spawn(router(BrokerState::new(pk, spent, dir(host_url)))).await;
        let client = reqwest::Client::new();

        let r1 = client
            .post(format!("{broker}/v1/exec"))
            .header("content-type", "application/json")
            .body(exec_body(key_id, &token))
            .send()
            .await
            .unwrap();
        assert_eq!(r1.status(), 200);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let r2 = client
            .post(format!("{broker}/v1/exec"))
            .header("content-type", "application/json")
            .body(exec_body(key_id, &token))
            .send()
            .await
            .unwrap();
        assert_eq!(r2.status(), 409);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "double-spend must not reach the host");
    }

    #[tokio::test]
    async fn garbage_token_rejected_before_forward() {
        let (pk, _) = real_token();
        let key_id = *blake3::hash(&pk.0).as_bytes();
        let hits = Arc::new(AtomicU64::new(0));
        let host_url = mock_host(hits.clone()).await;
        let spent = Arc::new(RedbSpentSet::new(Store::open(&tmp()).unwrap(), 1));
        let broker = spawn(router(BrokerState::new(pk, spent, dir(host_url)))).await;
        let garbage = Token(vec![0u8; 320]);
        let r = reqwest::Client::new()
            .post(format!("{broker}/v1/exec"))
            .header("content-type", "application/json")
            .body(exec_body(key_id, &garbage))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 422);
        assert_eq!(hits.load(Ordering::SeqCst), 0, "invalid token must not reach the host");
    }
}
