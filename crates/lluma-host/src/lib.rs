//! `lluma-host` — the serving host (Phase 1 #5 slice, ADR-0003).
//!
//! Receives `{spend_id, sealed}` from the broker, opens the HPKE seal with its
//! host key (**aad = spend_id** — the #1 AAD contract binds the token to this
//! exact ciphertext; any mismatch fails closed), runs the prompt through an
//! `Upstream` (echo stub for the slice; a real LLM adapter is a thin swap), and
//! seals the response to the client's session key. The host sees the prompt
//! plaintext but NEVER the originator IP (its only inbound peer is the broker)
//! and the response is E2E-sealed so no relay/gateway/broker can read it.

pub mod openai;
pub mod tunnel;
pub use openai::OpenAiUpstream;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

use lluma_core::proto::v1::{ExecResponse, HostExecRequest};
use lluma_core::wire::{HostSecretKey, SealedRequest, SpendId};

/// An upstream failure. Opaque (L8) — never carries prompt bytes or a provider
/// `Display` to the wire.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("upstream unavailable")]
    Transport,
    #[error("upstream status")]
    Status,
    #[error("upstream decode")]
    Decode,
    #[error("bad prompt encoding")]
    BadPrompt,
    #[error("encode error")]
    Encode,
}

/// The upstream model. One method so a real OpenAI-compatible adapter is a thin
/// swap for `EchoUpstream`. Fallible — a real model call can time out or error,
/// and the host must return a proper 502 rather than seal a fake "answer".
/// Boxed future → object-safe (`Arc<dyn Upstream>`).
pub trait Upstream: Send + Sync {
    fn complete<'a>(
        &'a self,
        prompt: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, UpstreamError>> + Send + 'a>>;
}

/// Echo stub: returns `sentinel ‖ prompt`. Proves the routing/crypto invariant
/// without a real model (ADR-0003).
pub struct EchoUpstream {
    pub sentinel: Vec<u8>,
}

impl Upstream for EchoUpstream {
    fn complete<'a>(
        &'a self,
        prompt: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, UpstreamError>> + Send + 'a>> {
        let mut out = self.sentinel.clone();
        out.extend_from_slice(prompt);
        Box::pin(async move { Ok(out) })
    }
}

#[derive(Clone)]
pub struct HostState {
    pub host_sk: Arc<HostSecretKey>,
    pub upstream: Arc<dyn Upstream>,
}

pub fn router(state: HostState) -> Router {
    Router::new().route("/v1/exec", post(exec)).with_state(state)
}

fn err(status: StatusCode, code: &'static str) -> Response {
    (status, Json(serde_json::json!({ "code": code, "message": code }))).into_response()
}

/// A serving failure, mapped to a status by the HTTP handler and to a `Fail`
/// frame by the tunnel. Opaque — carries no prompt bytes or provider detail.
#[derive(Debug, Clone, Copy)]
pub enum ServeError {
    /// The seal did not open (aad/spend_id mismatch or tamper) — the upstream
    /// was NOT called. Fails closed.
    Seal,
    /// The upstream model call failed — never seal a fabricated answer.
    Upstream,
    /// A local sealing/setup error after a valid open.
    Internal,
}

/// The core serving-crypto path, shared by the dial-in HTTP handler and the
/// reverse tunnel: open the sealed request with `host_sk` (aad = `spend_id` —
/// the #1 AAD contract), run the prompt through `upstream`, and seal the answer
/// to the client's session key as a single final chunk. The host sees the
/// prompt plaintext but never the originator IP; the response is E2E-sealed.
pub async fn serve_sealed(
    host_sk: &HostSecretKey,
    spend_id: &SpendId,
    sealed: &SealedRequest,
    upstream: &dyn Upstream,
) -> Result<ExecResponse, ServeError> {
    // Open — fails closed on any aad/spend_id mismatch or tamper.
    let (prompt, reply_to) = lluma_crypto::e2e::e2e_open(host_sk, &spend_id.0, sealed)
        .map_err(|_| ServeError::Seal)?;
    let answer = upstream.complete(&prompt).await.map_err(|_| ServeError::Upstream)?;
    // Seal the response to the client's session key (single final chunk).
    let mut rng = rand_core::OsRng;
    let (mut hctx, preamble) =
        lluma_crypto::e2e::response_setup_host(&mut rng, &reply_to).map_err(|_| ServeError::Internal)?;
    let chunk = lluma_crypto::e2e::response_seal_chunk(&mut hctx, &answer, true)
        .map_err(|_| ServeError::Internal)?;
    Ok(ExecResponse { preamble, chunk })
}

async fn exec(State(st): State<HostState>, body: Bytes) -> Response {
    let req: HostExecRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "bad_request"),
    };
    if req.validate().is_err() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "bad_request");
    }
    match serve_sealed(&st.host_sk, &req.spend_id, &req.sealed, st.upstream.as_ref()).await {
        Ok(resp) => match serde_json::to_vec(&resp) {
            Ok(body) => {
                (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], body).into_response()
            }
            Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        },
        Err(ServeError::Seal) => err(StatusCode::UNPROCESSABLE_ENTITY, "seal_invalid"),
        Err(ServeError::Upstream) => err(StatusCode::BAD_GATEWAY, "upstream"),
        Err(ServeError::Internal) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lluma_core::wire::{SealedRequest, SpendId};

    async fn spawn(app: Router) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn seal_open_echo_roundtrip() {
        let mut rng = rand_core::OsRng;
        let (host_sk, host_pk) = lluma_crypto::e2e::host_keygen(&mut rng).unwrap();
        let (sess_sk, sess_pk) = lluma_crypto::e2e::session_keygen(&mut rng).unwrap();
        let spend_id = SpendId([5u8; 32]);
        let prompt = b"what is the capital of france?";
        let sealed =
            lluma_crypto::e2e::e2e_seal(&mut rng, &host_pk, &spend_id.0, prompt, &sess_pk).unwrap();

        let state = HostState {
            host_sk: Arc::new(host_sk),
            upstream: Arc::new(EchoUpstream { sentinel: b"ANSWER:".to_vec() }),
        };
        let url = spawn(router(state)).await;
        let body = serde_json::to_vec(&HostExecRequest { spend_id, sealed }).unwrap();
        let resp = reqwest::Client::new()
            .post(format!("{url}/v1/exec"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let er: ExecResponse = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();

        let mut cctx = lluma_crypto::e2e::response_setup_client(&sess_sk, &er.preamble).unwrap();
        let (answer, is_final) =
            lluma_crypto::e2e::response_open_chunk(&mut cctx, &er.chunk).unwrap();
        assert!(is_final);
        assert_eq!(answer, b"ANSWER:what is the capital of france?".to_vec());
    }

    #[tokio::test]
    async fn aad_mismatch_fails_closed_no_upstream() {
        let mut rng = rand_core::OsRng;
        let (host_sk, host_pk) = lluma_crypto::e2e::host_keygen(&mut rng).unwrap();
        let (_sess_sk, sess_pk) = lluma_crypto::e2e::session_keygen(&mut rng).unwrap();
        // Seal with aad = A, but the request will carry spend_id = B.
        let sealed =
            lluma_crypto::e2e::e2e_seal(&mut rng, &host_pk, &[1u8; 32], b"hi", &sess_pk).unwrap();
        let state = HostState {
            host_sk: Arc::new(host_sk),
            upstream: Arc::new(EchoUpstream { sentinel: b"X".to_vec() }),
        };
        let url = spawn(router(state)).await;
        let body = serde_json::to_vec(&HostExecRequest {
            spend_id: SpendId([2u8; 32]),
            sealed: SealedRequest(sealed.0),
        })
        .unwrap();
        let resp = reqwest::Client::new()
            .post(format!("{url}/v1/exec"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 422, "aad mismatch must fail closed");
    }
}
