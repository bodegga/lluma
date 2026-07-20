//! `lluma-gateway` — the OHTTP gateway (Phase 1 #3).
//!
//! Holds the `GatewaySecretKey`, decapsulates the client capsule the relay
//! forwarded, decodes the inner BHTTP request, applies an **SSRF allowlist**
//! (fixed method set + path-prefix allowlist + authority ALWAYS overwritten with
//! the configured origin — a client-controlled URL must never steer the
//! gateway), forwards to the origin, then BHTTP-encodes and OHTTP-seals the
//! response. It never sees the originator IP (only the relay's), and errors are
//! uniform and detail-free (leak L8 / Fable R5).

use std::io::Cursor;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use bhttp::{Message, Mode};

use lluma_core::wire::{EncapsulatedRequest, GatewaySecretKey};

/// Public gateway configuration.
pub struct GatewayConfig {
    pub secret: GatewaySecretKey,
    pub origin_url: String,
    pub allowed_path_prefixes: Vec<String>,
}

#[derive(Clone)]
struct GwState {
    secret: Arc<GatewaySecretKey>,
    origin_url: Arc<String>,
    prefixes: Arc<Vec<String>>,
    http: reqwest::Client,
}

#[derive(Debug, thiserror::Error)]
enum GatewayError {
    #[error("decapsulate")]
    Decapsulate,
    #[error("bhttp")]
    Bhttp,
    #[error("bad request")]
    BadRequest,
    #[error("forbidden")]
    Forbidden,
    #[error("upstream")]
    Upstream,
    #[error("seal")]
    Seal,
}

/// Build the gateway router. Single route `POST /` taking `message/ohttp-req`
/// and returning `message/ohttp-res`.
pub fn router(cfg: GatewayConfig) -> Router {
    let state = GwState {
        secret: Arc::new(cfg.secret),
        origin_url: Arc::new(cfg.origin_url),
        prefixes: Arc::new(cfg.allowed_path_prefixes),
        http: reqwest::Client::new(),
    };
    Router::new().route("/", post(handle)).with_state(state)
}

async fn handle(State(st): State<GwState>, body: Bytes) -> Response {
    match process(&st, &body).await {
        Ok(sealed) => (
            [(header::CONTENT_TYPE, "message/ohttp-res")],
            sealed,
        )
            .into_response(),
        // Uniform, detail-free failure — never leak which stage failed (L8).
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

async fn process(st: &GwState, body: &Bytes) -> Result<Vec<u8>, GatewayError> {
    // 1. Decapsulate the client capsule (we hold the HPKE secret).
    let capsule = EncapsulatedRequest(body.to_vec());
    let (inner, mut resp_ctx) = lluma_crypto::ohttp::ohttp_decapsulate(&st.secret, &capsule)
        .map_err(|_| GatewayError::Decapsulate)?;

    // 2. Decode the inner BHTTP request.
    let mut cur = Cursor::new(&inner[..]);
    let msg = Message::read_bhttp(&mut cur).map_err(|_| GatewayError::Bhttp)?;
    let method = msg
        .control()
        .method()
        .and_then(|m| std::str::from_utf8(m).ok())
        .map(|m| m.to_ascii_uppercase())
        .ok_or(GatewayError::BadRequest)?;
    let path = msg
        .control()
        .path()
        .and_then(|p| std::str::from_utf8(p).ok())
        .map(|p| p.to_string())
        .ok_or(GatewayError::BadRequest)?;

    // 3. SSRF guard: fixed method set, path-prefix allowlist, authority ignored
    //    (we build the URL from the CONFIGURED origin, never the inner request).
    if method != "GET" && method != "POST" {
        return Err(GatewayError::Forbidden);
    }
    if !st.prefixes.iter().any(|p| path.starts_with(p.as_str())) {
        return Err(GatewayError::Forbidden);
    }

    let content_type = msg.header().get(b"content-type").map(|v| v.to_vec());
    let inner_body = msg.content().to_vec();

    // 4. Forward to the origin (authority overwritten with origin_url).
    let url = format!("{}{}", st.origin_url, path);
    let mut rb = if method == "GET" {
        st.http.get(&url)
    } else {
        st.http.post(&url).body(inner_body)
    };
    if let Some(ct) = &content_type {
        rb = rb.header(header::CONTENT_TYPE, ct.clone());
    }
    let origin_resp = rb.send().await.map_err(|_| GatewayError::Upstream)?;
    let status = origin_resp.status().as_u16();
    let resp_body = origin_resp
        .bytes()
        .await
        .map_err(|_| GatewayError::Upstream)?
        .to_vec();

    // 5. BHTTP-encode the origin response and OHTTP-seal it (single final chunk).
    let mut out = Message::response(
        bhttp::StatusCode::try_from(status).map_err(|_| GatewayError::Bhttp)?,
    );
    out.write_content(&resp_body);
    let mut resp_bhttp = Vec::new();
    out.write_bhttp(Mode::KnownLength, &mut resp_bhttp)
        .map_err(|_| GatewayError::Bhttp)?;

    lluma_crypto::ohttp::ohttp_seal_chunk(&mut resp_ctx, &resp_bhttp, true)
        .map_err(|_| GatewayError::Seal)
}
