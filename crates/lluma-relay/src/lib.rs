//! `lluma-relay` — the stateless OHTTP relay (Phase 1 #3).
//!
//! It is the ONLY party that sees the client's IP, and it holds no secrets. It
//! rate-limits per source IP, caps body size, and forwards the opaque OHTTP
//! capsule to a configured gateway — copying only `content-type`, stripping every
//! other inbound header and adding none (no `X-Forwarded-For`/`Via`/`Forwarded`;
//! Fable R5), over a single shared upstream client so the gateway can't partition
//! traffic by connection. It never logs bodies (leak L8).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

/// Per-IP token-bucket parameters.
#[derive(Clone)]
pub struct RateLimitConfig {
    pub capacity: u32,
    pub refill_per_sec: u32,
}

/// Relay configuration.
#[derive(Clone)]
pub struct RelayConfig {
    pub gateway_url: String,
    pub max_body_bytes: usize,
    pub per_ip: RateLimitConfig,
    /// Reserved duress proof-of-work difficulty. Only `0` (off) is implemented;
    /// when enabled it MUST be a single global value (never per-client — L12).
    pub pow_difficulty: u8,
    /// A signed bootstrap blob to mirror verbatim at `GET /v1/bootstrap` (the
    /// relay mirrors, never authors).
    pub bootstrap_blob: Option<Vec<u8>>,
}

/// Uniform, detail-free relay errors (a distinctive error echo is a tagging
/// channel — Fable R5).
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("rate limited")]
    RateLimited,
    #[error("bad content type")]
    BadContentType,
    #[error("upstream unavailable")]
    UpstreamUnavailable,
}

impl RelayError {
    fn status(&self) -> StatusCode {
        match self {
            RelayError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            RelayError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            RelayError::BadContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RelayError::UpstreamUnavailable => StatusCode::BAD_GATEWAY,
        }
    }
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let status = self.status();
        if matches!(self, RelayError::RateLimited) {
            (status, [(header::RETRY_AFTER, "1")]).into_response()
        } else {
            status.into_response()
        }
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Clone)]
struct RelayState {
    gateway_url: Arc<String>,
    max_body_bytes: usize,
    per_ip: RateLimitConfig,
    buckets: Arc<Mutex<HashMap<IpAddr, Bucket>>>,
    bootstrap_blob: Arc<Option<Vec<u8>>>,
    http: reqwest::Client,
}

/// Build the relay router. Callers MUST serve it with
/// `.into_make_service_with_connect_info::<SocketAddr>()` so the per-IP limiter
/// can see the peer address.
pub fn router(cfg: RelayConfig) -> Router {
    let state = RelayState {
        gateway_url: Arc::new(cfg.gateway_url),
        max_body_bytes: cfg.max_body_bytes,
        per_ip: cfg.per_ip,
        buckets: Arc::new(Mutex::new(HashMap::new())),
        bootstrap_blob: Arc::new(cfg.bootstrap_blob),
        http: reqwest::Client::new(),
    };
    Router::new()
        .route("/ohttp", post(ohttp))
        .route("/v1/bootstrap", get(bootstrap))
        .with_state(state)
}

/// Consume one token for `ip`; refill by elapsed time up to capacity.
fn allow(state: &RelayState, ip: IpAddr) -> bool {
    let mut g = state.buckets.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let cap = state.per_ip.capacity as f64;
    let refill = state.per_ip.refill_per_sec as f64;
    let b = g.entry(ip).or_insert(Bucket { tokens: cap, last: now });
    let elapsed = now.duration_since(b.last).as_secs_f64();
    b.tokens = (b.tokens + elapsed * refill).min(cap);
    b.last = now;
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        true
    } else {
        false
    }
}

async fn ohttp(
    State(state): State<RelayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    if body.len() > state.max_body_bytes {
        return RelayError::PayloadTooLarge.into_response();
    }
    if !allow(&state, peer.ip()) {
        return RelayError::RateLimited.into_response();
    }
    // Forward verbatim; set ONLY content-type, strip everything else.
    let upstream = state
        .http
        .post(state.gateway_url.as_str())
        .header(header::CONTENT_TYPE, "message/ohttp-req")
        .body(body.to_vec())
        .send()
        .await;
    let resp = match upstream {
        Ok(r) => r,
        Err(_) => return RelayError::UpstreamUnavailable.into_response(),
    };
    let status = resp.status();
    let ct = resp.headers().get(header::CONTENT_TYPE).cloned();
    let bytes = match resp.bytes().await {
        Ok(b) => b.to_vec(),
        Err(_) => return RelayError::UpstreamUnavailable.into_response(),
    };
    let mut builder = Response::builder().status(status);
    match ct {
        Some(v) => builder = builder.header(header::CONTENT_TYPE, v),
        None => builder = builder.header(header::CONTENT_TYPE, "message/ohttp-res"),
    }
    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|_| RelayError::UpstreamUnavailable.into_response())
}

async fn bootstrap(State(state): State<RelayState>) -> Response {
    match state.bootstrap_blob.as_ref() {
        Some(bytes) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes.clone(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(cap: u32, refill: u32) -> RelayState {
        RelayState {
            gateway_url: Arc::new("http://127.0.0.1:1".to_string()),
            max_body_bytes: 1024,
            per_ip: RateLimitConfig { capacity: cap, refill_per_sec: refill },
            buckets: Arc::new(Mutex::new(HashMap::new())),
            bootstrap_blob: Arc::new(None),
            http: reqwest::Client::new(),
        }
    }

    #[test]
    fn bucket_denies_after_capacity_with_no_refill() {
        let st = state(2, 0);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(allow(&st, ip));
        assert!(allow(&st, ip));
        assert!(!allow(&st, ip), "3rd immediate request must be denied");
    }

    #[test]
    fn separate_ips_have_separate_buckets() {
        let st = state(1, 0);
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        let b: IpAddr = "2.2.2.2".parse().unwrap();
        assert!(allow(&st, a));
        assert!(!allow(&st, a));
        assert!(allow(&st, b), "a different IP has its own budget");
    }
}
