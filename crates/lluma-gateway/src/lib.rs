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

/// Anchored SSRF allowlist check. The path must be absolute, free of
/// query/fragment, and contain no empty/`.`/`..` segments (defeating traversal
/// bypasses like `/v1/issue/../admin/grant`); it must then either equal an
/// allowlisted prefix exactly or extend it at a `/` segment boundary (so
/// `/v1/issuex` does NOT match `/v1/issue`).
fn path_allowed(path: &str, prefixes: &[String]) -> bool {
    // Reject anything the SENT-url normalizer (WHATWG / the `url` crate that
    // reqwest uses) would re-interpret AFTER this check: percent-encoding
    // (`%2e%2e` → `..`) and backslashes (rewritten to `/`), plus query/fragment
    // and non-absolute paths. `path_allowed` validates the BHTTP-decoded bytes,
    // but reqwest re-parses the `format!`-built URL — so the two must be forced
    // to agree by refusing any byte that normalization would rewrite.
    if !path.starts_with('/')
        || path.contains(['?', '#', '%', '\\'])
        || path.bytes().any(|b| b < 0x21)
    {
        // `< 0x21` rejects SPACE and all control bytes — notably ASCII tab
        // (0x09) and LF/CR (0x0a/0x0d), which the WHATWG URL parser strips
        // before dot-segment removal (a `.\t.` segment would become `..`).
        return false;
    }
    // Reject empty (`//`), `.`, and `..` segments (literal traversal).
    if path[1..]
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return false;
    }
    prefixes.iter().any(|p| {
        if p.ends_with('/') {
            // A trailing-slash prefix ("/v1/") matches everything beneath it
            // (the slash is the boundary).
            path.starts_with(p.as_str())
        } else {
            path == p.as_str()
                || path
                    .strip_prefix(p.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        }
    })
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

    // 3. SSRF guard: fixed method set + anchored path allowlist. The path MUST
    //    be absolute and contain no traversal (`.`/`..`) or empty segments — a
    //    bare `starts_with` prefix check is unsafe (`/v1/issue/../admin/grant`
    //    prefix-matches `/v1/issue` yet normalizes to `/v1/admin/grant`
    //    upstream). Allowlist match requires an exact hit or a `/` segment
    //    boundary; query/fragment-bearing paths are rejected (our endpoints use
    //    none). Authority is never taken from the inner request — the URL is
    //    built from the CONFIGURED origin.
    if method != "GET" && method != "POST" {
        return Err(GatewayError::Forbidden);
    }
    if !path_allowed(&path, &st.prefixes) {
        return Err(GatewayError::Forbidden);
    }

    let content_type = msg.header().get(b"content-type").map(|v| v.to_vec());
    let inner_body = msg.content().to_vec();

    // 4. Forward to the origin (authority overwritten with origin_url). Re-parse
    //    the URL and re-run the allowlist on the NORMALIZED path: reqwest's `url`
    //    crate strips tab/LF/CR and collapses dot segments, so the bytes it
    //    actually sends differ from the raw decoded path. Validating the parsed
    //    path closes the entire normalization-mismatch class (Fable C1), not
    //    just specific byte vectors.
    let url = format!("{}{}", st.origin_url, path);
    let parsed = reqwest::Url::parse(&url).map_err(|_| GatewayError::Forbidden)?;
    if !path_allowed(parsed.path(), &st.prefixes) {
        return Err(GatewayError::Forbidden);
    }
    let mut rb = if method == "GET" {
        st.http.get(parsed)
    } else {
        st.http.post(parsed).body(inner_body)
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

#[cfg(test)]
mod tests {
    use super::path_allowed;

    fn prefixes() -> Vec<String> {
        vec!["/v1/issue".into(), "/v1/redeem".into(), "/v1/key-config".into()]
    }

    #[test]
    fn allows_exact_endpoints() {
        let p = prefixes();
        assert!(path_allowed("/v1/issue", &p));
        assert!(path_allowed("/v1/redeem", &p));
        assert!(path_allowed("/v1/key-config", &p));
    }

    #[test]
    fn blocks_disallowed_sibling() {
        assert!(!path_allowed("/v1/admin/grant", &prefixes()));
    }

    #[test]
    fn blocks_traversal_bypass() {
        // The finding: prefix-matches "/v1/issue" but normalizes to admin/grant.
        assert!(!path_allowed("/v1/issue/../admin/grant", &prefixes()));
        assert!(!path_allowed("/v1/issue/..", &prefixes()));
        assert!(!path_allowed("/v1/./issue", &prefixes()));
    }

    #[test]
    fn blocks_percent_encoded_and_backslash_traversal() {
        // Fable review C1: the url crate normalizes these AFTER path_allowed, so
        // any '%' or '\' must be refused outright.
        let p = prefixes();
        assert!(!path_allowed("/v1/issue/%2e%2e/admin/grant", &p));
        assert!(!path_allowed("/v1/issue/%2E%2E/admin/grant", &p));
        assert!(!path_allowed("/v1/issue/.%2e/admin", &p));
        assert!(!path_allowed("/v1/issue/\\../admin/grant", &p));
        assert!(!path_allowed("/v1/issue%2f..", &p));
    }

    #[test]
    fn blocks_control_char_traversal() {
        // WHATWG URL parsing strips tab/LF/CR before dot-segment removal, so a
        // `.\t.` segment would normalize to `..`. Control bytes must be refused.
        let p = prefixes();
        assert!(!path_allowed("/v1/issue/.\t./admin/grant", &p));
        assert!(!path_allowed("/v1/issue/.\n./admin/grant", &p));
        assert!(!path_allowed("/v1/issue/.\r./admin/grant", &p));
        assert!(!path_allowed("/v1/issue /x", &p));
    }

    #[test]
    fn trailing_slash_prefix_matches_beneath() {
        let p = vec!["/v1/".to_string()];
        assert!(path_allowed("/v1/issue", &p));
        assert!(path_allowed("/v1/anything", &p));
        assert!(!path_allowed("/v2/issue", &p));
    }

    #[test]
    fn blocks_suffix_bypass() {
        // "/v1/issuex" must not match the "/v1/issue" prefix (needs a boundary).
        assert!(!path_allowed("/v1/issuex", &prefixes()));
        assert!(!path_allowed("/v1/issue-evil", &prefixes()));
    }

    #[test]
    fn blocks_query_fragment_empty_and_relative() {
        let p = prefixes();
        assert!(!path_allowed("/v1/issue?x=1", &p));
        assert!(!path_allowed("/v1/issue#frag", &p));
        assert!(!path_allowed("/v1//issue", &p));
        assert!(!path_allowed("v1/issue", &p));
        assert!(!path_allowed("/etc/passwd", &p));
    }

    #[test]
    fn allows_subpath_at_boundary() {
        // Sub-paths under an allowed prefix are permitted (they simply 404 at the
        // origin); the security property is that disallowed siblings are blocked.
        assert!(path_allowed("/v1/issue/batch", &prefixes()));
    }
}
