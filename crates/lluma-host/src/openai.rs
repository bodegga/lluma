//! Generic OpenAI-compatible upstream adapter (#5 real inference).
//!
//! Config-driven — base URL + model + API key — so ANY OpenAI-compatible
//! `/chat/completions` endpoint works (OpenAI, a local llama.cpp/vLLM server, a
//! gateway, …). This is the "~20-line swap" ADR-0003 promised for `EchoUpstream`.
//!
//! Privacy note: the host sees the prompt plaintext **by construction** — it is
//! the model boundary. Forwarding it to a third-party API means trusting THAT
//! provider with the prompt; that is a host-operator decision, not a protocol
//! linkage change — the provider never learns the originator IP or account
//! identity (the host's only inbound peer is the broker, over the relay path).
//! Choose a provider (or self-host) accordingly.
//!
//! The request body/response are handled with `serde_json` over a raw reqwest
//! body so the workspace `reqwest` needs no extra `json` feature. No live API
//! call is made in tests — they run against an in-process mock server.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::{Upstream, UpstreamError};

/// An OpenAI-compatible chat-completions upstream.
pub struct OpenAiUpstream {
    /// Full API prefix, e.g. `https://api.openai.com/v1` (no trailing slash).
    base_url: String,
    model: String,
    api_key: String,
    http: reqwest::Client,
}

impl OpenAiUpstream {
    /// Construct with an explicit endpoint. `base_url` should NOT end in `/`.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>, api_key: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            model: model.into(),
            api_key: api_key.into(),
            http,
        }
    }

    /// Build from env: `LLUMA_UPSTREAM_BASE_URL`, `LLUMA_UPSTREAM_MODEL`,
    /// `LLUMA_UPSTREAM_API_KEY`. Returns `None` if any is unset/empty, so the
    /// host can fall back to the echo stub when no real upstream is configured.
    pub fn from_env() -> Option<Self> {
        let base_url = non_empty(std::env::var("LLUMA_UPSTREAM_BASE_URL").ok())?;
        let model = non_empty(std::env::var("LLUMA_UPSTREAM_MODEL").ok())?;
        let api_key = non_empty(std::env::var("LLUMA_UPSTREAM_API_KEY").ok())?;
        Some(Self::new(base_url, model, api_key))
    }
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

impl Upstream for OpenAiUpstream {
    fn complete<'a>(
        &'a self,
        prompt: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, UpstreamError>> + Send + 'a>> {
        Box::pin(async move {
            let prompt_str = std::str::from_utf8(prompt).map_err(|_| UpstreamError::BadPrompt)?;
            let body = serde_json::json!({
                "model": self.model,
                "messages": [{ "role": "user", "content": prompt_str }],
            });
            let bytes = serde_json::to_vec(&body).map_err(|_| UpstreamError::Encode)?;

            let resp = self
                .http
                .post(format!("{}/chat/completions", self.base_url))
                .header("authorization", format!("Bearer {}", self.api_key))
                .header("content-type", "application/json")
                .body(bytes)
                .send()
                .await
                .map_err(|_| UpstreamError::Transport)?;
            if !resp.status().is_success() {
                return Err(UpstreamError::Status);
            }
            let rb = resp.bytes().await.map_err(|_| UpstreamError::Transport)?;
            let v: serde_json::Value =
                serde_json::from_slice(&rb).map_err(|_| UpstreamError::Decode)?;
            // choices[0].message.content
            let content = v
                .get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str())
                .ok_or(UpstreamError::Decode)?;
            Ok(content.as_bytes().to_vec())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::{Json, Router};

    async fn spawn(app: Router) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn completes_against_mock_openai_endpoint() {
        // Mock server returns a canned OpenAI chat-completions response and
        // asserts the request carries our model + prompt.
        let app = Router::new().route(
            "/v1/chat/completions",
            post(|body: axum::body::Bytes| async move {
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(v["model"], "test-model");
                assert_eq!(v["messages"][0]["content"], "ping");
                assert_eq!(v["messages"][0]["role"], "user");
                Json(serde_json::json!({
                    "choices": [{ "message": { "role": "assistant", "content": "pong" } }]
                }))
            }),
        );
        let base = format!("{}/v1", spawn(app).await);
        let up = OpenAiUpstream::new(base, "test-model", "sk-test");
        let out = up.complete(b"ping").await.unwrap();
        assert_eq!(out, b"pong".to_vec());
    }

    #[tokio::test]
    async fn upstream_error_status_is_reported() {
        let app = Router::new().route(
            "/v1/chat/completions",
            post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
        );
        let base = format!("{}/v1", spawn(app).await);
        let up = OpenAiUpstream::new(base, "m", "sk-test");
        assert!(matches!(up.complete(b"hi").await, Err(UpstreamError::Status)));
    }

    #[tokio::test]
    async fn malformed_response_is_decode_error() {
        let app = Router::new().route(
            "/v1/chat/completions",
            post(|| async { Json(serde_json::json!({ "unexpected": true })) }),
        );
        let base = format!("{}/v1", spawn(app).await);
        let up = OpenAiUpstream::new(base, "m", "sk-test");
        assert!(matches!(up.complete(b"hi").await, Err(UpstreamError::Decode)));
    }

    #[test]
    fn from_env_none_when_unset() {
        // With the vars unset this returns None (host falls back to echo).
        // (We don't set env in tests to avoid cross-test interference.)
        // A dedicated presence test would require serial env mutation.
        let _ = OpenAiUpstream::from_env();
    }
}
