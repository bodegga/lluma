//! `OhttpAgent` — the client round-trip: BHTTP-encode the inner request, OHTTP-
//! encapsulate it to the gateway key, POST it to the relay, then open the sealed
//! response and BHTTP-decode it. The relay sees only the capsule + our IP; the
//! gateway (which holds the HPKE secret) sees the inner request but never our IP.

use lluma_core::wire::OhttpKeyConfig;

use crate::error::NetError;
use crate::framing::{decode_response, encode_request, InnerRequest, InnerResponse};

/// A client bound to one relay URL and one gateway key-config.
pub struct OhttpAgent {
    relay_url: String,
    key_config: OhttpKeyConfig,
    http: reqwest::Client,
}

impl OhttpAgent {
    pub fn new(relay_url: impl Into<String>, key_config: OhttpKeyConfig) -> Self {
        Self {
            relay_url: relay_url.into(),
            key_config,
            http: reqwest::Client::new(),
        }
    }

    /// One oblivious round-trip. Fails closed (`NotFinal`) if the sealed response
    /// is not marked final — a dropped terminal chunk must never read as complete.
    pub async fn round_trip(&self, req: InnerRequest) -> Result<InnerResponse, NetError> {
        let inner = encode_request(&req)?;

        // OHTTP encapsulate. The ohttp/hpke path uses rand_core 0.6 OsRng (NOT
        // the blind-rsa DefaultRng used by the token path).
        let mut rng = rand_core::OsRng;
        let (capsule, mut client_ctx) =
            lluma_crypto::ohttp::ohttp_encapsulate(&mut rng, &self.key_config, &inner)
                .map_err(|_| NetError::Encapsulation)?;

        let resp = self
            .http
            .post(format!("{}/ohttp", self.relay_url))
            .header("content-type", "message/ohttp-req")
            .body(capsule.0)
            .send()
            .await
            .map_err(|_| NetError::Http)?;
        let status = resp.status();
        let body = resp.bytes().await.map_err(|_| NetError::Http)?.to_vec();
        if !status.is_success() {
            return Err(NetError::Relay(status.as_u16()));
        }

        let (plaintext, is_final) = lluma_crypto::ohttp::ohttp_open_chunk(&mut client_ctx, &body)?;
        if !is_final {
            return Err(NetError::NotFinal);
        }
        decode_response(&plaintext)
    }
}
