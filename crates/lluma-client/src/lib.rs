//! `lluma-client` — the consumer client (Phase 1 #5 slice, ADR-0003).
//!
//! Composition over the existing pieces: an `OhttpAgent` (relay transport) plus
//! account keys. It fetches the issuer key-config (pinned), acquires blind
//! tokens over OHTTP, and executes anonymous inference — sealing the prompt E2E
//! to the host key with `aad = spend_id` (the #1 AAD contract) and requiring the
//! sealed response to be marked final. Everything the client sends leaves only
//! through the relay; nothing downstream of the blind-token redemption can be
//! joined back to the account.

use blind_rsa_signatures::reexports::rand::Rng;

use lluma_core::proto::v1::{ExecRequest, ExecResponse, IssueRequest, IssueResponse, KeyConfigResponse};
use lluma_core::wire::{
    AccountPublicKey, AccountSecretKey, HostPublicKey, IssueRequestBody, OhttpKeyConfig, Token,
};
use lluma_net::{InnerRequest, OhttpAgent};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("transport")]
    Transport,
    #[error("protocol")]
    Protocol,
    #[error("crypto")]
    Crypto,
    #[error("response not final")]
    NotFinal,
    #[error("server status {0}")]
    Server(u16),
}

impl From<lluma_net::NetError> for ClientError {
    fn from(_: lluma_net::NetError) -> Self {
        ClientError::Transport
    }
}
impl From<lluma_crypto::CryptoError> for ClientError {
    fn from(_: lluma_crypto::CryptoError) -> Self {
        ClientError::Crypto
    }
}

fn now_unix_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct Client {
    agent: OhttpAgent,
    sk: AccountSecretKey,
    pk: AccountPublicKey,
    host_pk: HostPublicKey,
}

impl Client {
    pub fn new(
        relay_url: impl Into<String>,
        gateway_key_config: OhttpKeyConfig,
        sk: AccountSecretKey,
        pk: AccountPublicKey,
        host_pk: HostPublicKey,
    ) -> Self {
        Self {
            agent: OhttpAgent::new(relay_url, gateway_key_config),
            sk,
            pk,
            host_pk,
        }
    }

    /// Fetch and pin the issuer key-config (`key_id == BLAKE3(pubkey)`).
    pub async fn key_config(&self) -> Result<KeyConfigResponse, ClientError> {
        let resp = self
            .agent
            .round_trip(InnerRequest {
                method: "GET".into(),
                path: "/v1/key-config".into(),
                content_type: None,
                body: Vec::new(),
            })
            .await?;
        if resp.status != 200 {
            return Err(ClientError::Server(resp.status));
        }
        let kc: KeyConfigResponse =
            serde_json::from_slice(&resp.body).map_err(|_| ClientError::Protocol)?;
        if *blake3::hash(&kc.issuer_public_key.0).as_bytes() != kc.key_id {
            return Err(ClientError::Protocol);
        }
        Ok(kc)
    }

    /// Acquire `count` blind tokens over OHTTP (issue is identity-bound at the
    /// issuer but rides the relay too, so even the issuer never sees the IP).
    pub async fn acquire(
        &self,
        kc: &KeyConfigResponse,
        count: usize,
    ) -> Result<Vec<Token>, ClientError> {
        let mut rng = blind_rsa_signatures::DefaultRng;
        let mut states = Vec::with_capacity(count);
        let mut blinded = Vec::with_capacity(count);
        for _ in 0..count {
            let (st, b) = lluma_crypto::tokens::token_blind(&mut rng, &kc.issuer_public_key)?;
            states.push(st);
            blinded.push(b);
        }
        let batch_hash = *blake3::hash(
            &postcard::to_stdvec(&blinded).map_err(|_| ClientError::Protocol)?,
        )
        .as_bytes();
        let mut request_id = [0u8; 32];
        rng.fill_bytes(&mut request_id);
        let account: [u8; 32] = self.pk.0.as_slice().try_into().map_err(|_| ClientError::Crypto)?;
        let body = IssueRequestBody {
            version: 1,
            account,
            key_id: kc.key_id,
            request_id,
            ts_unix_s: now_unix_s(),
            blinded_batch_hash: batch_hash,
        };
        let auth_sig = lluma_crypto::account::issue_request_sign(&self.sk, &body)?;
        let req = IssueRequest { body, blinded, auth_sig };
        let json = serde_json::to_vec(&req).map_err(|_| ClientError::Protocol)?;
        let resp = self
            .agent
            .round_trip(InnerRequest {
                method: "POST".into(),
                path: "/v1/issue".into(),
                content_type: Some("application/json".into()),
                body: json,
            })
            .await?;
        if resp.status != 200 {
            return Err(ClientError::Server(resp.status));
        }
        let ir: IssueResponse =
            serde_json::from_slice(&resp.body).map_err(|_| ClientError::Protocol)?;
        if ir.signatures.len() != states.len() {
            return Err(ClientError::Protocol);
        }
        let mut tokens = Vec::with_capacity(states.len());
        for (st, sig) in states.into_iter().zip(ir.signatures.iter()) {
            tokens.push(lluma_crypto::tokens::token_unblind(&kc.issuer_public_key, st, sig)?);
        }
        Ok(tokens)
    }

    /// Execute one anonymous inference: seal `prompt` E2E to the host (aad =
    /// spend_id), spend the token via the broker, open the sealed response.
    pub async fn exec(
        &self,
        kc: &KeyConfigResponse,
        token: Token,
        prompt: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let spend_id = lluma_crypto::tokens::token_spend_id(&token);
        let mut rng = rand_core::OsRng;
        let (sess_sk, sess_pk) = lluma_crypto::e2e::session_keygen(&mut rng)?;
        let sealed =
            lluma_crypto::e2e::e2e_seal(&mut rng, &self.host_pk, &spend_id.0, prompt, &sess_pk)?;
        let req = ExecRequest {
            key_id: kc.key_id,
            token,
            sealed,
        };
        let json = serde_json::to_vec(&req).map_err(|_| ClientError::Protocol)?;
        let resp = self
            .agent
            .round_trip(InnerRequest {
                method: "POST".into(),
                path: "/v1/exec".into(),
                content_type: Some("application/json".into()),
                body: json,
            })
            .await?;
        if resp.status != 200 {
            return Err(ClientError::Server(resp.status));
        }
        let er: ExecResponse =
            serde_json::from_slice(&resp.body).map_err(|_| ClientError::Protocol)?;
        let mut cctx = lluma_crypto::e2e::response_setup_client(&sess_sk, &er.preamble)?;
        let (answer, is_final) =
            lluma_crypto::e2e::response_open_chunk(&mut cctx, &er.chunk)?;
        if !is_final {
            return Err(ClientError::NotFinal);
        }
        Ok(answer)
    }
}
