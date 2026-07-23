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

use lluma_core::proto::v1::{
    ExecRequest, ExecResponse, IssueRequest, IssueResponse, KeyConfigResponse, SignedBootstrap,
    SnapshotResponse,
};
use lluma_core::wire::{
    AccountPublicKey, AccountSecretKey, BootstrapDoc, HostPublicKey, IssueRequestBody,
    OhttpKeyConfig, ReceiptSignature, SnapshotBody, SnapshotHostEntry, Token,
};
use lluma_net::{InnerRequest, OhttpAgent};

/// Verify a signed bootstrap against the pinned registry public key and decode
/// it. Pure + fail-closed — reused by [`fetch_bootstrap`] and unit-testable
/// without a network. A malicious relay cannot forge this: the signature is
/// checked against the app's compiled-in registry key before any field is read.
pub fn verify_bootstrap(
    registry_pk: &AccountPublicKey,
    sb: &SignedBootstrap,
) -> Result<BootstrapDoc, ClientError> {
    let sig = ReceiptSignature(sb.sig.clone());
    lluma_crypto::account::bootstrap_verify(registry_pk, &sb.doc, &sig)
        .map_err(|_| ClientError::Crypto)?;
    let doc: BootstrapDoc = postcard::from_bytes(&sb.doc).map_err(|_| ClientError::Protocol)?;
    // Fail-closed content validation (defense in depth; the signature already
    // authenticates these, but reject shapes we will not consume).
    if doc.version != 1 || doc.gateway_kc.is_empty() || !doc.relay_url.starts_with("https://") {
        return Err(ClientError::Protocol);
    }
    // A tunnel endpoint, if offered, MUST be a clean wss:// URL — plain ws is
    // hijackable after the auth handshake (crypto-architect must-have 1). Parse
    // strictly (scheme, host, no userinfo) to close the URL-confusion class,
    // rather than a prefix check.
    if let Some(url) = &doc.tunnel_url {
        let u = reqwest::Url::parse(url).map_err(|_| ClientError::Protocol)?;
        if u.scheme() != "wss"
            || u.host_str().is_none_or(|h| h.is_empty())
            || !u.username().is_empty()
            || u.password().is_some()
        {
            return Err(ClientError::Protocol);
        }
    }
    // Sanity-bound the published host-registration difficulty so a mis-signed
    // absurd value can't make a would-be host grind PoW forever (a real policy
    // is ~20 bits; the broker rejects a too-low PoW regardless).
    if let Some(d) = doc.pow_difficulty {
        if d > 30 {
            return Err(ClientError::Protocol);
        }
    }
    Ok(doc)
}

/// Fetch + verify the signed bootstrap from a relay over plain HTTPS (this runs
/// BEFORE OHTTP is configured — it is safe precisely because the payload is
/// signature-verified against the pinned registry key). Returns the verified
/// network coordinates the app self-configures from.
pub async fn fetch_bootstrap(
    relay_url: &str,
    registry_pk: &AccountPublicKey,
) -> Result<BootstrapDoc, ClientError> {
    let url = format!("{}/v1/bootstrap", relay_url.trim_end_matches('/'));
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| ClientError::Transport)?;
    let resp = http.get(&url).send().await.map_err(|_| ClientError::Transport)?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Err(ClientError::Server(status));
    }
    let bytes = resp.bytes().await.map_err(|_| ClientError::Transport)?;
    let sb: SignedBootstrap =
        serde_json::from_slice(&bytes).map_err(|_| ClientError::Protocol)?;
    verify_bootstrap(registry_pk, &sb)
}

/// Fixed snapshot bucket size (64 KiB) and length-prefix width — must match the
/// broker's `snapshot` module exactly.
const SNAPSHOT_BUCKET: usize = 65_536;
const SNAPSHOT_LEN_PREFIX: usize = 4;

/// Verify a signed registry snapshot and decode its body. Fails closed on any
/// size / signature / length / decode mismatch. Pure (no network) so it is unit
/// testable and reused by [`Client::snapshot`].
pub fn verify_snapshot(
    registry_pk: &AccountPublicKey,
    sr: &SnapshotResponse,
) -> Result<SnapshotBody, ClientError> {
    if sr.body.len() != SNAPSHOT_BUCKET {
        return Err(ClientError::Protocol);
    }
    let sig = ReceiptSignature(sr.sig.clone());
    lluma_crypto::account::snapshot_verify(registry_pk, &sr.body, &sig)
        .map_err(|_| ClientError::Crypto)?;
    let len = u32::from_le_bytes([sr.body[0], sr.body[1], sr.body[2], sr.body[3]]) as usize;
    let end = SNAPSHOT_LEN_PREFIX
        .checked_add(len)
        .filter(|e| *e <= sr.body.len())
        .ok_or(ClientError::Protocol)?;
    postcard::from_bytes(&sr.body[SNAPSHOT_LEN_PREFIX..end]).map_err(|_| ClientError::Protocol)
}

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
    /// The selected host's Ed25519 account/pubkey (routing metadata for the
    /// broker to resolve + bind the spend to). In the full model this comes from
    /// the signed snapshot entry alongside `host_pk` (its HPKE key).
    host_account: [u8; 32],
    /// Pinned issuer `key_id` from the verified bootstrap. When set, `key_config`
    /// requires the served `key_id` to match — otherwise a misbehaving
    /// gateway/broker could serve a per-client issuer key to tag/link tokens.
    expected_issuer_key_id: Option<[u8; 32]>,
}

impl Client {
    pub fn new(
        relay_url: impl Into<String>,
        gateway_key_config: OhttpKeyConfig,
        sk: AccountSecretKey,
        pk: AccountPublicKey,
        host_pk: HostPublicKey,
        host_account: [u8; 32],
    ) -> Self {
        Self {
            agent: OhttpAgent::new(relay_url, gateway_key_config),
            sk,
            pk,
            host_pk,
            host_account,
            expected_issuer_key_id: None,
        }
    }

    /// Pin the expected issuer `key_id` (from the verified bootstrap doc). Any
    /// served key-config with a different `key_id` is rejected.
    pub fn with_expected_issuer_key_id(mut self, key_id: [u8; 32]) -> Self {
        self.expected_issuer_key_id = Some(key_id);
        self
    }

    /// Fetch and pin the issuer key-config (`key_id == BLAKE3(pubkey)`), and —
    /// if an expected `key_id` was pinned from the bootstrap — require it to
    /// match exactly.
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
        if let Some(expected) = self.expected_issuer_key_id {
            if kc.key_id != expected {
                return Err(ClientError::Protocol);
            }
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
        if ir.key_id != kc.key_id || ir.signatures.len() != states.len() {
            return Err(ClientError::Protocol);
        }
        let mut tokens = Vec::with_capacity(states.len());
        for (st, sig) in states.into_iter().zip(ir.signatures.iter()) {
            tokens.push(lluma_crypto::tokens::token_unblind(&kc.issuer_public_key, st, sig)?);
        }
        Ok(tokens)
    }

    /// Fetch + verify the signed host snapshot over the relay, returning the
    /// active hosts. The client selects a host locally (there is no live
    /// "pick me a host" query).
    pub async fn snapshot(
        &self,
        registry_pk: &AccountPublicKey,
    ) -> Result<Vec<SnapshotHostEntry>, ClientError> {
        let resp = self
            .agent
            .round_trip(InnerRequest {
                method: "GET".into(),
                path: "/v1/snapshot".into(),
                content_type: None,
                body: Vec::new(),
            })
            .await?;
        if resp.status != 200 {
            return Err(ClientError::Server(resp.status));
        }
        let sr: SnapshotResponse =
            serde_json::from_slice(&resp.body).map_err(|_| ClientError::Protocol)?;
        Ok(verify_snapshot(registry_pk, &sr)?.hosts)
    }

    /// Execute one anonymous inference against the host configured at
    /// construction. Retained for back-compat (`live_smoke`); delegates to
    /// [`Client::exec_with_host`].
    pub async fn exec(
        &self,
        kc: &KeyConfigResponse,
        token: Token,
        prompt: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let host = SnapshotHostEntry {
            host_account: self.host_account,
            hpke_pk: self.host_pk.0.clone(),
            models: vec![],
            tier_flags: 0,
            load_bucket: 0,
            freshness_bucket: 0,
        };
        self.exec_with_host(kc, token, &host, prompt).await
    }

    /// Execute one anonymous inference against a specific snapshot-selected
    /// host: seal `prompt` E2E to that host (aad = spend_id), spend the token
    /// via the broker, open the sealed response.
    pub async fn exec_with_host(
        &self,
        kc: &KeyConfigResponse,
        token: Token,
        host: &SnapshotHostEntry,
        prompt: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let host_pk = HostPublicKey(host.hpke_pk.clone());
        let spend_id = lluma_crypto::tokens::token_spend_id(&token);
        let mut rng = rand_core::OsRng;
        let (sess_sk, sess_pk) = lluma_crypto::e2e::session_keygen(&mut rng)?;
        let sealed =
            lluma_crypto::e2e::e2e_seal(&mut rng, &host_pk, &spend_id.0, prompt, &sess_pk)?;
        let req = ExecRequest {
            key_id: kc.key_id,
            host_account: host.host_account,
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
