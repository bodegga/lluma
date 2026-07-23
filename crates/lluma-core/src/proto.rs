//! `proto::v1` — the JSON wire DTOs for the issuer HTTP API (Tasks 2+).
//!
//! All byte-vector newtypes (`Token`, `BlindedTokenRequest`, `BlindSignature`,
//! `IssueSignature`, `IssuerPublicKey`) serialize as **base64 strings** over
//! JSON via per-field `#[serde(with)]` helper modules. Fixed `[u8; 32]` arrays
//! serialize as serde's default integer arrays. Each request/response DTO
//! exposes `validate()` enforcing EXACT byte lengths (fail closed) — callers
//! must run it on every ingress DTO before touching the crypto layer.

pub mod v1 {
    use crate::wire::{
        AccountId, BlindSignature, BlindedTokenRequest, HeartbeatBody, HostRegisterBody,
        IssueRequestBody, IssueSignature, IssuerPublicKey, ResponsePreamble, SealedRequest,
        SpendId, Token, TrialRegisterBody, UsageReceiptBody,
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Serialize};

    /// Maximum number of blinded requests in a single `/issue` batch.
    pub const ISSUE_BATCH_MAX: usize = 64;

    /// Single hard-coded denomination (leak L6 — never parameterized on the wire).
    pub const DENOMINATION: u64 = 1;

    // ---- base64 serde helpers for the variable-length byte-vector newtypes ----

    mod b64_token {
        use super::{Engine, Token, STANDARD};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(x: &Token, s: S) -> Result<S::Ok, S::Error> {
            STANDARD.encode(&x.0).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Token, D::Error> {
            let st: String = Deserialize::deserialize(d)?;
            let bytes = STANDARD.decode(st).map_err(serde::de::Error::custom)?;
            Ok(Token(bytes))
        }
    }

    mod b64_blinded {
        use super::{BlindedTokenRequest, Engine, STANDARD};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(
            xs: &[BlindedTokenRequest],
            s: S,
        ) -> Result<S::Ok, S::Error> {
            let enc: Vec<String> = xs.iter().map(|x| STANDARD.encode(&x.0)).collect();
            enc.serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Vec<BlindedTokenRequest>, D::Error> {
            let strs: Vec<String> = Deserialize::deserialize(d)?;
            strs.into_iter()
                .map(|st| {
                    STANDARD
                        .decode(st)
                        .map_err(serde::de::Error::custom)
                        .map(BlindedTokenRequest)
                })
                .collect()
        }
    }

    mod b64_sig {
        use super::{BlindSignature, Engine, STANDARD};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(xs: &[BlindSignature], s: S) -> Result<S::Ok, S::Error> {
            let enc: Vec<String> = xs.iter().map(|x| STANDARD.encode(&x.0)).collect();
            enc.serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Vec<BlindSignature>, D::Error> {
            let strs: Vec<String> = Deserialize::deserialize(d)?;
            strs.into_iter()
                .map(|st| {
                    STANDARD
                        .decode(st)
                        .map_err(serde::de::Error::custom)
                        .map(BlindSignature)
                })
                .collect()
        }
    }

    mod b64_auth_sig {
        use super::{Engine, IssueSignature, STANDARD};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(x: &IssueSignature, s: S) -> Result<S::Ok, S::Error> {
            STANDARD.encode(&x.0).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<IssueSignature, D::Error> {
            let st: String = Deserialize::deserialize(d)?;
            let bytes = STANDARD.decode(st).map_err(serde::de::Error::custom)?;
            Ok(IssueSignature(bytes))
        }
    }

    mod b64_issuer_pk {
        use super::{Engine, IssuerPublicKey, STANDARD};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(x: &IssuerPublicKey, s: S) -> Result<S::Ok, S::Error> {
            STANDARD.encode(&x.0).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<IssuerPublicKey, D::Error> {
            let st: String = Deserialize::deserialize(d)?;
            let bytes = STANDARD.decode(st).map_err(serde::de::Error::custom)?;
            Ok(IssuerPublicKey(bytes))
        }
    }

    mod b64_sealed {
        use super::{Engine, SealedRequest, STANDARD};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(x: &SealedRequest, s: S) -> Result<S::Ok, S::Error> {
            STANDARD.encode(&x.0).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SealedRequest, D::Error> {
            let st: String = Deserialize::deserialize(d)?;
            Ok(SealedRequest(
                STANDARD.decode(st).map_err(serde::de::Error::custom)?,
            ))
        }
    }

    mod b64_preamble {
        use super::{Engine, ResponsePreamble, STANDARD};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(x: &ResponsePreamble, s: S) -> Result<S::Ok, S::Error> {
            STANDARD.encode(&x.0).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ResponsePreamble, D::Error> {
            let st: String = Deserialize::deserialize(d)?;
            Ok(ResponsePreamble(
                STANDARD.decode(st).map_err(serde::de::Error::custom)?,
            ))
        }
    }

    mod b64_vec {
        use super::{Engine, STANDARD};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(x: &[u8], s: S) -> Result<S::Ok, S::Error> {
            STANDARD.encode(x).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            let st: String = Deserialize::deserialize(d)?;
            STANDARD.decode(st).map_err(serde::de::Error::custom)
        }
    }

    /// DTO-level error. Length/shape failures only — never carries wire bytes.
    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum ProtoError {
        #[error("field {0} has wrong length")]
        WrongLength(&'static str),
        #[error("batch size out of range")]
        BatchSize,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KeyConfigResponse {
        pub key_id: [u8; 32],
        #[serde(with = "b64_issuer_pk")]
        pub issuer_public_key: IssuerPublicKey,
        pub epoch: u64,
        pub denomination: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct IssueRequest {
        pub body: IssueRequestBody,
        #[serde(with = "b64_blinded")]
        pub blinded: Vec<BlindedTokenRequest>,
        #[serde(with = "b64_auth_sig")]
        pub auth_sig: IssueSignature,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IssueResponse {
        pub key_id: [u8; 32],
        #[serde(with = "b64_sig")]
        pub signatures: Vec<BlindSignature>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RedeemRequest {
        pub key_id: [u8; 32],
        #[serde(with = "b64_token")]
        pub token: Token,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RedeemResponse {
        pub spend_id: SpendId,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct GrantRequest {
        pub account_id: AccountId,
        pub amount: u64,
    }

    /// `POST /v1/exec` — redeem a token and forward an E2E-sealed request. The
    /// broker verifies + spends the token, then forwards `{spend_id, sealed}` to
    /// the resolved host. `sealed` is the HPKE `SealedRequest` (aad = spend_id).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ExecRequest {
        pub key_id: [u8; 32],
        /// The client-selected serving host (its Ed25519 account/pubkey). Routing
        /// metadata only — the broker resolves this to a registered active host
        /// and records the `spend_id → host_account` binding. NOT part of the E2E
        /// seal's AAD (that is `spend_id`); a wrong host simply fails to open the seal.
        pub host_account: [u8; 32],
        #[serde(with = "b64_token")]
        pub token: Token,
        #[serde(with = "b64_sealed")]
        pub sealed: SealedRequest,
    }

    /// `POST /v1/exec` response — the host's OHTTP-style response (single final
    /// chunk): a `preamble` (session KEM encap) + one sealed `chunk`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ExecResponse {
        #[serde(with = "b64_preamble")]
        pub preamble: ResponsePreamble,
        #[serde(with = "b64_vec")]
        pub chunk: Vec<u8>,
    }

    /// Broker → host hop: the spent-and-verified `spend_id` plus the sealed
    /// request. Carries NO token, NO account — the host sees content, never
    /// identity or IP.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HostExecRequest {
        pub spend_id: SpendId,
        #[serde(with = "b64_sealed")]
        pub sealed: SealedRequest,
    }

    /// Upper bound on a sealed request / response chunk (defense against memory
    /// abuse; matches the relay's 1 MiB body cap). A real sealed prompt is far
    /// smaller. Enforced in `validate()` and by the tunnel/exec length caps.
    pub const MAX_SEALED_LEN: usize = 1 << 20;

    /// Reverse-tunnel frames (host ⇄ broker over an authenticated WebSocket).
    /// JSON, tagged, versioned. The broker length-caps each frame BEFORE parsing;
    /// `Job`/`Done` additionally bound `sealed`/`chunk` by `MAX_SEALED_LEN`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "t", rename_all = "snake_case")]
    pub enum TunnelFrame {
        /// host → broker: opens the handshake, naming the account to bind.
        Hello { v: u8, host_account: [u8; 32] },
        /// broker → host: single-use 32-byte random challenge.
        Challenge { v: u8, challenge: [u8; 32] },
        /// host → broker: Ed25519 sig over the domain-separated auth preimage.
        Auth {
            v: u8,
            #[serde(with = "b64_vec")]
            sig: Vec<u8>,
        },
        /// broker → host: handshake accepted; the socket is now bound.
        AuthOk { v: u8 },
        /// broker → host: a job to serve, correlated by `request_id`.
        Job {
            v: u8,
            request_id: u64,
            spend_id: SpendId,
            #[serde(with = "b64_sealed")]
            sealed: SealedRequest,
        },
        /// host → broker: the sealed response for `request_id`.
        Done {
            v: u8,
            request_id: u64,
            #[serde(with = "b64_preamble")]
            preamble: ResponsePreamble,
            #[serde(with = "b64_vec")]
            chunk: Vec<u8>,
        },
        /// host → broker: the host could not serve `request_id` (opaque).
        Fail { v: u8, request_id: u64 },
    }

    /// `POST /v1/host/register` — a host joins the registry. `sig` is the
    /// host's Ed25519 signature over the canonical `HostRegisterBody`;
    /// `pow_nonce` is the broker-issued 8-byte proof-of-work nonce.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HostRegisterRequest {
        pub body: HostRegisterBody,
        #[serde(with = "b64_vec")]
        pub sig: Vec<u8>,
        #[serde(with = "b64_vec")]
        pub pow_nonce: Vec<u8>,
    }

    /// `POST /v1/host/heartbeat` — periodic host liveness + load report.
    /// `sig` is the host's Ed25519 signature over the canonical `HeartbeatBody`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HeartbeatRequest {
        pub body: HeartbeatBody,
        #[serde(with = "b64_vec")]
        pub sig: Vec<u8>,
    }

    /// `POST /v1/trial/register` — anti-Sybil one-time trial registration;
    /// `pow_nonce` is the 8-byte proof-of-work nonce tying the registration to
    /// the consumer account.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TrialRegisterRequest {
        pub body: TrialRegisterBody,
        #[serde(with = "b64_vec")]
        pub pow_nonce: Vec<u8>,
    }

    /// `POST /v1/receipt/submit` — a host submits a signed usage receipt for
    /// ledger credit. `sig` is the host's Ed25519 signature over the canonical
    /// `UsageReceiptBody`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReceiptSubmit {
        pub body: UsageReceiptBody,
        #[serde(with = "b64_vec")]
        pub sig: Vec<u8>,
    }

    /// `GET /v1/snapshot` response — the fixed-size (64 KiB) padded, signed
    /// registry snapshot. `body` is the postcard-encoded `SnapshotBody`
    /// (zero-padded to the 65536-byte bucket); `sig` is the registry key's
    /// Ed25519 signature over the EXACT bytes of `body`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SnapshotResponse {
        #[serde(with = "b64_vec")]
        pub body: Vec<u8>,
        #[serde(with = "b64_vec")]
        pub sig: Vec<u8>,
    }

    /// `GET /v1/bootstrap` response — the signed client bootstrap. `doc` is the
    /// postcard-encoded `BootstrapDoc`; `sig` is the registry key's Ed25519
    /// signature over the EXACT bytes of `doc` (domain `lluma-bootstrap-v1`).
    /// The relay mirrors this blob verbatim and never authors or signs it; the
    /// client verifies `sig` against its pinned (compiled-in) registry key
    /// before trusting any field.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SignedBootstrap {
        #[serde(with = "b64_vec")]
        pub doc: Vec<u8>,
        #[serde(with = "b64_vec")]
        pub sig: Vec<u8>,
    }

    impl HostExecRequest {
        pub fn validate(&self) -> Result<(), ProtoError> {
            if self.sealed.0.is_empty() || self.sealed.0.len() > MAX_SEALED_LEN {
                return Err(ProtoError::WrongLength("sealed"));
            }
            Ok(())
        }
    }

    impl ExecRequest {
        pub fn validate(&self) -> Result<(), ProtoError> {
            if self.token.0.len() != 320 {
                return Err(ProtoError::WrongLength("token"));
            }
            if self.sealed.0.is_empty() || self.sealed.0.len() > MAX_SEALED_LEN {
                return Err(ProtoError::WrongLength("sealed"));
            }
            Ok(())
        }
    }

    impl ExecResponse {
        pub fn validate(&self) -> Result<(), ProtoError> {
            if self.preamble.0.is_empty() || self.preamble.0.len() > MAX_SEALED_LEN {
                return Err(ProtoError::WrongLength("preamble"));
            }
            if self.chunk.is_empty() || self.chunk.len() > MAX_SEALED_LEN {
                return Err(ProtoError::WrongLength("chunk"));
            }
            Ok(())
        }
    }

    impl HostRegisterRequest {
        pub fn validate(&self) -> Result<(), ProtoError> {
            if self.body.version != 1 {
                return Err(ProtoError::WrongLength("version"));
            }
            if self.sig.len() != 64 {
                return Err(ProtoError::WrongLength("sig"));
            }
            if self.pow_nonce.len() != 8 {
                return Err(ProtoError::WrongLength("pow_nonce"));
            }
            if self.body.ingress_addr.is_empty() {
                return Err(ProtoError::WrongLength("ingress_addr"));
            }
            if self.body.hpke_pk.is_empty() {
                return Err(ProtoError::WrongLength("hpke_pk"));
            }
            Ok(())
        }
    }

    impl HeartbeatRequest {
        pub fn validate(&self) -> Result<(), ProtoError> {
            if self.body.version != 1 {
                return Err(ProtoError::WrongLength("version"));
            }
            if self.sig.len() != 64 {
                return Err(ProtoError::WrongLength("sig"));
            }
            Ok(())
        }
    }

    impl TrialRegisterRequest {
        pub fn validate(&self) -> Result<(), ProtoError> {
            if self.body.version != 1 {
                return Err(ProtoError::WrongLength("version"));
            }
            if self.pow_nonce.len() != 8 {
                return Err(ProtoError::WrongLength("pow_nonce"));
            }
            Ok(())
        }
    }

    impl ReceiptSubmit {
        pub fn validate(&self) -> Result<(), ProtoError> {
            if self.body.version != 1 {
                return Err(ProtoError::WrongLength("version"));
            }
            if self.sig.len() != 64 {
                return Err(ProtoError::WrongLength("sig"));
            }
            Ok(())
        }
    }

    impl SnapshotResponse {
        pub fn validate(&self) -> Result<(), ProtoError> {
            if self.sig.len() != 64 {
                return Err(ProtoError::WrongLength("sig"));
            }
            if self.body.len() != 65536 {
                return Err(ProtoError::WrongLength("body"));
            }
            Ok(())
        }
    }

    impl KeyConfigResponse {
        /// Nothing to validate at the DTO layer — `key_id` is type-enforced
        /// `[u8; 32]` and `issuer_public_key` is a variable-length RSA DER
        /// blob whose integrity is pinned by the client recomputing
        /// `BLAKE3(pubkey) == key_id` (a later task).
        pub fn validate(&self) -> Result<(), ProtoError> {
            Ok(())
        }
    }

    impl IssueRequest {
        pub fn validate(&self) -> Result<(), ProtoError> {
            if self.body.version != 1 {
                return Err(ProtoError::WrongLength("version"));
            }
            if self.blinded.is_empty() || self.blinded.len() > ISSUE_BATCH_MAX {
                return Err(ProtoError::BatchSize);
            }
            for b in &self.blinded {
                if b.0.len() != 256 {
                    return Err(ProtoError::WrongLength("blinded"));
                }
            }
            if self.auth_sig.0.len() != 64 {
                return Err(ProtoError::WrongLength("auth_sig"));
            }
            Ok(())
        }
    }

    impl IssueResponse {
        pub fn validate(&self) -> Result<(), ProtoError> {
            for s in &self.signatures {
                if s.0.len() != 256 {
                    return Err(ProtoError::WrongLength("signatures"));
                }
            }
            Ok(())
        }
    }

    impl RedeemRequest {
        pub fn validate(&self) -> Result<(), ProtoError> {
            if self.token.0.len() != 320 {
                return Err(ProtoError::WrongLength("token"));
            }
            Ok(())
        }
    }

    impl RedeemResponse {
        /// Nothing to validate — `spend_id` is type-enforced `[u8; 32]`.
        pub fn validate(&self) -> Result<(), ProtoError> {
            Ok(())
        }
    }

    impl GrantRequest {
        /// Nothing to validate — `account_id` is type-enforced `[u8; 32]`.
        pub fn validate(&self) -> Result<(), ProtoError> {
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn sample_body() -> IssueRequestBody {
            IssueRequestBody {
                version: 1,
                account: [7u8; 32],
                key_id: [9u8; 32],
                request_id: [11u8; 32],
                ts_unix_s: 1_700_000_000,
                blinded_batch_hash: [13u8; 32],
            }
        }

        fn sample_issue_request(batch: usize) -> IssueRequest {
            let blinded = (0..batch)
                .map(|_| BlindedTokenRequest(vec![0xABu8; 256]))
                .collect::<Vec<_>>();
            IssueRequest {
                body: sample_body(),
                blinded,
                auth_sig: IssueSignature(vec![0xCDu8; 64]),
            }
        }

        #[test]
        fn key_config_response_round_trips() {
            let kc = KeyConfigResponse {
                key_id: [1u8; 32],
                issuer_public_key: IssuerPublicKey(vec![0x42u8; 294]),
                epoch: 1,
                denomination: DENOMINATION,
            };
            let bytes = serde_json::to_vec(&kc).expect("serialize");
            let back: KeyConfigResponse = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(back.key_id, kc.key_id);
            assert_eq!(back.issuer_public_key.0, kc.issuer_public_key.0);
            assert_eq!(back.epoch, kc.epoch);
            assert_eq!(back.denomination, kc.denomination);
            assert!(back.validate().is_ok());
        }

        #[test]
        fn issue_request_round_trips_and_validates() {
            let req = sample_issue_request(3);
            let bytes = serde_json::to_vec(&req).expect("serialize");
            let back: IssueRequest = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(back.body, req.body);
            assert_eq!(back.blinded.len(), 3);
            assert_eq!(back.blinded[0].0, req.blinded[0].0);
            assert_eq!(back.auth_sig.0, req.auth_sig.0);
            assert!(back.validate().is_ok());
        }

        #[test]
        fn issue_response_round_trips_and_validates() {
            let resp = IssueResponse {
                key_id: [9u8; 32],
                signatures: vec![BlindSignature(vec![0x77u8; 256]); 2],
            };
            let bytes = serde_json::to_vec(&resp).expect("serialize");
            let back: IssueResponse = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(back.key_id, resp.key_id);
            assert_eq!(back.signatures.len(), 2);
            assert!(back.validate().is_ok());
        }

        #[test]
        fn redeem_request_round_trips_and_validates() {
            let req = RedeemRequest {
                key_id: [9u8; 32],
                token: Token(vec![0x11u8; 320]),
            };
            let bytes = serde_json::to_vec(&req).expect("serialize");
            let back: RedeemRequest = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(back.key_id, req.key_id);
            assert_eq!(back.token.0, req.token.0);
            assert!(back.validate().is_ok());
        }

        #[test]
        fn redeem_response_round_trips() {
            let r = RedeemResponse {
                spend_id: SpendId([2u8; 32]),
            };
            let bytes = serde_json::to_vec(&r).expect("serialize");
            let back: RedeemResponse = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(back.spend_id.0, r.spend_id.0);
            assert!(back.validate().is_ok());
        }

        #[test]
        fn grant_request_round_trips() {
            let r = GrantRequest {
                account_id: AccountId([3u8; 32]),
                amount: 7,
            };
            let bytes = serde_json::to_vec(&r).expect("serialize");
            let back: GrantRequest = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(back.account_id.0, r.account_id.0);
            assert_eq!(back.amount, r.amount);
            assert!(back.validate().is_ok());
        }

        #[test]
        fn redeem_token_wrong_length_fails() {
            let req = RedeemRequest {
                key_id: [9u8; 32],
                token: Token(vec![0u8; 319]),
            };
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("token")));
        }

        #[test]
        fn issue_batch_zero_fails() {
            let req = sample_issue_request(0);
            assert_eq!(req.validate(), Err(ProtoError::BatchSize));
        }

        #[test]
        fn issue_batch_too_big_fails() {
            let req = sample_issue_request(ISSUE_BATCH_MAX + 1);
            assert_eq!(req.validate(), Err(ProtoError::BatchSize));
        }

        #[test]
        fn issue_blinded_wrong_length_fails() {
            let mut req = sample_issue_request(2);
            req.blinded[1] = BlindedTokenRequest(vec![0u8; 255]);
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("blinded")));
        }

        // ---- Task 2: host registry / snapshots / receipts / trial DTOs ----

        use crate::model::ModelId;
        use crate::wire::SnapshotBody;

        fn sample_host_register_request() -> HostRegisterRequest {
            HostRegisterRequest {
                body: HostRegisterBody {
                    version: 1,
                    host_account: [0xA7u8; 32],
                    hpke_pk: vec![0x42u8; 32],
                    ingress_addr: "127.0.0.1:7000".into(),
                    models: vec![ModelId("llama-3.1-8b".into())],
                },
                sig: vec![0xCDu8; 64],
                pow_nonce: vec![0x11u8; 8],
            }
        }

        #[test]
        fn host_register_request_round_trips() {
            let req = sample_host_register_request();
            let bytes = serde_json::to_vec(&req).expect("serialize");
            let back: HostRegisterRequest = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(back.body, req.body);
            assert_eq!(back.sig, req.sig);
            assert_eq!(back.pow_nonce, req.pow_nonce);
            assert!(back.validate().is_ok());
        }

        #[test]
        fn host_register_wrong_sig_length_fails() {
            let mut req = sample_host_register_request();
            req.sig = vec![0u8; 63];
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("sig")));
        }

        #[test]
        fn host_register_wrong_pow_nonce_length_fails() {
            let mut req = sample_host_register_request();
            req.pow_nonce = vec![0u8; 7];
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("pow_nonce")));
        }

        #[test]
        fn host_register_bad_version_fails() {
            let mut req = sample_host_register_request();
            req.body.version = 2;
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("version")));
        }

        #[test]
        fn host_register_empty_ingress_fails() {
            let mut req = sample_host_register_request();
            req.body.ingress_addr.clear();
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("ingress_addr")));
        }

        #[test]
        fn host_register_empty_hpke_pk_fails() {
            let mut req = sample_host_register_request();
            req.body.hpke_pk.clear();
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("hpke_pk")));
        }

        fn sample_heartbeat_request() -> HeartbeatRequest {
            HeartbeatRequest {
                body: HeartbeatBody {
                    version: 1,
                    host_account: [0xA7u8; 32],
                    hb_counter: 42,
                    load_bucket: 5,
                    models: vec![ModelId("llama-3.1-8b".into())],
                },
                sig: vec![0xCDu8; 64],
            }
        }

        #[test]
        fn heartbeat_request_round_trips() {
            let req = sample_heartbeat_request();
            let bytes = serde_json::to_vec(&req).expect("serialize");
            let back: HeartbeatRequest = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(back.body, req.body);
            assert_eq!(back.sig, req.sig);
            assert!(back.validate().is_ok());
        }

        #[test]
        fn heartbeat_wrong_sig_length_fails() {
            let mut req = sample_heartbeat_request();
            req.sig = vec![0u8; 65];
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("sig")));
        }

        #[test]
        fn heartbeat_bad_version_fails() {
            let mut req = sample_heartbeat_request();
            req.body.version = 0;
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("version")));
        }

        fn sample_trial_register_request() -> TrialRegisterRequest {
            TrialRegisterRequest {
                body: TrialRegisterBody {
                    version: 1,
                    account: [0x1Fu8; 32],
                },
                pow_nonce: vec![0x22u8; 8],
            }
        }

        #[test]
        fn trial_register_request_round_trips() {
            let req = sample_trial_register_request();
            let bytes = serde_json::to_vec(&req).expect("serialize");
            let back: TrialRegisterRequest = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(back.body, req.body);
            assert_eq!(back.pow_nonce, req.pow_nonce);
            assert!(back.validate().is_ok());
        }

        #[test]
        fn trial_register_wrong_pow_nonce_length_fails() {
            let mut req = sample_trial_register_request();
            req.pow_nonce = vec![0u8; 9];
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("pow_nonce")));
        }

        fn sample_receipt_submit() -> ReceiptSubmit {
            ReceiptSubmit {
                body: UsageReceiptBody {
                    version: 1,
                    host_account: [0xA7u8; 32],
                    model_id: ModelId("llama-3.1-8b".into()),
                    tier: 1,
                    units: 7,
                    spend_id: [0x5Au8; 32],
                    epoch: 9,
                    timestamp_h: 1_700_000,
                },
                sig: vec![0xCDu8; 64],
            }
        }

        #[test]
        fn receipt_submit_round_trips() {
            let req = sample_receipt_submit();
            let bytes = serde_json::to_vec(&req).expect("serialize");
            let back: ReceiptSubmit = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(back.body, req.body);
            assert_eq!(back.sig, req.sig);
            assert!(back.validate().is_ok());
        }

        #[test]
        fn receipt_submit_wrong_sig_length_fails() {
            let mut req = sample_receipt_submit();
            req.sig = vec![0u8; 63];
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("sig")));
        }

        #[test]
        fn receipt_submit_bad_version_fails() {
            let mut req = sample_receipt_submit();
            req.body.version = 2;
            assert_eq!(req.validate(), Err(ProtoError::WrongLength("version")));
        }

        fn sample_snapshot_response() -> SnapshotResponse {
            SnapshotResponse {
                body: vec![0u8; 65536],
                sig: vec![0xCDu8; 64],
            }
        }

        #[test]
        fn snapshot_response_round_trips() {
            let resp = sample_snapshot_response();
            let bytes = serde_json::to_vec(&resp).expect("serialize");
            let back: SnapshotResponse = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(back.body, resp.body);
            assert_eq!(back.sig, resp.sig);
            assert!(back.validate().is_ok());
        }

        #[test]
        fn snapshot_response_wrong_sig_length_fails() {
            let mut resp = sample_snapshot_response();
            resp.sig = vec![0u8; 63];
            assert_eq!(resp.validate(), Err(ProtoError::WrongLength("sig")));
        }

        #[test]
        fn snapshot_response_wrong_body_length_fails() {
            let mut resp = sample_snapshot_response();
            resp.body = vec![0u8; 65535];
            assert_eq!(resp.validate(), Err(ProtoError::WrongLength("body")));
        }

        #[test]
        fn snapshot_body_postcard_round_trips_through_response() {
            // Sanity: a real SnapshotBody postcard-encodes then pads to the
            // 64 KiB bucket the SnapshotResponse validate() requires.
            let body = SnapshotBody {
                header: crate::wire::SnapshotHeader {
                    epoch: 7,
                    issued_at_h: 1_700_000,
                    issuer_key_id: [0x11u8; 32],
                },
                hosts: vec![crate::wire::SnapshotHostEntry {
                    host_account: [0xAAu8; 32],
                    hpke_pk: vec![0x42u8; 32],
                    models: vec![ModelId("llama-3.1-8b".into())],
                    tier_flags: 1,
                    load_bucket: 2,
                    freshness_bucket: 3,
                }],
            };
            let mut enc = postcard::to_stdvec(&body).expect("postcard encode");
            enc.resize(65536, 0);
            let resp = SnapshotResponse {
                body: enc,
                sig: vec![0xCDu8; 64],
            };
            assert!(resp.validate().is_ok());
        }
    }
}
