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
        AccountId, BlindSignature, BlindedTokenRequest, IssueRequestBody, IssueSignature,
        IssuerPublicKey, SpendId, Token,
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
    pub struct GrantRequest {
        pub account_id: AccountId,
        pub amount: u64,
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
    }
}
