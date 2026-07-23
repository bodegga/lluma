//! Byte-newtypes shared across the Lluma wire protocol. Public-material types
//! are transparent; secret-material types are zeroize-on-drop and never derive
//! Debug/Serialize over their bytes (privacy invariant, leak L8).
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ModelId;

macro_rules! public_bytes {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name(pub Vec<u8>);
        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

macro_rules! secret_bytes {
    ($name:ident) => {
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name(pub Vec<u8>);
        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

// Public material (safe to log/serialize).
public_bytes!(IssuerPublicKey);
public_bytes!(BlindedTokenRequest);
public_bytes!(OhttpKeyConfig);
public_bytes!(EncapsulatedRequest);
public_bytes!(HostPublicKey);
public_bytes!(SessionPublicKey);
public_bytes!(SealedRequest);
public_bytes!(AccountPublicKey);
public_bytes!(ReceiptSignature);
public_bytes!(KeystoreBlob);
public_bytes!(ResponsePreamble);

// A `Token` is a spendable bearer instrument and a `BlindSignature` is its
// precursor: `Debug`-logging either is a credit leak. They keep the same
// derives as the other public-byte types EXCEPT `Debug`, which is redacted to
// length only (no blake3 dependency in lluma-core).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token(pub Vec<u8>);
impl AsRef<[u8]> for Token {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl core::fmt::Debug for Token {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Token([redacted; {} bytes])", self.0.len())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindSignature(pub Vec<u8>);
impl AsRef<[u8]> for BlindSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl core::fmt::Debug for BlindSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BlindSignature([redacted; {} bytes])", self.0.len())
    }
}

// Fixed-size content-addressed ids. `Hash` is derived so they can key the
// issuer's `HashMap`/`HashSet` state (ledger balances, spent-set, idem cache).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpendId(pub [u8; 32]);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub [u8; 32]);

// Secret material (zeroize on drop; no Debug/Serialize).
secret_bytes!(IssuerSecretKey);
secret_bytes!(GatewaySecretKey);
secret_bytes!(HostSecretKey);
secret_bytes!(SessionSecretKey);
secret_bytes!(AccountSecretKey);
secret_bytes!(BlindingState);

/// A BIP-39 mnemonic's 16-byte entropy (12 words). Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic(pub [u8; 16]);
impl AsRef<[u8]> for Mnemonic {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Canonical usage-receipt body. Deterministic encoding via postcard.
/// Contains the HOST's account and the spent-token id only — never a consumer
/// account, session key, ciphertext hash, or fine timestamp (leak L4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageReceiptBody {
    pub version: u8,
    pub host_account: [u8; 32],
    pub model_id: ModelId,
    pub tier: u8,
    pub units: u32,
    pub spend_id: [u8; 32],
    pub epoch: u32,
    pub timestamp_h: u32,
}

/// Canonical issue-request body, signed by the consumer's account Ed25519 key
/// to authorize an issue batch. `account` is the signer's own public-key bytes
/// (32 B). Domain-separated from usage-receipt signing (see `lluma-crypto`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRequestBody {
    pub version: u8,
    pub account: [u8; 32],
    pub key_id: [u8; 32],
    pub request_id: [u8; 32],
    pub ts_unix_s: u64,
    pub blinded_batch_hash: [u8; 32],
}

/// Ed25519 signature (64 B) over the canonical `IssueRequestBody`. Public
/// material — Debug is safe (no secret bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueSignature(pub Vec<u8>);
impl AsRef<[u8]> for IssueSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Canonical host-registration body, signed by the host's account Ed25519 key
/// to join the registry. `hpke_pk` is the host's HPKE KEM public key; models is
/// the (non-empty) set of `ModelId`s the host is offering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRegisterBody {
    pub version: u8,
    pub host_account: [u8; 32],
    pub hpke_pk: Vec<u8>,
    pub ingress_addr: String,
    pub models: Vec<ModelId>,
}

/// Canonical heartbeat body, signed by the host's account Ed25519 key. Carries
/// load/freshness buckets the broker folds into the next signed snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatBody {
    pub version: u8,
    pub host_account: [u8; 32],
    pub hb_counter: u64,
    pub load_bucket: u8,
    pub models: Vec<ModelId>,
}

/// Canonical anti-Sybil trial-registration body. The issuer credits a one-time
/// trial allowance to `account` on acceptance. This body is NOT signed — the
/// request is gated by proof-of-work (nonce carried in the `TrialRegisterRequest`
/// DTO, domain `lluma-pow-trial-v1`), which binds the grant to this account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialRegisterBody {
    pub version: u8,
    pub account: [u8; 32],
}

/// One host as it appears in the signed registry snapshot. NOTE: deliberately
/// carries NO `ingress_addr` — clients never learn host network addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotHostEntry {
    pub host_account: [u8; 32],
    pub hpke_pk: Vec<u8>,
    pub models: Vec<ModelId>,
    pub tier_flags: u8,
    pub load_bucket: u8,
    pub freshness_bucket: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotHeader {
    pub epoch: u64,
    pub issued_at_h: u32,
    pub issuer_key_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBody {
    pub header: SnapshotHeader,
    pub hosts: Vec<SnapshotHostEntry>,
}

/// Client bootstrap document — the network coordinates an app needs to connect,
/// published (signed) so a fresh install can self-configure. Signed by the
/// registry key with domain `lluma-bootstrap-v1`; the app verifies against its
/// pinned registry public key. Carries only NON-pinned material: the registry
/// pubkey itself is compiled into the app, so it is not repeated here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapDoc {
    pub version: u8,
    /// Canonical relay URL (hook for future nearest-relay selection).
    pub relay_url: String,
    /// Gateway OHTTP key-config bytes (what the client seals OHTTP to).
    pub gateway_kc: Vec<u8>,
    /// Pinned issuer key-id (`BLAKE3(issuer_pubkey)`) the client cross-checks.
    pub issuer_key_id: [u8; 32],
    /// Unix seconds the doc was signed (freshness/debugging; not an expiry).
    pub issued_at_s: u64,
    /// Reverse-tunnel endpoint (`wss://…/v1/host/tunnel`) a NAT-bound host dials,
    /// or `None` when tunnelling is not offered. Appended LAST for ONE-WAY compat:
    /// a client built BEFORE this field still decodes a doc signed WITH it
    /// (postcard reads its known fields and ignores trailing bytes), and the
    /// signature still covers the whole doc. The reverse is NOT true — postcard
    /// is not self-describing, so a client built WITH this field cannot decode an
    /// OLD blob that lacks it (it would read past the end). Deploy rule: publish
    /// the re-signed blob (which carries the tag byte) BEFORE shipping any client
    /// built from this revision. `serde(default)` is deliberately omitted: it is
    /// inert for postcard and would only mislead. A host trusts this URL — and
    /// verifies the broker's TLS against its hostname — only because it is
    /// registry-signed here, so a malicious relay cannot substitute its own.
    pub tunnel_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_body_postcard_round_trips() {
        let body = SnapshotBody {
            header: SnapshotHeader {
                epoch: 42,
                issued_at_h: 1_700_000,
                issuer_key_id: [0x11u8; 32],
            },
            hosts: vec![
                SnapshotHostEntry {
                    host_account: [0xAAu8; 32],
                    hpke_pk: vec![0x42u8; 32],
                    models: vec![ModelId("llama-3.1-8b".into())],
                    tier_flags: 1,
                    load_bucket: 2,
                    freshness_bucket: 3,
                },
                SnapshotHostEntry {
                    host_account: [0xBBu8; 32],
                    hpke_pk: vec![0x43u8; 32],
                    models: vec![ModelId("qwen2.5-7b".into())],
                    tier_flags: 0,
                    load_bucket: 7,
                    freshness_bucket: 7,
                },
            ],
        };
        let enc = postcard::to_stdvec(&body).expect("encode");
        let back: SnapshotBody = postcard::from_bytes(&enc).expect("decode");
        assert_eq!(back, body);
    }
}
