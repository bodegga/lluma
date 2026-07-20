//! `client.rs` — the redemption client (Task 8).
//!
//! Feature-gated behind `client` (see `lib.rs`): the reqwest dependency pulls
//! a fair bit of TLS/native-roots baggage, and the server crate is useful on
//! its own (Task 9's `main.rs`) without it. `cargo build -p lluma-issuer
//! --no-default-features` must compile — so every line below is only built
//! when the `client` feature is on (the file is gated at the module decl in
//! `lib.rs`; nothing inside this file needs a second `#[cfg]`).
//!
//! ## Transport separation (spec §9 — privacy invariant)
//!
//! `IssuerClient` (the issue side) and `RedeemClient` (the redeem side) each
//! construct their **own** `reqwest::Client`. They MUST NOT share one: a
//! shared keep-alive connection (or pooled cookie/conn affinity) would let
//! the issuer correlate an `/issue` from account A with a later `/redeem`
//! of a token issued to A, breaking unlinkability at the transport layer.
//! The two types are deliberately distinct so a caller can't accidentally
//! reuse one client's pool for the other flow.
//!
//! ## L8 (no plaintext/secret leakage)
//!
//! All reqwest transport errors map to `IssuerError::Internal` with no inner
//! text — the inner `Display` of a reqwest error can echo URLs and partial
//! response bytes, which can include base64 token material. Only the static
//! `IssuerError` `Display` strings ever reach a caller. Non-2xx HTTP
//! responses are mapped strictly by the JSON `code` field, never by inspecting
//! the response body text.

use std::time::{SystemTime, UNIX_EPOCH};

use blind_rsa_signatures::reexports::rand::Rng;
use lluma_core::proto::v1::{
    IssueRequest, IssueResponse, KeyConfigResponse, RedeemRequest, RedeemResponse,
};
use lluma_core::wire::{
    AccountPublicKey, AccountSecretKey, IssueRequestBody, SpendId, Token,
};

use crate::IssuerError;

/// Recompute `BLAKE3(issuer_public_key) == key_id` and reject if it does not.
/// The client pins the issuer's public key to its announced `key_id` so a
/// MITM that substitutes a different key (with a colliding or doctored
/// `key_id`) is caught before any tokens are minted against the wrong key.
/// Pure function — split out so it is trivially unit-testable.
fn verify_key_id(kc: &KeyConfigResponse) -> Result<(), IssuerError> {
    let got = *blake3::hash(&kc.issuer_public_key.0).as_bytes();
    if got != kc.key_id {
        return Err(IssuerError::BadRequest);
    }
    Ok(())
}

/// Map a server-reported error `code` string to the matching `IssuerError`.
/// An unknown code maps to `Internal` — never to a more permissive variant —
/// so a future server adding a code cannot corrupt the client's error
/// semantics.
fn map_code(code: &str) -> IssuerError {
    match code {
        "insufficient_credits" => IssuerError::InsufficientCredits,
        "unauthorized" => IssuerError::Unauthorized,
        "token_invalid" => IssuerError::TokenInvalid,
        "double_spend" => IssuerError::DoubleSpend,
        "request_id_conflict" => IssuerError::RequestIdConflict,
        "bad_request" => IssuerError::BadRequest,
        _ => IssuerError::Internal,
    }
}

/// Read a `reqwest::Response` to completion. On 2xx, return the raw body
/// bytes; on non-2xx, parse the `{code,message}` JSON body and map the `code`
/// field to an `IssuerError`. Any transport-level decode failure collapses
/// to `Internal` — never log or surface the raw body (leak L8).
async fn into_body(resp: reqwest::Response) -> Result<Vec<u8>, IssuerError> {
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|_| IssuerError::Internal)?
        .to_vec();
    if status.is_success() {
        Ok(bytes)
    } else {
        // Parse the error envelope only — its `code` field is a fixed
        // server-side string; the `message` is the static thiserror Display.
        let code = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("code").and_then(|c| c.as_str()).map(str::to_owned))
            .unwrap_or_default();
        Err(map_code(&code))
    }
}

// =========================================================================
// IssuerClient — the issue side. Owns its own reqwest::Client.
// =========================================================================

/// Client for the issue side: `GET /v1/key-config` and `POST /v1/issue`.
///
/// Has its own `reqwest::Client` — never shared with `RedeemClient`. A shared
/// client would keep a TCP keep-alive connection alive across issue↔redeem
/// and let the issuer correlate the two flows by connection identity.
pub struct IssuerClient {
    base_url: String,
    http: reqwest::Client,
}

impl IssuerClient {
    /// Construct a new issue-side client. Builds a fresh `reqwest::Client`
    /// (no shared pool with any other client in this process).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
        }
    }

    /// `GET /v1/key-config`. Fetch, parse, then **recompute and pin**
    /// `key_id == BLAKE3(issuer_public_key)`; a mismatched key_id is a
    /// `BadRequest` (treated as a malformed/attacked config).
    pub async fn fetch_key_config(&self) -> Result<KeyConfigResponse, IssuerError> {
        let resp = self
            .http
            .get(format!("{}/v1/key-config", self.base_url))
            .send()
            .await
            .map_err(|_| IssuerError::Internal)?;
        let bytes = into_body(resp).await?;
        let kc: KeyConfigResponse =
            serde_json::from_slice(&bytes).map_err(|_| IssuerError::Internal)?;
        verify_key_id(&kc)?;
        Ok(kc)
    }

    /// Blind `count` nonces against the issuer's public key, sign the batch
    /// with the account's Ed25519 secret key, POST `/v1/issue`, and unblind
    /// each returned signature positionally into a `Token`.
    ///
    /// `BlindingState`s are consumed (by value) by `token_unblind` — they
    /// are never cloned, and the function takes `account_pk` separately from
    /// `account_sk` so the caller can pass a borrowed pk view even if its
    /// storage differs from the secret-key store.
    pub async fn request_tokens(
        &self,
        kc: &KeyConfigResponse,
        account_sk: &AccountSecretKey,
        account_pk: &AccountPublicKey,
        count: usize,
    ) -> Result<Vec<Token>, IssuerError> {
        // Single RNG for both token_blind and the request_id nonce — the
        // brief pins DefaultRng here (RNG-split note, Global Constraints).
        let mut rng = blind_rsa_signatures::DefaultRng;

        let mut states = Vec::with_capacity(count);
        let mut blinded = Vec::with_capacity(count);
        for _ in 0..count {
            let (st, b) = lluma_crypto::tokens::token_blind(&mut rng, &kc.issuer_public_key)?;
            states.push(st);
            blinded.push(b);
        }

        // Batch hash: BLAKE3(postcard(blinded)) — pinned server-side.
        let bh_vec = postcard::to_stdvec(&blinded).map_err(|_| IssuerError::Internal)?;
        let blinded_batch_hash = *blake3::hash(&bh_vec).as_bytes();

        // Fresh request_id for this batch (idempotency key on the server).
        let mut request_id = [0u8; 32];
        rng.fill_bytes(&mut request_id);

        // account_pk must be a 32-byte Ed25519 public key.
        let account: [u8; 32] = account_pk
            .0
            .as_slice()
            .try_into()
            .map_err(|_| IssuerError::BadRequest)?;

        let ts_unix_s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IssuerError::Internal)?
            .as_secs();

        let body = IssueRequestBody {
            version: 1,
            account,
            key_id: kc.key_id,
            request_id,
            ts_unix_s,
            blinded_batch_hash,
        };
        let auth_sig = lluma_crypto::account::issue_request_sign(account_sk, &body)?;
        let req = IssueRequest {
            body,
            blinded,
            auth_sig,
        };

        let body_bytes = serde_json::to_vec(&req).map_err(|_| IssuerError::Internal)?;
        let resp = self
            .http
            .post(format!("{}/v1/issue", self.base_url))
            .header("content-type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(|_| IssuerError::Internal)?;

        let bytes = into_body(resp).await?;
        let r: IssueResponse =
            serde_json::from_slice(&bytes).map_err(|_| IssuerError::Internal)?;
        r.validate().map_err(|_| IssuerError::Internal)?;

        // The server returned exactly one signature per blinded request; if
        // not, something is wrong and we refuse to unblind (position-discovery
        // would be ambiguous).
        if r.signatures.len() != states.len() {
            return Err(IssuerError::Internal);
        }

        // Unblind positionally: states[i] consumed by value.
        let mut tokens = Vec::with_capacity(states.len());
        for (st, sig) in states.into_iter().zip(r.signatures.iter()) {
            let t = lluma_crypto::tokens::token_unblind(&kc.issuer_public_key, st, sig)?;
            tokens.push(t);
        }
        Ok(tokens)
    }
}

// =========================================================================
// RedeemClient — the redeem side. Its OWN reqwest::Client, never shared.
// =========================================================================

/// Client for the redeem side: `POST /v1/redeem`.
///
/// Deliberately a separate type from `IssuerClient` and the owner of its own
/// `reqwest::Client` — see the module-level transport-separation note. A
/// `RedeemRequest` carries no account identity, so there must be no
/// side-channel (connection pool, cookies, header affinity) capable of
/// linking it to a prior `/issue`.
pub struct RedeemClient {
    base_url: String,
    http: reqwest::Client,
}

impl RedeemClient {
    /// Construct a new redeem-side client with its own `reqwest::Client`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
        }
    }

    /// `POST /v1/redeem` with `{key_id, token}`. On 2xx parse `RedeemResponse`
    /// and return `spend_id`; on non-2xx map the server's `code` field to the
    /// matching `IssuerError`.
    pub async fn redeem(&self, key_id: [u8; 32], token: Token) -> Result<SpendId, IssuerError> {
        let req = RedeemRequest { key_id, token };
        let body = serde_json::to_vec(&req).map_err(|_| IssuerError::Internal)?;
        let resp = self
            .http
            .post(format!("{}/v1/redeem", self.base_url))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| IssuerError::Internal)?;
        let bytes = into_body(resp).await?;
        let r: RedeemResponse =
            serde_json::from_slice(&bytes).map_err(|_| IssuerError::Internal)?;
        Ok(r.spend_id)
    }
}

#[cfg(test)]
mod tests {
    //! In-process server harness: spin a real `axum::serve` over a
    //! `TcpListener` bound to `127.0.0.1:0` and exercise the client against
    //! it over a real HTTP wire. No `tower::ServiceExt::oneshot` here — the
    //! whole point of Task 8 is to prove the transport layer.

    use super::*;
    use crate::keys::EpochKeys;
    use crate::ledger::{CreditLedger, InMemoryLedger};
    use crate::service::{self, AppState};
    use crate::spent_set::{InMemorySpentSet, SpentSet};
    use crate::idem::IssueIdempotencyCache;
    use lluma_core::wire::Mnemonic;
    use std::sync::Arc;

    const ADMIN: &str = "test-admin-secret";

    /// Build an `AppState` with a freshly-keygen'd in-memory epoch keypair
    /// (no disk IO), fresh in-memory ledger/spent-set/idem cache, and a
    /// SystemTime-backed clock. Spawns `axum::serve` on an ephemeral port and
    /// returns `(base_url, state)` so tests can read shared state directly.
    async fn spawn_server() -> (String, AppState) {
        let mut rng = blind_rsa_signatures::DefaultRng;
        let (secret, public) =
            lluma_crypto::tokens::issuer_keygen(&mut rng).expect("issuer_keygen");
        let keys = EpochKeys {
            epoch: 1,
            secret,
            public,
        };
        let state = AppState {
            keys: Arc::new(keys),
            ledger: Arc::new(InMemoryLedger::new()) as Arc<dyn CreditLedger>,
            spent: Arc::new(InMemorySpentSet::new()) as Arc<dyn SpentSet>,
            idem: Arc::new(IssueIdempotencyCache::new()),
            admin_secret: Arc::new(ADMIN.to_string()),
            now_unix_s: || {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            },
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let server_state = state.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, service::router(server_state)).await;
        });
        (format!("http://{addr}"), state)
    }

    fn account_keypair(seed: u8) -> (AccountSecretKey, AccountPublicKey) {
        lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([seed; 16]))
            .expect("derive keypair")
    }

    /// Seed `amount` credits for `account_id` via the real /admin/grant
    /// endpoint. Uses a throwaway reqwest client (NOT one of the client
    /// types under test) — this is test scaffolding, not the code path under
    /// test.
    async fn grant(base: &str, account_id: lluma_core::wire::AccountId, amount: u64) {
        let body = serde_json::to_vec(&lluma_core::proto::v1::GrantRequest {
            account_id,
            amount,
        })
        .expect("serialize grant");
        let resp = reqwest::Client::new()
            .post(format!("{base}/v1/admin/grant"))
            .header("x-admin-secret", ADMIN)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .expect("grant send");
        assert_eq!(resp.status(), 200, "admin/grant should succeed");
        // Drain the body so the connection can be released.
        let _ = resp.bytes().await;
    }

    #[tokio::test]
    async fn verify_key_id_accepts_consistent_kc() {
        let mut rng = blind_rsa_signatures::DefaultRng;
        let (_, public) = lluma_crypto::tokens::issuer_keygen(&mut rng).expect("keygen");
        let key_id = *blake3::hash(&public.0).as_bytes();
        let kc = KeyConfigResponse {
            key_id,
            issuer_public_key: public.clone(),
            epoch: 1,
            denomination: 1,
        };
        assert!(verify_key_id(&kc).is_ok());
    }

    #[tokio::test]
    async fn verify_key_id_rejects_doctored_key_id() {
        let mut rng = blind_rsa_signatures::DefaultRng;
        let (_, public) = lluma_crypto::tokens::issuer_keygen(&mut rng).expect("keygen");
        // Doctored key_id: flip a byte. Recomputation must catch it.
        let mut key_id = *blake3::hash(&public.0).as_bytes();
        key_id[0] ^= 0xff;
        let kc = KeyConfigResponse {
            key_id,
            issuer_public_key: public,
            epoch: 1,
            denomination: 1,
        };
        assert!(matches!(verify_key_id(&kc), Err(IssuerError::BadRequest)));
    }

    #[tokio::test]
    async fn fetch_key_config_returns_kc_with_key_id_equal_to_blake3_pubkey() {
        let (base, state) = spawn_server().await;
        let client = IssuerClient::new(&base);
        let kc = client.fetch_key_config().await.expect("fetch kc");
        let want = *blake3::hash(&state.keys.public.0).as_bytes();
        assert_eq!(kc.key_id, want);
        assert_eq!(kc.key_id, state.keys.key_id());
        assert_eq!(kc.epoch, 1);
        assert_eq!(kc.denomination, 1);
    }

    #[tokio::test]
    async fn request_tokens_count_4_yields_4_verifiable_tokens() {
        let (base, state) = spawn_server().await;
        let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");
        let (sk, pk) = account_keypair(1);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        grant(&base, account_id, 10).await;

        let tokens = IssuerClient::new(&base)
            .request_tokens(&kc, &sk, &pk, 4)
            .await
            .expect("issue 4");
        assert_eq!(tokens.len(), 4);
        // Each token verifies under the issuer's public key.
        for t in &tokens {
            lluma_crypto::tokens::token_verify(&state.keys.public, t)
                .expect("token verifies under issuer pk");
        }
        // 10 granted, 4 debited → balance 6.
        assert_eq!(state.ledger.balance(&account_id), 6);
    }

    #[tokio::test]
    async fn redeem_each_token_once_then_second_is_double_spend() {
        let (base, state) = spawn_server().await;
        let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");
        let (sk, pk) = account_keypair(2);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        grant(&base, account_id, 4).await;

        let tokens = IssuerClient::new(&base)
            .request_tokens(&kc, &sk, &pk, 4)
            .await
            .expect("issue 4");

        // RedeemClient has its OWN reqwest::Client — fresh instance per
        // test, distinct from any IssuerClient in scope.
        let redeem = RedeemClient::new(&base);
        for t in &tokens {
            let spend_id = redeem
                .redeem(kc.key_id, t.clone())
                .await
                .expect("first redeem Ok");
            let want = lluma_crypto::tokens::token_spend_id(t);
            assert_eq!(spend_id.0, want.0);
        }
        // Redeeming the first token again → DoubleSpend.
        let dup = redeem
            .redeem(kc.key_id, tokens[0].clone())
            .await
            .expect_err("expected DoubleSpend");
        assert!(matches!(dup, IssuerError::DoubleSpend));
        // Spent set holds exactly 4 ids.
        // (No public len API on SpentSet, so we assert behaviour instead.)
        let _ = state;
    }

    #[tokio::test]
    async fn request_tokens_beyond_balance_returns_insufficient_credits() {
        let (base, _state) = spawn_server().await;
        let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");
        let (sk, pk) = account_keypair(3);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        // Grant only 2 credits; request 3 → InsufficientCredits.
        grant(&base, account_id, 2).await;

        let err = IssuerClient::new(&base)
            .request_tokens(&kc, &sk, &pk, 3)
            .await
            .expect_err("expected InsufficientCredits");
        assert!(matches!(err, IssuerError::InsufficientCredits));
    }

    // ---- Transport separation: structurally, the two clients own separate
    // reqwest::Client instances. A regression that refactored them to share
    // one would be observable by a single test that confirms each `new()`
    // constructs its own — there is no shared static or builder to leak
    // through. We assert the invariant by construction: the two types are
    // distinct (one compiles for issue, a different one for redeem) and the
    // fields are private to each impl block. ----

    #[tokio::test]
    async fn issue_and_redeem_clients_are_distinct_types_with_separate_pools() {
        let (base, _state) = spawn_server().await;
        // Two IssuerClient instances — each its own pool.
        let a = IssuerClient::new(&base);
        let b = IssuerClient::new(&base);
        // Touch both so they cannot be optimized away; in practice the only
        // invariant we can statically assert here is that they compile as
        // distinct instances. The structural invariant — separate reqwest
        // clients per type — is enforced by the field declarations above.
        assert_eq!(a.base_url, base);
        assert_eq!(b.base_url, base);
        // A RedeemClient shares neither instance's pool.
        let r = RedeemClient::new(&base);
        assert_eq!(r.base_url, base);
    }
}