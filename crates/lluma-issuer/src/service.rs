//! `service.rs` — the axum 0.7 HTTP service: router + handlers over the
//! `CreditLedger`, `SpentSet`, `IssueIdempotencyCache`, and `EpochKeys` trait
//! seams built in Tasks 2–6.
//!
//! ## L8 (no plaintext/secret leakage)
//! Request bodies are read as raw `axum::body::Bytes` and parsed with
//! `serde_json::from_slice`, mapping ANY parse error to `IssuerError::BadRequest`
//! — never surfacing serde's error text, which can echo request bytes. Using
//! `axum::Json<T>` as a request extractor is intentionally avoided: its default
//! rejection embeds the serde `Display` string in the response body.
//! `Json` IS used for RESPONSES (only the request-extractor path is dangerous).
//! No handler/layer logs request or response bodies — at most method+path+status.
//! Crypto failures all collapse to `IssuerError::Internal`; the inner `Display`
//! (which may interpolate blind/RSA detail) is dropped.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;

use lluma_core::proto::v1::{
    GrantRequest, IssueRequest, IssueResponse, KeyConfigResponse, RedeemRequest, RedeemResponse,
    DENOMINATION,
};
use lluma_core::wire::{AccountPublicKey, AccountId};

use crate::idem::IssueIdempotencyCache;
use crate::keys::EpochKeys;
use crate::ledger::CreditLedger;
use crate::spent_set::SpentSet;
use crate::IssuerError;

/// Shared application state held by every handler via `State<AppState>`.
/// All fields are `Arc`/`fn` so the struct is cheaply `Clone` per request.
#[derive(Clone)]
pub struct AppState {
    pub keys: Arc<EpochKeys>,
    pub ledger: Arc<dyn CreditLedger>,
    pub spent: Arc<dyn SpentSet>,
    pub idem: Arc<IssueIdempotencyCache>,
    pub admin_secret: Arc<String>,
    /// Injectable clock so tests run deterministically. Production sets this to
    /// `|| SystemTime::now()...` in `main.rs` (Task 9).
    pub now_unix_s: fn() -> u64,
}

/// Build the v1 issuer router with the supplied state.
pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/v1/key-config", get(key_config))
        .route("/v1/issue", post(issue))
        .route("/v1/redeem", post(redeem))
        .route("/v1/admin/grant", post(admin_grant))
        .with_state(state)
}

/// Parse a request body as JSON, mapping ANY failure to `BadRequest` (L8:
/// never surface serde's `Display`, which can echo request bytes).
fn parse<T: serde::de::DeserializeOwned>(b: &Bytes) -> Result<T, IssuerError> {
    serde_json::from_slice(b).map_err(|_| IssuerError::BadRequest)
}

// ---- IntoResponse for IssuerError: static code+message, no request bytes ----

impl IntoResponse for IssuerError {
    fn into_response(self) -> Response {
        // Map the typed `u16` to a `StatusCode` without `unwrap` — the variant
        // set is fixed and covered exhaustively below.
        let status = match self.status() {
            402 => StatusCode::PAYMENT_REQUIRED,
            403 => StatusCode::FORBIDDEN,
            409 => StatusCode::CONFLICT,
            422 => StatusCode::UNPROCESSABLE_ENTITY,
            500 => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        // `self.to_string()` is the static thiserror message — fixed text,
        // no request bytes interpolated.
        let body = serde_json::json!({
            "code": self.code(),
            "message": self.to_string(),
        });
        (status, Json(body)).into_response()
    }
}

// ---- handlers ----

/// `GET /v1/key-config` — return the current epoch's public key + content id.
async fn key_config(State(state): State<AppState>) -> Result<Json<KeyConfigResponse>, IssuerError> {
    Ok(Json(KeyConfigResponse {
        key_id: state.keys.key_id(),
        issuer_public_key: state.keys.public.clone(),
        epoch: state.keys.epoch,
        denomination: DENOMINATION,
    }))
}

/// `POST /v1/issue` — blind-sign a batch of blinded tokens, debiting credits.
///
/// Handler order is normative (spec §6 / Task 7 brief):
/// 1. parse (serde err → BadRequest)
/// 2. validate (version, batch size, blinded/auth_sig lengths → BadRequest)
/// 3. issue_request_verify → Unauthorized
/// 4. |now − ts_unix_s| ≤ 600 → else BadRequest
/// 5. body.key_id == keys.key_id() → else BadRequest
/// 6. blake3(postcard(blinded)) == body.blinded_batch_hash → else BadRequest
/// 7. account_id = account_fingerprint(account)
/// 8. idem.lookup → Replay(resp) ⇒ return resp; Conflict ⇒ 409; Fresh ⇒ continue
/// 9. ledger.debit(blinded.len() as u64) → 402 on InsufficientCredits
/// 10. token_issue per blinded, in order; on any Err: refund + 500 Internal
/// 11. resp = IssueResponse { key_id, signatures }; idem.store; return resp
async fn issue(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<IssueResponse>, IssuerError> {
    // Step 1: parse — never surface serde's text.
    let req: IssueRequest = parse(&body)?;

    // Step 2: validate (version, batch size, field lengths).
    req.validate().map_err(|_| IssuerError::BadRequest)?;

    // Step 3: verify the Ed25519 auth signature over the request body.
    lluma_crypto::account::issue_request_verify(
        &AccountPublicKey(req.body.account.to_vec()),
        &req.body,
        &req.auth_sig,
    )
    .map_err(|_| IssuerError::Unauthorized)?;

    // Step 4: freshness window — ±600 s.
    let now = (state.now_unix_s)();
    if now.abs_diff(req.body.ts_unix_s) > 600 {
        return Err(IssuerError::BadRequest);
    }

    // Step 5: pin to this issuer's epoch key.
    if req.body.key_id != state.keys.key_id() {
        return Err(IssuerError::BadRequest);
    }

    // Step 6: blake3(postcard(blinded)) must equal body.blinded_batch_hash.
    let bh_bytes = postcard::to_stdvec(&req.blinded).map_err(|_| IssuerError::Internal)?;
    let bh = *blake3::hash(&bh_bytes).as_bytes();
    if bh != req.body.blinded_batch_hash {
        return Err(IssuerError::BadRequest);
    }

    // Step 7: account content id (BLAKE3 of the account pubkey — never the raw key).
    let account_id: AccountId = lluma_crypto::account::account_fingerprint(&AccountPublicKey(
        req.body.account.to_vec(),
    ));

    // Step 8: idempotency replay/conflict check.
    match state.idem.lookup(&account_id, &req.body.request_id, &req.body.blinded_batch_hash) {
        crate::idem::IdemLookup::Replay(r) => return Ok(Json(r)),
        crate::idem::IdemLookup::Conflict => return Err(IssuerError::RequestIdConflict),
        crate::idem::IdemLookup::Fresh => {}
    }

    // Step 9: debit credits atomically. Amount = batch size (single denomination).
    let amount = req.blinded.len() as u64;
    state.ledger.debit(&account_id, amount)?;

    // Step 10: blind-sign each blinded token in order. On any failure, refund
    // the just-debited credits and return Internal (never surface crypto detail).
    let mut rng = blind_rsa_signatures::DefaultRng;
    let mut signatures = Vec::with_capacity(req.blinded.len());
    for b in &req.blinded {
        match lluma_crypto::tokens::token_issue(&mut rng, &state.keys.secret, b) {
            Ok(sig) => signatures.push(sig),
            Err(_) => {
                state.ledger.grant(&account_id, amount);
                return Err(IssuerError::Internal);
            }
        }
    }

    // Step 11: build response, store in idempotency cache, return.
    let resp = IssueResponse {
        key_id: state.keys.key_id(),
        signatures,
    };
    state.idem.store(
        &account_id,
        req.body.request_id,
        req.body.blinded_batch_hash,
        resp.clone(),
    );
    Ok(Json(resp))
}

/// `POST /v1/redeem` — verify a token and record its `SpendId` atomically.
///
/// Order (spec §6):
/// 1. parse (serde err → BadRequest)
/// 2. validate (token length 320 → TokenInvalid, NOT BadRequest)
/// 3. req.key_id == keys.key_id() → else TokenInvalid (cross-key isolation)
/// 4. token_verify → else TokenInvalid
/// 5. spend_id = token_spend_id(token); spent.insert → Inserted ⇒ 200,
///    AlreadySpent ⇒ 409 DoubleSpend
async fn redeem(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<RedeemResponse>, IssuerError> {
    // Step 1: parse.
    let req: RedeemRequest = parse(&body)?;

    // Step 2: validate — token-length failure maps to TokenInvalid, not BadRequest.
    req.validate().map_err(|_| IssuerError::TokenInvalid)?;

    // Step 3: cross-key isolation.
    if req.key_id != state.keys.key_id() {
        return Err(IssuerError::TokenInvalid);
    }

    // Step 4: cryptographic verification under this issuer's public key.
    lluma_crypto::tokens::token_verify(&state.keys.public, &req.token)
        .map_err(|_| IssuerError::TokenInvalid)?;

    // Step 5: double-spend check-and-set.
    let spend_id = lluma_crypto::tokens::token_spend_id(&req.token);
    match state.spent.insert(spend_id) {
        crate::spent_set::InsertOutcome::AlreadySpent => Err(IssuerError::DoubleSpend),
        crate::spent_set::InsertOutcome::Inserted => Ok(Json(RedeemResponse { spend_id })),
    }
}

/// `POST /v1/admin/grant` — admin-only credit grant.
///
/// 1. header `x-admin-secret` constant-time-ish compared to `admin_secret`
///    → unequal ⇒ Unauthorized (403).
/// 2. parse `GrantRequest`; `ledger.grant(account_id, amount)`; 200.
///
/// The `unwrap_or("")` on the borrowed header value is not a `Result::unwrap`
/// — it returns a static `&str` slice; no panics.
async fn admin_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, IssuerError> {
    let secret = headers
        .get("x-admin-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct_eq(secret, state.admin_secret.as_str()) {
        return Err(IssuerError::Unauthorized);
    }

    let g: GrantRequest = parse(&body)?;
    state.ledger.grant(&g.account_id, g.amount);
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Constant-time-ish byte comparison. Length-mismatch returns early; once
/// lengths match, every byte is folded into a single diff so the loop's
/// branch behaviour is independent of the secret's contents.
fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use lluma_core::wire::{AccountSecretKey, BlindingState, IssueRequestBody, Mnemonic, Token};
    use tower::ServiceExt;

    /// Fixed clocks so tests are deterministic: handlers read `(state.now_unix_s)()`.
    const NOW: u64 = 1_000_000;

    /// Build a fresh state with an in-memory epoch keypair (no disk IO), fresh
    /// ledger / spent-set / idem cache, and the supplied admin secret.
    fn make_state(admin: &str) -> AppState {
        let mut rng = blind_rsa_signatures::DefaultRng;
        let (secret, public) = lluma_crypto::tokens::issuer_keygen(&mut rng).expect("keygen");
        let keys = EpochKeys {
            epoch: 1,
            secret,
            public,
        };
        AppState {
            keys: Arc::new(keys),
            ledger: Arc::new(lluma_ledger()) as Arc<dyn CreditLedger>,
            spent: Arc::new(lluma_spent()) as Arc<dyn SpentSet>,
            idem: Arc::new(IssueIdempotencyCache::new()),
            admin_secret: Arc::new(admin.to_string()),
            now_unix_s: || NOW,
        }
    }

    fn lluma_ledger() -> crate::ledger::InMemoryLedger {
        crate::ledger::InMemoryLedger::new()
    }
    fn lluma_spent() -> crate::spent_set::InMemorySpentSet {
        crate::spent_set::InMemorySpentSet::new()
    }

    fn account_keypair(seed: u8) -> (AccountSecretKey, AccountPublicKey) {
        lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([seed; 16]))
            .expect("derive keypair")
    }

    /// Build a valid signed `IssueRequest` for `count` blinded tokens. All
    /// blinds use a fresh `DefaultRng`. `request_id` defaults to a fixed
    /// value so two calls with the same args produce an exact-replay request;
    /// callers can override it for the conflict test.
    fn build_issue_request(
        keys: &EpochKeys,
        sk: &AccountSecretKey,
        pk: &AccountPublicKey,
        count: usize,
        ts: u64,
        request_id: [u8; 32],
    ) -> IssueRequest {
        let mut rng = blind_rsa_signatures::DefaultRng;
        let mut blinded: Vec<lluma_core::wire::BlindedTokenRequest> =
            Vec::with_capacity(count);
        for _ in 0..count {
            let (_state, b) =
                lluma_crypto::tokens::token_blind(&mut rng, &keys.public).expect("blind");
            blinded.push(b);
        }
        let bh_bytes = postcard::to_stdvec(&blinded).expect("postcard");
        let bh = *blake3::hash(&bh_bytes).as_bytes();
        let mut account = [0u8; 32];
        account.copy_from_slice(&pk.0);
        let body = IssueRequestBody {
            version: 1,
            account,
            key_id: keys.key_id(),
            request_id,
            ts_unix_s: ts,
            blinded_batch_hash: bh,
        };
        let auth_sig =
            lluma_crypto::account::issue_request_sign(sk, &body).expect("sign");
        IssueRequest {
            body,
            blinded,
            auth_sig,
        }
    }

    fn build_issue_request_with_wrong_batch_hash(
        keys: &EpochKeys,
        sk: &AccountSecretKey,
        pk: &AccountPublicKey,
        count: usize,
    ) -> IssueRequest {
        let mut rng = blind_rsa_signatures::DefaultRng;
        let mut blinded: Vec<lluma_core::wire::BlindedTokenRequest> =
            Vec::with_capacity(count);
        for _ in 0..count {
            let (_state, b) =
                lluma_crypto::tokens::token_blind(&mut rng, &keys.public).expect("blind");
            blinded.push(b);
        }
        let mut account = [0u8; 32];
        account.copy_from_slice(&pk.0);
        // Use a deliberately wrong blinded_batch_hash (all 0xFF).
        let body = IssueRequestBody {
            version: 1,
            account,
            key_id: keys.key_id(),
            request_id: [0xAA; 32],
            ts_unix_s: NOW,
            blinded_batch_hash: [0xFF; 32],
        };
        let auth_sig =
            lluma_crypto::account::issue_request_sign(sk, &body).expect("sign");
        IssueRequest {
            body,
            blinded,
            auth_sig,
        }
    }

    /// Build a real, unblinded, verifiable token without going through the
    /// HTTP layer — used to feed `/redeem` deterministic inputs.
    fn build_real_token(keys: &EpochKeys) -> Token {
        let mut rng = blind_rsa_signatures::DefaultRng;
        let (state, req) =
            lluma_crypto::tokens::token_blind(&mut rng, &keys.public).expect("blind");
        let blind_sig =
            lluma_crypto::tokens::token_issue(&mut rng, &keys.secret, &req).expect("issue");
        lluma_crypto::tokens::token_unblind(&keys.public, state, &blind_sig).expect("unblind")
    }

    fn build_post<T: serde::Serialize>(uri: &str, body: &T) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(body).expect("serialize"),
            ))
            .expect("request builder")
    }

    fn build_post_with_admin<T: serde::Serialize>(
        uri: &str,
        admin_secret: &str,
        body: &T,
    ) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-admin-secret", admin_secret)
            .body(axum::body::Body::from(
                serde_json::to_vec(body).expect("serialize"),
            ))
            .expect("request builder")
    }

    async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("collect body")
            .to_vec()
    }

    // ---- Task 7 normative handler tests ----

    #[tokio::test]
    async fn key_config_returns_key_id_equal_to_blake3_pubkey() {
        let state = make_state("test-secret");
        let app = router(state.clone());
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/key-config")
            .body(axum::body::Body::empty())
            .expect("request builder");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 200);
        let bytes = body_bytes(resp).await;
        let kc: KeyConfigResponse = serde_json::from_slice(&bytes).expect("parse kc");
        let want = *blake3::hash(&state.keys.public.0).as_bytes();
        assert_eq!(kc.key_id, want);
        assert_eq!(kc.key_id, state.keys.key_id());
        assert_eq!(kc.epoch, 1);
        assert_eq!(kc.denomination, DENOMINATION);
    }

    #[tokio::test]
    async fn happy_issue_returns_signatures_and_debits_balance() {
        let state = make_state("test-secret");
        let (sk, pk) = account_keypair(1);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        state.ledger.grant(&account_id, 10);

        let req_body = build_issue_request(&state.keys, &sk, &pk, 3, NOW, [0xAA; 32]);
        let req = build_post("/v1/issue", &req_body);
        let resp = router(state.clone())
            .oneshot(req)
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), 200);
        let bytes = body_bytes(resp).await;
        let r: IssueResponse = serde_json::from_slice(&bytes).expect("parse issue resp");
        assert_eq!(r.signatures.len(), 3);
        assert_eq!(r.key_id, state.keys.key_id());
        // 10 granted, 3 debited → balance 7.
        assert_eq!(state.ledger.balance(&account_id), 7);
    }

    #[tokio::test]
    async fn issue_beyond_balance_returns_402() {
        let state = make_state("test-secret");
        let (sk, pk) = account_keypair(2);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        state.ledger.grant(&account_id, 2);

        let req_body =
            build_issue_request(&state.keys, &sk, &pk, 3, NOW, [0xBB; 32]);
        let req = build_post("/v1/issue", &req_body);
        let resp = router(state.clone()).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 402);
    }

    #[tokio::test]
    async fn bad_auth_sig_returns_403() {
        let state = make_state("test-secret");
        let (sk, pk) = account_keypair(3);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        state.ledger.grant(&account_id, 10);

        let mut req_body =
            build_issue_request(&state.keys, &sk, &pk, 3, NOW, [0xCC; 32]);
        // Flip a byte in auth_sig — still 64 bytes (validate() passes), but
        // verify() fails → 403 unauthorized.
        req_body.auth_sig.0[0] ^= 0xff;
        let req = build_post("/v1/issue", &req_body);
        let resp = router(state).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn stale_ts_returns_422() {
        let state = make_state("test-secret");
        let (sk, pk) = account_keypair(4);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        state.ledger.grant(&account_id, 10);

        // now = 1_000_000; ts = now − 1000 ⇒ |diff| = 1000 > 600.
        let req_body =
            build_issue_request(&state.keys, &sk, &pk, 3, NOW - 1000, [0xDD; 32]);
        let req = build_post("/v1/issue", &req_body);
        let resp = router(state).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn wrong_blinded_batch_hash_returns_422() {
        let state = make_state("test-secret");
        let (sk, pk) = account_keypair(5);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        state.ledger.grant(&account_id, 10);

        let req_body =
            build_issue_request_with_wrong_batch_hash(&state.keys, &sk, &pk, 3);
        let req = build_post("/v1/issue", &req_body);
        let resp = router(state).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn batch_of_zero_returns_422() {
        let state = make_state("test-secret");
        let (sk, pk) = account_keypair(6);
        // Build a 1-batch then truncate `blinded` to 0 — validates() flags BatchSize.
        let mut req_body =
            build_issue_request(&state.keys, &sk, &pk, 1, NOW, [0xEE; 32]);
        req_body.blinded.clear();
        let req = build_post("/v1/issue", &req_body);
        let resp = router(state).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn batch_of_65_returns_422() {
        let state = make_state("test-secret");
        let (sk, pk) = account_keypair(7);
        let req_body =
            build_issue_request(&state.keys, &sk, &pk, 65, NOW, [0xFF; 32]);
        let req = build_post("/v1/issue", &req_body);
        let resp = router(state).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn idem_replay_same_request_returns_same_signatures_and_debits_once() {
        let state = make_state("test-secret");
        let (sk, pk) = account_keypair(8);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        state.ledger.grant(&account_id, 10);

        // First call: a valid batch of 3.
        let req1 =
            build_issue_request(&state.keys, &sk, &pk, 3, NOW, [0x11; 32]);
        let req = build_post("/v1/issue", &req1);
        let resp = router(state.clone())
            .oneshot(req)
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), 200);
        let bytes1 = body_bytes(resp).await;
        let r1: IssueResponse = serde_json::from_slice(&bytes1).expect("parse r1");
        assert_eq!(r1.signatures.len(), 3);
        assert_eq!(state.ledger.balance(&account_id), 7);

        // Replay the EXACT same request (same request_id, same blinded batch
        // → same blinded_batch_hash). Must return identical signatures and not
        // debit again.
        let req = build_post("/v1/issue", &req1);
        let resp = router(state.clone())
            .oneshot(req)
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), 200);
        let bytes2 = body_bytes(resp).await;
        let r2: IssueResponse = serde_json::from_slice(&bytes2).expect("parse r2");
        assert_eq!(r2.signatures.len(), 3);
        // Signature bytes must match exactly.
        for (a, b) in r1.signatures.iter().zip(r2.signatures.iter()) {
            assert_eq!(a.0, b.0, "replay must return identical signatures");
        }
        // Balance unchanged on the 2nd call.
        assert_eq!(state.ledger.balance(&account_id), 7);
    }

    #[tokio::test]
    async fn idem_same_request_id_different_batch_returns_409() {
        let state = make_state("test-secret");
        let (sk, pk) = account_keypair(9);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        state.ledger.grant(&account_id, 10);

        // First: a 3-batch request under request_id R.
        let req1 =
            build_issue_request(&state.keys, &sk, &pk, 3, NOW, [0x22; 32]);
        let req = build_post("/v1/issue", &req1);
        let resp = router(state.clone())
            .oneshot(req)
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), 200);
        assert_eq!(state.ledger.balance(&account_id), 7);

        // Second: SAME request_id R but a DIFFERENT blinded batch (4 blinds →
        // different blinded_batch_hash) → Conflict.
        let req2 =
            build_issue_request(&state.keys, &sk, &pk, 4, NOW, [0x22; 32]);
        let req = build_post("/v1/issue", &req2);
        let resp = router(state.clone()).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 409);
        // Balance not debited by the conflicting attempt.
        assert_eq!(state.ledger.balance(&account_id), 7);
    }

    #[tokio::test]
    async fn redeem_valid_token_returns_spend_id_200() {
        let state = make_state("test-secret");
        let token = build_real_token(&state.keys);
        let req_body = RedeemRequest {
            key_id: state.keys.key_id(),
            token: token.clone(),
        };
        let req = build_post("/v1/redeem", &req_body);
        let resp = router(state).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 200);
        let bytes = body_bytes(resp).await;
        let r: RedeemResponse = serde_json::from_slice(&bytes).expect("parse redeem resp");
        let want = lluma_crypto::tokens::token_spend_id(&token);
        assert_eq!(r.spend_id.0, want.0);
    }

    #[tokio::test]
    async fn redeem_same_token_twice_second_409() {
        let state = make_state("test-secret");
        let token = build_real_token(&state.keys);
        let req_body = RedeemRequest {
            key_id: state.keys.key_id(),
            token: token.clone(),
        };
        let req = build_post("/v1/redeem", &req_body);
        let resp = router(state.clone())
            .oneshot(req)
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), 200);

        let req = build_post("/v1/redeem", &req_body);
        let resp = router(state).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 409);
    }

    #[tokio::test]
    async fn redeem_with_wrong_key_id_returns_422() {
        let state = make_state("test-secret");
        let token = build_real_token(&state.keys);
        let mut req_body = RedeemRequest {
            key_id: state.keys.key_id(),
            token,
        };
        // Flip a byte in key_id — cross-key isolation rejects.
        req_body.key_id[0] ^= 0xff;
        let req = build_post("/v1/redeem", &req_body);
        let resp = router(state).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn redeem_tampered_token_returns_422() {
        let state = make_state("test-secret");
        let mut token = build_real_token(&state.keys);
        // Flip a byte inside the token — still 320 bytes (validate passes),
        // then token_verify fails → 422 token_invalid.
        token.0[10] ^= 0xff;
        let req_body = RedeemRequest {
            key_id: state.keys.key_id(),
            token,
        };
        let req = build_post("/v1/redeem", &req_body);
        let resp = router(state).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn grant_without_admin_secret_returns_403() {
        let state = make_state("test-secret");
        let (_, pk) = account_keypair(10);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        let g = GrantRequest {
            account_id,
            amount: 5,
        };
        // No x-admin-secret header → 403.
        let bytes = serde_json::to_vec(&g).expect("serialize");
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/grant")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(bytes))
            .expect("request builder");
        let resp = router(state.clone())
            .oneshot(req)
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), 403);
        assert_ne!(state.ledger.balance(&account_id), 5);
    }

    #[tokio::test]
    async fn grant_with_wrong_admin_secret_returns_403() {
        let state = make_state("test-secret");
        let (_, pk) = account_keypair(11);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        let g = GrantRequest {
            account_id,
            amount: 5,
        };
        let req = build_post_with_admin("/v1/admin/grant", "WRONG", &g);
        let resp = router(state).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn grant_with_correct_secret_returns_200_and_balance_rises() {
        let state = make_state("test-secret");
        let (_, pk) = account_keypair(12);
        let account_id = lluma_crypto::account::account_fingerprint(&pk);
        let g = GrantRequest {
            account_id,
            amount: 5,
        };
        let req = build_post_with_admin("/v1/admin/grant", "test-secret", &g);
        let resp = router(state.clone())
            .oneshot(req)
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), 200);
        assert_eq!(state.ledger.balance(&account_id), 5);
    }

    // ---- L8 sanity: error bodies never echo request bytes ----

    #[tokio::test]
    async fn error_body_has_only_code_and_message_static_text() {
        // A malformed JSON body injecting attacker text must NOT appear in the
        // response body — only `{ "code": "...", "message": "bad request" }`.
        let state = make_state("test-secret");
        let evil = br#"{"evil":"ATTACKER_DATA_THAT_MUST_LEAK"}"#;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/issue")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(&evil[..]))
            .expect("request builder");
        let resp = router(state).oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), 422);
        let bytes = body_bytes(resp).await;
        let s = String::from_utf8(bytes).expect("utf8 body");
        assert!(
            !s.contains("ATTACKER_DATA_THAT_MUST_LEAK"),
            "L8 violation: error body echoed request bytes: {s}"
        );
        let v: serde_json::Value = serde_json::from_str(&s).expect("error is JSON");
        assert_eq!(v["code"], "bad_request");
        assert_eq!(v["message"], "bad request");
    }

    // silences unused-import warnings for the `_state` / `_blinding_state`
    // references kept here for clarity in the token-flow helpers.
    #[allow(dead_code)]
    fn _keep_blinding_state_type(_: BlindingState) {}
}