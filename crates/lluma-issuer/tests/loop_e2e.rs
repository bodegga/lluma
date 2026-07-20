//! End-to-end token-issuance loop + unlinkability harness (Task 10).
//!
//! Spins the REAL axum service over a `TcpListener` on `127.0.0.1:0` and drives
//! it with the real `IssuerClient`/`RedeemClient` over a genuine HTTP wire. A
//! recording middleware plays the "malicious logging issuer": it captures the
//! raw request+response bytes of every `/v1/issue` and `/v1/redeem` so the
//! unlinkability sweeps inspect exactly what the issuer observed.
//!
//! ## Note on the byte-disjointness sweep (deviation from the brief, deliberate)
//!
//! The delegation brief framed the disjointness sweep over raw JSON transcripts
//! with a whitelist of {key_id, issuer pubkey}. That is not implementable as
//! written: the DTOs serialize `[u8;32]` fields (`key_id`, `account`, …) as
//! JSON *arrays of numbers*, and JSON field-names (`"key_id"` is 8 bytes) are
//! themselves ≥8-byte windows shared between the issue and redeem transcripts —
//! a raw-JSON sweep would fail on scaffolding, not on any privacy leak. The
//! meaningful, non-vacuous invariant is that the **cryptographic material** the
//! issuer sees at issue time (blinded messages, blind signatures, the account
//! key, request_id, batch hash) shares no bytes with the material it sees at
//! redeem time (tokens, spend_ids). We extract those typed fields and check
//! disjointness over them — which by construction excludes the public `key_id`
//! (legitimately present on both sides) without any whitelist hack.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use lluma_issuer::client::{IssuerClient, RedeemClient};
use lluma_issuer::idem::IssueIdempotencyCache;
use lluma_issuer::keys::{load_or_create, EpochKeys};
use lluma_issuer::ledger::{CreditLedger, InMemoryLedger};
use lluma_issuer::service::{self, AppState};
use lluma_issuer::spent_set::{InMemorySpentSet, SpentSet};
use lluma_issuer::IssuerError;

use lluma_core::proto::v1::{
    GrantRequest, IssueRequest, IssueResponse, KeyConfigResponse, RedeemRequest, RedeemResponse,
};
use lluma_core::wire::{
    AccountId, AccountPublicKey, AccountSecretKey, IssueRequestBody, Mnemonic, Token,
};

const ADMIN: &str = "test-admin-secret";

// ------------------------------------------------------------------ recorder

/// (path, request bytes, status, response bytes) for one /issue or /redeem call.
type Transcript = (String, Vec<u8>, u16, Vec<u8>);

#[derive(Clone)]
struct Recorder(Arc<Mutex<Vec<Transcript>>>);

impl Recorder {
    fn new() -> Self {
        Recorder(Arc::new(Mutex::new(Vec::new())))
    }
    fn dump(&self) -> Vec<Transcript> {
        self.0.lock().expect("recorder lock").clone()
    }
}

/// axum middleware: buffer request+response bodies, record the ones for the two
/// privacy-sensitive endpoints, and pass the bytes through unchanged.
async fn record(
    axum::extract::State(rec): axum::extract::State<Recorder>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let req_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    let req = axum::extract::Request::from_parts(parts, axum::body::Body::from(req_bytes.clone()));

    let res = next.run(req).await;
    let status = res.status().as_u16();
    let (rp, rbody) = res.into_parts();
    let resp_bytes = axum::body::to_bytes(rbody, usize::MAX)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();

    if path == "/v1/issue" || path == "/v1/redeem" {
        rec.0
            .lock()
            .expect("recorder lock")
            .push((path, req_bytes, status, resp_bytes.clone()));
    }
    axum::response::Response::from_parts(rp, axum::body::Body::from(resp_bytes))
}

// ------------------------------------------------------------------ scaffolding

fn real_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fresh_keys() -> EpochKeys {
    let mut rng = blind_rsa_signatures::DefaultRng;
    let (secret, public) = lluma_crypto::tokens::issuer_keygen(&mut rng).expect("issuer_keygen");
    EpochKeys {
        epoch: 1,
        secret,
        public,
    }
}

fn state_from_keys(keys: EpochKeys) -> AppState {
    AppState {
        keys: Arc::new(keys),
        ledger: Arc::new(InMemoryLedger::new()) as Arc<dyn CreditLedger>,
        spent: Arc::new(InMemorySpentSet::new()) as Arc<dyn SpentSet>,
        idem: Arc::new(IssueIdempotencyCache::new()),
        admin_secret: Arc::new(ADMIN.to_string()),
        now_unix_s: real_now,
    }
}

fn make_state() -> AppState {
    state_from_keys(fresh_keys())
}

/// Serve `state` with the recording middleware; return its base URL.
async fn spawn(state: AppState, rec: Recorder) -> String {
    let app =
        service::router(state).layer(axum::middleware::from_fn_with_state(rec, record));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn account(seed: u8) -> (AccountSecretKey, AccountPublicKey) {
    lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([seed; 16])).expect("derive keypair")
}

fn fingerprint(pk: &AccountPublicKey) -> AccountId {
    lluma_crypto::account::account_fingerprint(pk)
}

/// Seed credits via the real /v1/admin/grant endpoint (test scaffolding — a
/// throwaway client, NOT one of the client types under test).
async fn grant(base: &str, account_id: AccountId, amount: u64) {
    let body = serde_json::to_vec(&GrantRequest { account_id, amount }).expect("ser grant");
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/admin/grant"))
        .header("x-admin-secret", ADMIN)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("grant send");
    assert_eq!(resp.status(), 200, "admin/grant should succeed");
    let _ = resp.bytes().await;
}

/// POST a JSON value to `path`, returning (status, response bytes).
async fn post_json<T: serde::Serialize>(base: &str, path: &str, val: &T) -> (u16, Vec<u8>) {
    let body = serde_json::to_vec(val).expect("ser body");
    let resp = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post send");
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await.expect("read body").to_vec();
    (status, bytes)
}

/// Build a raw `IssueRequest` with a caller-chosen `request_id` and `ts` (for the
/// idempotency / replay tests, where the client's fresh-random request_id can't
/// be reused).
fn build_issue(
    kc: &KeyConfigResponse,
    sk: &AccountSecretKey,
    pk: &AccountPublicKey,
    count: usize,
    request_id: [u8; 32],
    ts_unix_s: u64,
) -> IssueRequest {
    let mut rng = blind_rsa_signatures::DefaultRng;
    let mut blinded = Vec::with_capacity(count);
    for _ in 0..count {
        let (_st, b) =
            lluma_crypto::tokens::token_blind(&mut rng, &kc.issuer_public_key).expect("blind");
        blinded.push(b);
    }
    let bh = *blake3::hash(&postcard::to_stdvec(&blinded).expect("postcard")).as_bytes();
    let account: [u8; 32] = pk.0.as_slice().try_into().expect("32-byte account pk");
    let body = IssueRequestBody {
        version: 1,
        account,
        key_id: kc.key_id,
        request_id,
        ts_unix_s,
        blinded_batch_hash: bh,
    };
    let auth_sig = lluma_crypto::account::issue_request_sign(sk, &body).expect("sign");
    IssueRequest {
        body,
        blinded,
        auth_sig,
    }
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

static KEY_PATH_CTR: AtomicU64 = AtomicU64::new(0);
fn unique_key_path() -> std::path::PathBuf {
    let n = KEY_PATH_CTR.fetch_add(1, Ordering::SeqCst);
    let mut p = std::env::temp_dir();
    p.push(format!("lluma-issuer-e2e-key-{}-{}.json", std::process::id(), n));
    let _ = std::fs::remove_file(&p);
    p
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn full_happy_loop() {
    let base = spawn(make_state(), Recorder::new()).await;
    let (sk, pk) = account(1);
    let id = fingerprint(&pk);
    grant(&base, id, 10).await;

    let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");
    let tokens = IssuerClient::new(&base)
        .request_tokens(&kc, &sk, &pk, 10)
        .await
        .expect("issue 10");
    assert_eq!(tokens.len(), 10);

    // Redeem via a SEPARATE client (its own reqwest::Client) — transport split.
    let redeem = RedeemClient::new(&base);
    for t in &tokens {
        redeem.redeem(kc.key_id, t.clone()).await.expect("redeem");
    }
}

#[tokio::test]
async fn unlinkability_two_account_interleaved() {
    let rec = Recorder::new();
    let base = spawn(make_state(), rec.clone()).await;

    let (ska, pka) = account(10);
    let (skb, pkb) = account(11);
    let ida = fingerprint(&pka);
    let idb = fingerprint(&pkb);
    grant(&base, ida, 5).await;
    grant(&base, idb, 5).await;

    let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");
    let ta = IssuerClient::new(&base)
        .request_tokens(&kc, &ska, &pka, 5)
        .await
        .expect("A issue");
    let tb = IssuerClient::new(&base)
        .request_tokens(&kc, &skb, &pkb, 5)
        .await
        .expect("B issue");

    // Deterministic shuffle: interleave A/B then reverse.
    let mut all: Vec<Token> = Vec::new();
    for i in 0..5 {
        all.push(ta[i].clone());
        all.push(tb[i].clone());
    }
    all.reverse();

    let redeem = RedeemClient::new(&base);
    let mut spend_ids = Vec::new();
    for t in &all {
        spend_ids.push(redeem.redeem(kc.key_id, t.clone()).await.expect("redeem"));
    }

    // ---- reconstruct the issuer's recorded view ----
    let logs = rec.dump();
    let issue: Vec<&Transcript> = logs.iter().filter(|(p, ..)| p == "/v1/issue").collect();
    let redeem_t: Vec<&Transcript> = logs.iter().filter(|(p, ..)| p == "/v1/redeem").collect();
    assert_eq!(issue.len(), 2, "two issue batches recorded");
    assert_eq!(redeem_t.len(), 10, "ten redeems recorded");

    // Issue-time cryptographic material the issuer saw.
    let mut issue_blobs: Vec<Vec<u8>> = Vec::new();
    let mut issue_auth_sigs: Vec<Vec<u8>> = Vec::new();
    for (_, reqb, _, respb) in &issue {
        let req: IssueRequest = serde_json::from_slice(reqb).expect("issue req");
        for b in &req.blinded {
            issue_blobs.push(b.0.clone());
        }
        issue_blobs.push(req.body.account.to_vec());
        issue_blobs.push(req.body.request_id.to_vec());
        issue_blobs.push(req.body.blinded_batch_hash.to_vec());
        issue_blobs.push(req.auth_sig.0.clone());
        issue_auth_sigs.push(req.auth_sig.0.clone());
        let resp: IssueResponse = serde_json::from_slice(respb).expect("issue resp");
        for s in &resp.signatures {
            issue_blobs.push(s.0.clone());
        }
    }

    // Redeem-time material.
    let mut redeem_blobs: Vec<Vec<u8>> = Vec::new();
    for (_, reqb, _, respb) in &redeem_t {
        let req: RedeemRequest = serde_json::from_slice(reqb).expect("redeem req");
        redeem_blobs.push(req.token.0.clone());
        let resp: RedeemResponse = serde_json::from_slice(respb).expect("redeem resp");
        redeem_blobs.push(resp.spend_id.0.to_vec());
    }

    // (A) Byte-disjointness over crypto material: no 8-byte window shared. (This
    // excludes key_id by construction — it is in neither blob set.)
    let mut issue_windows: HashSet<[u8; 8]> = HashSet::new();
    for blob in &issue_blobs {
        for w in blob.windows(8) {
            issue_windows.insert(w.try_into().expect("8"));
        }
    }
    // M-4: guard against a vacuous sweep if extraction silently broke.
    assert!(!issue_windows.is_empty(), "sweep A vacuous: no issue-side windows extracted");
    assert!(!redeem_blobs.is_empty(), "sweep A vacuous: no redeem-side blobs extracted");
    for blob in &redeem_blobs {
        for w in blob.windows(8) {
            let arr: [u8; 8] = w.try_into().expect("8");
            assert!(
                !issue_windows.contains(&arr),
                "redeem-side crypto material shares an 8-byte window with issue-side material — unlinkability regression"
            );
        }
    }

    // (B) Derivability: no redeemed spend_id is BLAKE3 of anything the issuer saw
    // at issue time (catches e.g. token == blind-sig unmodified).
    for sid in &spend_ids {
        for blob in &issue_blobs {
            assert_ne!(
                sid.0,
                *blake3::hash(blob).as_bytes(),
                "a spend_id equals BLAKE3 of an issue-time blob — token derivable from the issuer's view"
            );
        }
    }

    // (C) Structural (encoding-aware — Fable review I-2): the /redeem wire
    // objects must carry ONLY the protocol fields. A raw-byte search misses a
    // smuggled field (it would be a JSON int-array / base64), and the typed
    // sweeps (A)/(B) miss it too because serde drops unknown keys — so assert
    // the exact JSON key set of every /redeem request and response.
    use std::collections::BTreeSet;
    let want_req: BTreeSet<&str> = ["key_id", "token"].into_iter().collect();
    let want_resp: BTreeSet<&str> = ["spend_id"].into_iter().collect();
    for (_, reqb, status, respb) in &redeem_t {
        let rv: serde_json::Value = serde_json::from_slice(reqb).expect("redeem req json");
        let got: BTreeSet<&str> = rv
            .as_object()
            .expect("redeem req is a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(got, want_req, "redeem request must carry exactly {{key_id, token}}");
        if *status == 200 {
            let sv: serde_json::Value = serde_json::from_slice(respb).expect("redeem resp json");
            let gotr: BTreeSet<&str> = sv
                .as_object()
                .expect("redeem resp is a JSON object")
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(gotr, want_resp, "redeem response must carry exactly {{spend_id}}");
        }
    }

    // (C-raw) Belt-and-suspenders: also byte-scan redeem transcripts for raw
    // identity material (pubkey, account_id, auth_sig).
    let mut identity_needles: Vec<Vec<u8>> = vec![
        pka.0.clone(),
        pkb.0.clone(),
        ida.0.to_vec(),
        idb.0.to_vec(),
    ];
    identity_needles.extend(issue_auth_sigs);
    for (_, reqb, _, respb) in &redeem_t {
        for needle in &identity_needles {
            assert!(
                !contains_subslice(reqb, needle),
                "redeem request leaks issue-side identity bytes"
            );
            assert!(
                !contains_subslice(respb, needle),
                "redeem response leaks issue-side identity bytes"
            );
        }
    }
}

#[tokio::test]
async fn transport_separation_uses_distinct_clients() {
    // The issue side and redeem side use two DISTINCT client types, each owning
    // its own reqwest::Client (no shared connection pool that could link
    // issue↔redeem at the transport layer — spec §9). Enforced by construction:
    // there is no way to hand one client's pool to the other.
    let base = spawn(make_state(), Recorder::new()).await;
    let (sk, pk) = account(2);
    grant(&base, fingerprint(&pk), 1).await;
    let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");
    let tokens = IssuerClient::new(&base)
        .request_tokens(&kc, &sk, &pk, 1)
        .await
        .expect("issue");
    let spend_id = RedeemClient::new(&base)
        .redeem(kc.key_id, tokens[0].clone())
        .await
        .expect("redeem");
    assert_eq!(spend_id.0, lluma_crypto::tokens::token_spend_id(&tokens[0]).0);
}

#[tokio::test]
async fn double_spend_rejected() {
    let base = spawn(make_state(), Recorder::new()).await;
    let (sk, pk) = account(3);
    grant(&base, fingerprint(&pk), 1).await;
    let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");
    let tokens = IssuerClient::new(&base)
        .request_tokens(&kc, &sk, &pk, 1)
        .await
        .expect("issue");
    let redeem = RedeemClient::new(&base);
    redeem
        .redeem(kc.key_id, tokens[0].clone())
        .await
        .expect("first redeem Ok");
    let err = redeem
        .redeem(kc.key_id, tokens[0].clone())
        .await
        .expect_err("second redeem must fail");
    assert!(matches!(err, IssuerError::DoubleSpend));
}

#[tokio::test]
async fn balance_enforced() {
    let base = spawn(make_state(), Recorder::new()).await;
    let (sk, pk) = account(4);
    grant(&base, fingerprint(&pk), 2).await;
    let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");
    // Ask for 3 with only 2 credits → InsufficientCredits, all-or-nothing.
    let err = IssuerClient::new(&base)
        .request_tokens(&kc, &sk, &pk, 3)
        .await
        .expect_err("over-balance must fail");
    assert!(matches!(err, IssuerError::InsufficientCredits));
    // The 2 credits are untouched: a batch of 2 still succeeds.
    let ok = IssuerClient::new(&base)
        .request_tokens(&kc, &sk, &pk, 2)
        .await
        .expect("batch of 2 after a rejected 3");
    assert_eq!(ok.len(), 2);
}

#[tokio::test]
async fn idempotency_replay_conflict_and_staleness() {
    let state = make_state();
    let base = spawn(state.clone(), Recorder::new()).await;
    let (sk, pk) = account(5);
    let id = fingerprint(&pk);
    grant(&base, id, 10).await;
    let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");

    // Replay: same request_id + same batch → identical signatures, debit once.
    let req = build_issue(&kc, &sk, &pk, 3, [7u8; 32], real_now());
    let (s1, b1) = post_json(&base, "/v1/issue", &req).await;
    assert_eq!(s1, 200);
    let (s2, b2) = post_json(&base, "/v1/issue", &req).await;
    assert_eq!(s2, 200);
    let r1: IssueResponse = serde_json::from_slice(&b1).unwrap();
    let r2: IssueResponse = serde_json::from_slice(&b2).unwrap();
    let sigs1: Vec<&Vec<u8>> = r1.signatures.iter().map(|s| &s.0).collect();
    let sigs2: Vec<&Vec<u8>> = r2.signatures.iter().map(|s| &s.0).collect();
    assert_eq!(sigs1, sigs2, "replay must return identical signatures");
    assert_eq!(state.ledger.balance(&id), 7, "replay debits only once");

    // Same request_id, DIFFERENT batch → conflict.
    let req_conflict = build_issue(&kc, &sk, &pk, 3, [7u8; 32], real_now());
    let (s3, _) = post_json(&base, "/v1/issue", &req_conflict).await;
    assert_eq!(s3, 409, "request_id reuse with a different batch → conflict");

    // Stale timestamp → bad request (outside ±600 s).
    let req_stale = build_issue(&kc, &sk, &pk, 2, [8u8; 32], real_now() - 1000);
    let (s4, _) = post_json(&base, "/v1/issue", &req_stale).await;
    assert_eq!(s4, 422, "stale ts → bad request");
}

#[tokio::test]
async fn tamper_rejected() {
    let base = spawn(make_state(), Recorder::new()).await;
    let (sk, pk) = account(6);
    grant(&base, fingerprint(&pk), 1).await;
    let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");
    let mut token = IssuerClient::new(&base)
        .request_tokens(&kc, &sk, &pk, 1)
        .await
        .expect("issue")
        .remove(0);
    token.0[0] ^= 0xff; // flip a byte
    let err = RedeemClient::new(&base)
        .redeem(kc.key_id, token)
        .await
        .expect_err("tampered token must fail");
    assert!(matches!(err, IssuerError::TokenInvalid));
}

#[tokio::test]
async fn cross_key_isolation() {
    let base_a = spawn(make_state(), Recorder::new()).await;
    let base_b = spawn(make_state(), Recorder::new()).await; // different key
    let (sk, pk) = account(7);
    grant(&base_a, fingerprint(&pk), 1).await;
    let kc_a = IssuerClient::new(&base_a).fetch_key_config().await.expect("kc a");
    let token = IssuerClient::new(&base_a)
        .request_tokens(&kc_a, &sk, &pk, 1)
        .await
        .expect("issue")
        .remove(0);
    // Redeem A's token at B, presenting A's key_id (as a pinned client would).
    let err = RedeemClient::new(&base_b)
        .redeem(kc_a.key_id, token)
        .await
        .expect_err("A's token must not redeem at B");
    assert!(matches!(err, IssuerError::TokenInvalid));
}

#[tokio::test]
async fn key_config_integrity_identical_across_clients() {
    let base = spawn(make_state(), Recorder::new()).await;
    let kc1 = IssuerClient::new(&base).fetch_key_config().await.expect("kc1");
    let kc2 = IssuerClient::new(&base).fetch_key_config().await.expect("kc2");
    assert_eq!(kc1.key_id, kc2.key_id);
    assert_eq!(kc1.issuer_public_key.0, kc2.issuer_public_key.0);
    assert_eq!(kc1.epoch, kc2.epoch);
    assert_eq!(kc1.denomination, kc2.denomination);
    // The client already recomputed key_id == BLAKE3(pubkey) on fetch; re-assert.
    assert_eq!(kc1.key_id, *blake3::hash(&kc1.issuer_public_key.0).as_bytes());
}

#[tokio::test]
async fn error_bodies_are_l8_safe() {
    let base = spawn(make_state(), Recorder::new()).await;
    let (sk, pk) = account(8);
    grant(&base, fingerprint(&pk), 1).await;
    let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");
    let token = IssuerClient::new(&base)
        .request_tokens(&kc, &sk, &pk, 1)
        .await
        .expect("issue")
        .remove(0);

    // Double-spend 409: the error body must not echo the token bytes.
    let rr = RedeemRequest {
        key_id: kc.key_id,
        token: token.clone(),
    };
    let (s1, _) = post_json(&base, "/v1/redeem", &rr).await;
    assert_eq!(s1, 200);
    let (s2, b2) = post_json(&base, "/v1/redeem", &rr).await;
    assert_eq!(s2, 409);
    assert!(
        !contains_subslice(&b2, &token.0),
        "double-spend error body leaks token bytes (L8)"
    );

    // Unauthorized 403: bad auth_sig; body must not echo account or blinded bytes.
    let mut bad = build_issue(&kc, &sk, &pk, 1, [9u8; 32], real_now());
    bad.auth_sig.0[0] ^= 0xff;
    let (s3, b3) = post_json(&base, "/v1/issue", &bad).await;
    assert_eq!(s3, 403);
    assert!(
        !contains_subslice(&b3, &pk.0),
        "unauthorized error body leaks account pubkey (L8)"
    );
    for bl in &bad.blinded {
        assert!(
            !contains_subslice(&b3, &bl.0),
            "unauthorized error body leaks blinded message (L8)"
        );
    }
}

#[tokio::test]
async fn restart_respend_hole() {
    // Documents the #4 durable-spent-set blocker (spec §11): tokens survive an
    // issuer restart (the epoch key persists) AND the in-memory spent-set does
    // not, so an already-spent token becomes respendable after a restart. This
    // test asserts the hole so it is visible and tracked, not hidden.
    let path = unique_key_path();

    // ---- instance 1: issue + redeem a token ----
    let ek1 = load_or_create(&path, 1).expect("load_or_create 1");
    let base1 = spawn(state_from_keys(ek1), Recorder::new()).await;
    let (sk, pk) = account(20);
    grant(&base1, fingerprint(&pk), 1).await;
    let kc = IssuerClient::new(&base1).fetch_key_config().await.expect("kc");
    let token = IssuerClient::new(&base1)
        .request_tokens(&kc, &sk, &pk, 1)
        .await
        .expect("issue")
        .remove(0);
    RedeemClient::new(&base1)
        .redeem(kc.key_id, token.clone())
        .await
        .expect("first redeem Ok");

    // ---- "restart": a fresh instance from the SAME key path (same epoch key),
    // with a brand-new in-memory spent-set ----
    let ek2 = load_or_create(&path, 1).expect("load_or_create 2");
    // The reloaded key is byte-identical, so the token still verifies.
    assert_eq!(ek2.key_id(), kc.key_id, "reloaded epoch key must match");
    let base2 = spawn(state_from_keys(ek2), Recorder::new()).await;

    // The SAME token redeems AGAIN — the respend hole, demonstrated.
    RedeemClient::new(&base2)
        .redeem(kc.key_id, token)
        .await
        .expect("respend succeeds after restart — documents the #4 durable-spent-set blocker");

    // Cleanup temp key files.
    let _ = std::fs::remove_file(&path);
    let mut tmp = path.clone();
    tmp.set_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
}

#[tokio::test]
async fn concurrent_identical_issue_debits_once() {
    // Fable review I-1: two identical /issue requests fired concurrently must
    // debit the account exactly once (reserve-on-lookup). The idem.rs unit test
    // `concurrent_begins_yield_exactly_one_reserved` proves the primitive; this
    // corroborates it end-to-end over the wire.
    let state = make_state();
    let base = spawn(state.clone(), Recorder::new()).await;
    let (sk, pk) = account(9);
    let id = fingerprint(&pk);
    grant(&base, id, 10).await;
    let kc = IssuerClient::new(&base).fetch_key_config().await.expect("kc");

    let req = build_issue(&kc, &sk, &pk, 3, [42u8; 32], real_now());
    let (b1, b2) = (base.clone(), base.clone());
    let (r1, r2) = (req.clone(), req.clone());
    let (a, b) = tokio::join!(
        async move { post_json(&b1, "/v1/issue", &r1).await },
        async move { post_json(&b2, "/v1/issue", &r2).await },
    );

    // Debited exactly once regardless of interleaving: 10 - 3 = 7.
    assert_eq!(
        state.ledger.balance(&id),
        7,
        "concurrent identical /issue must debit only once"
    );
    let (s1, s2) = (a.0, b.0);
    assert!(s1 == 200 || s2 == 200, "at least one concurrent issue must succeed");
    for s in [s1, s2] {
        assert!(s == 200 || s == 503, "concurrent issue status must be 200 or 503, got {s}");
    }
}
