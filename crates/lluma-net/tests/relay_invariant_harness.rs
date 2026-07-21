//! Marquee integration harness for Phase-1 #3 (spec §6): prove that routing
//! issuance+redemption through relay → gateway → issuer keeps the invariant —
//! the relay sees the client's IP-stand-in but no content; the gateway/issuer
//! see content but never the client's IP-stand-in.
//!
//! Everything runs in-process on ephemeral ports. Each service's router is
//! wrapped in a recording middleware (the "malicious logging party") capturing
//! raw request/response bytes, and the sweeps run over those recorded views.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use tokio::net::TcpListener;

use lluma_core::proto::v1::{IssueRequest, IssueResponse, KeyConfigResponse, RedeemResponse};
use lluma_core::wire::{
    AccountPublicKey, AccountSecretKey, IssueRequestBody, Mnemonic, OhttpKeyConfig, Token,
};

use lluma_gateway::{router as gateway_router, GatewayConfig};
use lluma_issuer::idem::IssueIdempotencyCache;
use lluma_issuer::keys::EpochKeys;
use lluma_issuer::ledger::{CreditLedger, InMemoryLedger};
use lluma_issuer::service::{router as issuer_router, AppState};
use lluma_issuer::spent_set::{InMemorySpentSet, SpentSet};
use lluma_net::{InnerRequest, OhttpAgent};
use lluma_relay::{router as relay_router, RateLimitConfig, RelayConfig};

const ADMIN: &str = "test-admin";

// ---------------- recording middleware ----------------

type Transcript = (String, Vec<u8>, u16, Vec<u8>);

#[derive(Clone)]
struct Rec(Arc<Mutex<Vec<Transcript>>>);
impl Rec {
    fn new() -> Self {
        Rec(Arc::new(Mutex::new(Vec::new())))
    }
    /// True if any recorded request/response byte buffer contains `needle`.
    fn contains(&self, needle: &[u8]) -> bool {
        let g = self.0.lock().unwrap();
        g.iter().any(|(path, req, _, resp)| {
            win_contains(path.as_bytes(), needle)
                || win_contains(req, needle)
                || win_contains(resp, needle)
        })
    }
}

fn win_contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

async fn record(
    axum::extract::State(rec): axum::extract::State<Rec>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    // Capture headers too (the originator-IP-stand-in is a header), then body.
    let mut rb = Vec::new();
    for (k, v) in parts.headers.iter() {
        rb.extend_from_slice(k.as_str().as_bytes());
        rb.extend_from_slice(b": ");
        rb.extend_from_slice(v.as_bytes());
        rb.push(b'\n');
    }
    let bodyb = axum::body::to_bytes(body, usize::MAX).await.unwrap_or_default().to_vec();
    rb.extend_from_slice(&bodyb);
    let req = axum::extract::Request::from_parts(parts, axum::body::Body::from(bodyb));
    let res = next.run(req).await;
    let status = res.status().as_u16();
    let (rp, rbody) = res.into_parts();
    let respb = axum::body::to_bytes(rbody, usize::MAX).await.unwrap_or_default().to_vec();
    rec.0.lock().unwrap().push((path, rb, status, respb.clone()));
    axum::response::Response::from_parts(rp, axum::body::Body::from(respb))
}

fn wrap(app: Router, rec: &Rec) -> Router {
    app.layer(axum::middleware::from_fn_with_state(rec.clone(), record))
}

// ---------------- service construction ----------------

fn real_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn issuer_state() -> AppState {
    let mut rng = blind_rsa_signatures::DefaultRng;
    let (secret, public) = lluma_crypto::tokens::issuer_keygen(&mut rng).unwrap();
    AppState {
        keys: Arc::new(EpochKeys { epoch: 1, secret, public }),
        ledger: Arc::new(InMemoryLedger::new()) as Arc<dyn CreditLedger>,
        spent: Arc::new(InMemorySpentSet::new()) as Arc<dyn SpentSet>,
        idem: Arc::new(IssueIdempotencyCache::new()),
        admin_secret: Arc::new(ADMIN.to_string()),
        now_unix_s: real_now,
        issued_observer: None,
    }
}

async fn serve(app: Router) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { let _ = axum::serve(l, app).await; });
    format!("http://{addr}")
}

async fn serve_with_conninfo(app: Router) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });
    format!("http://{addr}")
}

struct Chain {
    relay_url: String,
    key_config: OhttpKeyConfig,
    issuer_url: String,
    relay_rec: Rec,
    gateway_rec: Rec,
    issuer_rec: Rec,
}

/// Bring up issuer ← gateway ← relay, each behind a recorder. Gateway allows only
/// the three real issuer endpoints (so /v1/admin/grant is a genuine SSRF probe).
async fn bring_up() -> Chain {
    let (relay_rec, gateway_rec, issuer_rec) = (Rec::new(), Rec::new(), Rec::new());

    let issuer_url = serve(wrap(issuer_router(issuer_state()), &issuer_rec)).await;

    let mut rng = rand_core::OsRng;
    let (secret, key_config) = lluma_crypto::ohttp::ohttp_keygen(&mut rng, 1).unwrap();
    let gw = gateway_router(GatewayConfig {
        secret,
        origin_url: issuer_url.clone(),
        allowed_path_prefixes: vec![
            "/v1/issue".into(),
            "/v1/redeem".into(),
            "/v1/key-config".into(),
        ],
    });
    let gateway_url = serve(wrap(gw, &gateway_rec)).await;

    let relay = relay_router(RelayConfig {
        gateway_url,
        max_body_bytes: 64 * 1024,
        per_ip: RateLimitConfig { capacity: 1000, refill_per_sec: 1000 },
        pow_difficulty: 0,
        bootstrap_blob: None,
    });
    let relay_url = serve_with_conninfo(wrap(relay, &relay_rec)).await;

    Chain { relay_url, key_config, issuer_url, relay_rec, gateway_rec, issuer_rec }
}

// ---------------- client-side issuer helpers (over OHTTP) ----------------

fn account(seed: u8) -> (AccountSecretKey, AccountPublicKey) {
    lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([seed; 16])).unwrap()
}

async fn grant_direct(issuer_url: &str, pk: &AccountPublicKey, amount: u64) {
    let id = lluma_crypto::account::account_fingerprint(pk);
    let body = serde_json::to_vec(&lluma_core::proto::v1::GrantRequest { account_id: id, amount }).unwrap();
    let resp = reqwest::Client::new()
        .post(format!("{issuer_url}/v1/admin/grant"))
        .header("x-admin-secret", ADMIN)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

/// Issue `count` tokens by routing GET /v1/key-config + POST /v1/issue through
/// the OHTTP chain, then unblinding locally.
async fn issue_via_ohttp(
    agent: &OhttpAgent,
    sk: &AccountSecretKey,
    pk: &AccountPublicKey,
    count: usize,
) -> (KeyConfigResponse, Vec<Token>) {
    let kc_resp = agent
        .round_trip(InnerRequest {
            method: "GET".into(),
            path: "/v1/key-config".into(),
            content_type: None,
            body: Vec::new(),
        })
        .await
        .expect("key-config round-trip");
    assert_eq!(kc_resp.status, 200);
    let kc: KeyConfigResponse = serde_json::from_slice(&kc_resp.body).unwrap();

    let mut rng = blind_rsa_signatures::DefaultRng;
    let mut states = Vec::new();
    let mut blinded = Vec::new();
    for _ in 0..count {
        let (st, b) = lluma_crypto::tokens::token_blind(&mut rng, &kc.issuer_public_key).unwrap();
        states.push(st);
        blinded.push(b);
    }
    let batch_hash = *blake3::hash(&postcard::to_stdvec(&blinded).unwrap()).as_bytes();
    let mut request_id = [0u8; 32];
    rng.fill_bytes(&mut request_id);
    let account: [u8; 32] = pk.0.as_slice().try_into().unwrap();
    let body = IssueRequestBody {
        version: 1,
        account,
        key_id: kc.key_id,
        request_id,
        ts_unix_s: real_now(),
        blinded_batch_hash: batch_hash,
    };
    let auth_sig = lluma_crypto::account::issue_request_sign(sk, &body).unwrap();
    let req = IssueRequest { body, blinded, auth_sig };
    let json = serde_json::to_vec(&req).unwrap();

    let resp = agent
        .round_trip(InnerRequest {
            method: "POST".into(),
            path: "/v1/issue".into(),
            content_type: Some("application/json".into()),
            body: json,
        })
        .await
        .expect("issue round-trip");
    assert_eq!(resp.status, 200, "issue should succeed through the chain");
    let ir: IssueResponse = serde_json::from_slice(&resp.body).unwrap();
    let tokens: Vec<Token> = states
        .into_iter()
        .zip(ir.signatures.iter())
        .map(|(st, sig)| lluma_crypto::tokens::token_unblind(&kc.issuer_public_key, st, sig).unwrap())
        .collect();
    (kc, tokens)
}

use blind_rsa_signatures::reexports::rand::Rng;

// ---------------- tests ----------------

#[tokio::test]
async fn relay_never_sees_content_gateway_and_issuer_do() {
    let c = bring_up().await;
    let (sk, pk) = account(1);
    grant_direct(&c.issuer_url, &pk, 5).await;
    let agent = OhttpAgent::new(&c.relay_url, c.key_config.clone());

    let (_kc, tokens) = issue_via_ohttp(&agent, &sk, &pk, 3).await;

    // Redeem one token through the chain.
    let rr = serde_json::to_vec(&lluma_core::proto::v1::RedeemRequest {
        key_id: _kc.key_id,
        token: tokens[0].clone(),
    })
    .unwrap();
    let resp = agent
        .round_trip(InnerRequest {
            method: "POST".into(),
            path: "/v1/redeem".into(),
            content_type: Some("application/json".into()),
            body: rr,
        })
        .await
        .expect("redeem round-trip");
    assert_eq!(resp.status, 200);
    let _sid: RedeemResponse = serde_json::from_slice(&resp.body).unwrap();

    // Relay must have seen NONE of the content: token bytes, account pubkey,
    // or the inner paths (all are inside the OHTTP ciphertext).
    assert!(!c.relay_rec.contains(&tokens[0].0), "relay saw a token");
    assert!(!c.relay_rec.contains(&pk.0), "relay saw the account pubkey");
    assert!(!c.relay_rec.contains(b"/v1/issue"), "relay saw the inner issue path");
    assert!(!c.relay_rec.contains(b"/v1/redeem"), "relay saw the inner redeem path");

    // Content WAS decrypted downstream of the relay: the issuer received the
    // inner request in plaintext (path + account identity at issue time). The
    // gateway's HTTP-layer view is only ciphertext (it decrypts internally), so
    // the plaintext proof lives at the origin.
    assert!(c.issuer_rec.contains(b"/v1/issue"), "issuer should receive the decrypted inner path");
    assert!(c.issuer_rec.contains(b"/v1/redeem"), "issuer should receive the decrypted redeem path");
    // (The issuer also sees the account identity at issue time — allowed — but it
    // is JSON int-array-encoded on the wire, so a raw-byte scan is not the tool
    // for that; the relay-absence + issuer-path-presence assertions are the proof.)
}

#[tokio::test]
async fn relay_strips_client_marker_gateway_and_issuer_never_see_it() {
    // CLIENT_MARKER stands in for the originator IP (identical on loopback).
    // The client sends it ONLY on the outer request to the relay; the relay must
    // strip it, so neither the gateway nor the issuer ever observe it.
    let c = bring_up().await;
    const MARKER: &[u8] = b"ORIGINATOR-IP-CANARY-8f3a1c";

    // Craft a valid capsule for GET /v1/key-config directly (OhttpAgent doesn't
    // expose custom headers), then POST it to the relay WITH the marker header.
    let msg = bhttp::Message::request(b"GET".to_vec(), b"https".to_vec(), Vec::new(), b"/v1/key-config".to_vec());
    let mut inner = Vec::new();
    msg.write_bhttp(bhttp::Mode::KnownLength, &mut inner).unwrap();
    let mut rng = rand_core::OsRng;
    let (capsule, _ctx) = lluma_crypto::ohttp::ohttp_encapsulate(&mut rng, &c.key_config, &inner).unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/ohttp", c.relay_url))
        .header("content-type", "message/ohttp-req")
        .header("x-client-marker", std::str::from_utf8(MARKER).unwrap())
        .body(capsule.0)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "key-config through the chain should succeed");
    let _ = resp.bytes().await;

    assert!(c.relay_rec.contains(MARKER), "relay should observe the client marker");
    assert!(!c.gateway_rec.contains(MARKER), "gateway must NOT see the client marker (relay stripped it)");
    assert!(!c.issuer_rec.contains(MARKER), "issuer must NOT see the client marker (IP-blind)");
}

#[tokio::test]
async fn gateway_ssrf_guard_blocks_disallowed_path_before_origin() {
    let c = bring_up().await;
    let agent = OhttpAgent::new(&c.relay_url, c.key_config.clone());
    // /v1/admin/grant is NOT in the gateway allowlist → rejected before origin.
    let out = agent
        .round_trip(InnerRequest {
            method: "POST".into(),
            path: "/v1/admin/grant".into(),
            content_type: Some("application/json".into()),
            body: b"{\"account_id\":[0],\"amount\":9}".to_vec(),
        })
        .await;
    // Gateway returns a bare non-sealed error → client sees a relay/transport error.
    assert!(out.is_err(), "disallowed path must not produce a sealed response");
    // The issuer must never have seen the admin path.
    assert!(!c.issuer_rec.contains(b"/v1/admin/grant"), "gateway leaked a disallowed path to origin");
}
