//! Marquee end-to-end slice (ADR-0003 / Fable's lean-path ruling): one
//! anonymous request reaches a (echo) model and returns, with no recorded party
//! view holding both the originator's connection and the plaintext.
//!
//! Topology (all in-process, ephemeral ports):
//!   client → relay → gateway → merged{issuer, broker} → host(echo)
//! Each party's router is wrapped in a recorder; the invariant matrix is checked
//! over the recorded bytes + the connection graph.

use std::sync::{Arc, Mutex};

use axum::Router;
use base64::Engine;
use tokio::net::TcpListener;

use lluma_broker::{
    counters, heartbeat, register, router as broker_router, BrokerConfig, BrokerState, Store,
};
use lluma_client::Client;
use lluma_gateway::{router as gateway_router, GatewayConfig};
use lluma_host::{router as host_router, EchoUpstream, HostState};
use lluma_issuer::idem::IssueIdempotencyCache;
use lluma_issuer::keys::EpochKeys;
use lluma_issuer::ledger::{CreditLedger, InMemoryLedger};
use lluma_issuer::service::{router as issuer_router, AppState};
use lluma_issuer::spent_set::{InMemorySpentSet, SpentSet};
use lluma_relay::{router as relay_router, RateLimitConfig, RelayConfig};

use lluma_core::proto::v1::{HeartbeatRequest, HostRegisterRequest};
use lluma_core::wire::{HeartbeatBody, HostRegisterBody, Mnemonic};
use lluma_crypto::account::{
    derive_keypair_from_seed, heartbeat_sign, host_register_sign, pow_solve, POW_HOST_DOMAIN,
};

const ADMIN: &str = "test-admin";
const PROMPT_SENTINEL: &[u8] = b"PROMPT-CANARY-3f9a2b7c1d";
const RESPONSE_SENTINEL: &[u8] = b"RESPONSE-CANARY-8e1d0c4a::";

// ---- recorder ----
type Transcript = (String, Vec<u8>, Vec<u8>);
#[derive(Clone)]
struct Rec(Arc<Mutex<Vec<Transcript>>>);
impl Rec {
    fn new() -> Self {
        Rec(Arc::new(Mutex::new(Vec::new())))
    }
    fn contains(&self, needle: &[u8]) -> bool {
        let g = self.0.lock().unwrap();
        g.iter().any(|(p, req, resp)| {
            win(p.as_bytes(), needle) || win(req, needle) || win(resp, needle)
        })
    }
    fn hits(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}
fn win(h: &[u8], n: &[u8]) -> bool {
    !n.is_empty() && n.len() <= h.len() && h.windows(n.len()).any(|w| w == n)
}

async fn record(
    axum::extract::State(rec): axum::extract::State<Rec>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let mut rb = Vec::new();
    for (k, v) in parts.headers.iter() {
        rb.extend_from_slice(k.as_str().as_bytes());
        rb.push(b':');
        rb.extend_from_slice(v.as_bytes());
    }
    let bodyb = axum::body::to_bytes(body, usize::MAX).await.unwrap_or_default().to_vec();
    rb.extend_from_slice(&bodyb);
    let req = axum::extract::Request::from_parts(parts, axum::body::Body::from(bodyb));
    let res = next.run(req).await;
    let (rp, rbody) = res.into_parts();
    let respb = axum::body::to_bytes(rbody, usize::MAX).await.unwrap_or_default().to_vec();
    rec.0.lock().unwrap().push((path, rb, respb.clone()));
    axum::response::Response::from_parts(rp, axum::body::Body::from(respb))
}
fn wrap(app: Router, rec: &Rec) -> Router {
    app.layer(axum::middleware::from_fn_with_state(rec.clone(), record))
}

fn real_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

async fn serve(app: Router) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { let _ = axum::serve(l, app).await; });
    format!("http://{addr}")
}
async fn serve_conninfo(app: Router) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(l, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await;
    });
    format!("http://{addr}")
}

fn tmp_redb() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    let mut p = std::env::temp_dir();
    p.push(format!("lluma-e2e-{}-{}.redb", std::process::id(), C.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_file(&p);
    p
}

#[tokio::test]
async fn anonymous_request_reaches_model_and_returns_invariant_holds() {
    // ---- keys shared across the topology ----
    let mut brng = blind_rsa_signatures::DefaultRng;
    let (issuer_sk, issuer_pk) = lluma_crypto::tokens::issuer_keygen(&mut brng).unwrap();
    let mut orng = rand_core::OsRng;
    let (host_sk, host_pk) = lluma_crypto::e2e::host_keygen(&mut orng).unwrap();
    let (gw_sk, gw_kc) = lluma_crypto::ohttp::ohttp_keygen(&mut orng, 1).unwrap();
    let (acct_sk, acct_pk) = lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([7u8; 16])).unwrap();
    let acct_id = lluma_crypto::account::account_fingerprint(&acct_pk);

    let (relay_rec, gw_rec, origin_rec, host_rec) = (Rec::new(), Rec::new(), Rec::new(), Rec::new());

    // ---- host ----
    let host_state = HostState {
        host_sk: Arc::new(host_sk),
        upstream: Arc::new(EchoUpstream { sentinel: RESPONSE_SENTINEL.to_vec() }),
    };
    let host_url = serve(wrap(host_router(host_state), &host_rec)).await;

    // ---- shared co-located store + broker config (issuer+broker on one DB, R6) ----
    let store = Store::open(&tmp_redb()).unwrap();
    let cfg = BrokerConfig::for_test(); // low PoW difficulty, loopback ingress ok
    // The serving host's Ed25519 ACCOUNT key (distinct from its HPKE `host_pk`).
    let (host_acct_sk, host_acct_pk) =
        lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([9u8; 16])).unwrap();
    let host_account: [u8; 32] = host_acct_pk.0.as_slice().try_into().unwrap();

    // ---- issuer app state; issued-counter wired to the co-located broker store
    // so the redeem tripwire (redeemed <= issued) sees issuance ----
    let store_obs = store.clone();
    let issuer_state = AppState {
        keys: Arc::new(EpochKeys { epoch: 1, secret: issuer_sk, public: issuer_pk.clone() }),
        ledger: Arc::new(InMemoryLedger::new()) as Arc<dyn CreditLedger>,
        spent: Arc::new(InMemorySpentSet::new()) as Arc<dyn SpentSet>,
        idem: Arc::new(IssueIdempotencyCache::new()),
        admin_secret: Arc::new(ADMIN.to_string()),
        now_unix_s: real_now,
        issued_observer: Some(Arc::new(move |epoch, n| {
            let _ = counters::bump_issued(&store_obs, epoch, n);
        })),
    };

    // ---- register + admit the serving host into the durable registry ----
    let reg_body = HostRegisterBody {
        version: 1,
        host_account,
        hpke_pk: host_pk.0.clone(),
        ingress_addr: host_url.clone(),
        models: vec![],
    };
    let reg_sig = host_register_sign(&host_acct_sk, &reg_body).unwrap();
    let nonce = pow_solve(POW_HOST_DOMAIN, &host_account, &cfg.epoch_salt, cfg.pow_difficulty);
    let reg = HostRegisterRequest { body: reg_body, sig: reg_sig.0, pow_nonce: nonce.to_vec() };
    register(&store, &reg, &cfg, 100).unwrap();
    for (c, t) in [(1u64, 130u64), (2, 160), (3, 190)] {
        let hb_body = HeartbeatBody {
            version: 1,
            host_account,
            hb_counter: c,
            load_bucket: 0,
            models: vec![],
        };
        let hb_sig = heartbeat_sign(&host_acct_sk, &hb_body).unwrap();
        heartbeat(&store, &HeartbeatRequest { body: hb_body, sig: hb_sig.0 }, t, &cfg).unwrap();
    }

    // ---- broker state (same issuer pk; the shared durable store; registry) ----
    let (reg_key_sk, _reg_key_pk) =
        derive_keypair_from_seed(&Mnemonic([11u8; 16])).unwrap();
    let broker_state = BrokerState::new(
        issuer_pk.clone(),
        store.clone(),
        cfg.clone(),
        reg_key_sk,
        ADMIN.to_string(),
        real_now,
    );

    // ---- merged origin (issuer + broker) behind one recorder ----
    let origin = Router::merge(issuer_router(issuer_state), broker_router(broker_state));
    let origin_url = serve(wrap(origin, &origin_rec)).await;

    // ---- gateway (origin = merged app; allowlist the three slice endpoints) ----
    let gw = gateway_router(GatewayConfig {
        secret: gw_sk,
        origin_url: origin_url.clone(),
        allowed_path_prefixes: vec![
            "/v1/key-config".into(),
            "/v1/issue".into(),
            "/v1/exec".into(),
        ],
    });
    let gw_url = serve(wrap(gw, &gw_rec)).await;

    // ---- relay ----
    let relay = relay_router(RelayConfig {
        gateway_url: gw_url,
        max_body_bytes: 64 * 1024,
        per_ip: RateLimitConfig { capacity: 1000, refill_per_sec: 1000 },
        pow_difficulty: 0,
        bootstrap_blob: None,
    });
    let relay_url = serve_conninfo(wrap(relay, &relay_rec)).await;

    // ---- grant credits (direct to origin/issuer — test setup) ----
    let grant = serde_json::to_vec(&lluma_core::proto::v1::GrantRequest { account_id: acct_id, amount: 5 }).unwrap();
    let gr = reqwest::Client::new()
        .post(format!("{origin_url}/v1/admin/grant"))
        .header("x-admin-secret", ADMIN)
        .header("content-type", "application/json")
        .body(grant)
        .send()
        .await
        .unwrap();
    assert_eq!(gr.status(), 200);

    // ---- the anonymous request ----
    let client = Client::new(&relay_url, gw_kc, acct_sk, acct_pk.clone(), host_pk, host_account);
    let kc = client.key_config().await.expect("key-config");
    let mut tokens = client.acquire(&kc, 2).await.expect("acquire");
    let token = tokens.remove(0);
    let answer = client.exec(&kc, token.clone(), PROMPT_SENTINEL).await.expect("exec");

    // Functional proof: the echo host decrypted the prompt and returned it.
    assert!(win(&answer, RESPONSE_SENTINEL), "answer must carry the response sentinel");
    assert!(win(&answer, PROMPT_SENTINEL), "answer must echo the prompt (host saw plaintext)");

    // Invariant matrix: no intermediary sees prompt or response plaintext.
    for (name, rec) in [("relay", &relay_rec), ("gateway", &gw_rec), ("origin", &origin_rec)] {
        assert!(!rec.contains(PROMPT_SENTINEL), "{name} must NOT see the prompt plaintext");
        assert!(!rec.contains(RESPONSE_SENTINEL), "{name} must NOT see the response plaintext");
    }
    // The host produced+sealed the response; its recorded HTTP bytes are the
    // sealed request in / sealed response out — neither sentinel appears in the
    // clear there either (decryption is internal to the handler).
    assert!(!host_rec.contains(RESPONSE_SENTINEL), "host wire bytes must be sealed (no response plaintext on the wire)");

    // Non-vacuity: recorders captured traffic, and a POSITIVE control proves the
    // scanner can see known cleartext (the origin genuinely receives the token
    // base64 in the ExecRequest body) — so the negative assertions above bite.
    assert!(relay_rec.hits() >= 3, "relay saw key-config + issue + exec");
    assert!(gw_rec.hits() >= 3, "gateway saw key-config + issue + exec");
    assert!(origin_rec.hits() >= 4, "origin saw grant + key-config + issue + exec");
    let tok_b64 = base64::engine::general_purpose::STANDARD
        .encode(&token.0)
        .into_bytes();
    assert!(origin_rec.contains(&tok_b64), "positive control: origin receives the token base64 (scanner works)");

    // Host negatives (non-vacuous given the positive control): the host never
    // receives the token, and its wire bytes are sealed (prompt only in-handler).
    assert!(!host_rec.contains(&tok_b64), "host must never receive the token");
    assert!(!host_rec.contains(PROMPT_SENTINEL), "host wire bytes are sealed");

    // Connection graph: the host's only inbound peer is the broker — the client
    // never reaches it. By construction the client holds only the relay URL and
    // the host URL lives only in the broker's directory. The host was hit once.
    assert_eq!(host_rec.hits(), 1, "host reached exactly once via the broker");

    // ---- replay: the same token must be refused AND never reach the host ----
    let replay = client.exec(&kc, token, PROMPT_SENTINEL).await;
    assert!(
        matches!(replay, Err(lluma_client::ClientError::Server(409))),
        "replayed token must be refused with 409 double_spend"
    );
    assert_eq!(host_rec.hits(), 1, "double-spend must not reach the host");
}
