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
use tokio::net::TcpListener;

use lluma_broker::{router as broker_router, BrokerState, HostEntry, RedbSpentSet, StaticHostDirectory, Store};
use lluma_client::Client;
use lluma_gateway::{router as gateway_router, GatewayConfig};
use lluma_host::{router as host_router, EchoUpstream, HostState};
use lluma_issuer::idem::IssueIdempotencyCache;
use lluma_issuer::keys::EpochKeys;
use lluma_issuer::ledger::{CreditLedger, InMemoryLedger};
use lluma_issuer::service::{router as issuer_router, AppState};
use lluma_issuer::spent_set::{InMemorySpentSet, SpentSet};
use lluma_relay::{router as relay_router, RateLimitConfig, RelayConfig};

use lluma_core::wire::{AccountId, Mnemonic};

const ADMIN: &str = "test-admin";
const PROMPT_SENTINEL: &[u8] = b"PROMPT-CANARY-3f9a2b7c1d";
const RESPONSE_SENTINEL: &[u8] = b"RESPONSE-CANARY-8e1d0c4a::";

// ---- recorder ----
#[derive(Clone)]
struct Rec(Arc<Mutex<Vec<(String, Vec<u8>, Vec<u8>)>>>);
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

    // ---- issuer app state (shares the issuer keypair) ----
    let issuer_state = AppState {
        keys: Arc::new(EpochKeys { epoch: 1, secret: issuer_sk, public: issuer_pk.clone() }),
        ledger: Arc::new(InMemoryLedger::new()) as Arc<dyn CreditLedger>,
        spent: Arc::new(InMemorySpentSet::new()) as Arc<dyn SpentSet>,
        idem: Arc::new(IssueIdempotencyCache::new()),
        admin_secret: Arc::new(ADMIN.to_string()),
        now_unix_s: real_now,
    };

    // ---- broker state (same issuer pk; durable spent-set; static host) ----
    let hosts = StaticHostDirectory::new(vec![HostEntry {
        host_account: AccountId([1; 32]),
        ingress_url: host_url.clone(),
        host_pk: host_pk.clone(),
    }]);
    let broker_state = BrokerState::new(
        issuer_pk.clone(),
        Arc::new(RedbSpentSet::new(Store::open(&tmp_redb()).unwrap(), 1)),
        hosts,
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
    let client = Client::new(&relay_url, gw_kc, acct_sk, acct_pk.clone(), host_pk);
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

    // Connection graph: the host's only inbound peer is the broker — the client
    // never reaches it. By construction the client holds only the relay URL and
    // the host URL lives only in the broker's directory. The host was hit once.
    assert_eq!(host_rec.hits(), 1, "host reached exactly once via the broker");

    // ---- replay: the same token must be refused AND never reach the host ----
    let replay = client.exec(&kc, token, PROMPT_SENTINEL).await;
    assert!(replay.is_err(), "replayed token must be rejected");
    assert_eq!(host_rec.hits(), 1, "double-spend must not reach the host");
}
