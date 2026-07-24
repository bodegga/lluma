//! Self-serve trial-credit slice: `Client::trial_register` solves the trial PoW
//! and registers over the relay→gateway→broker OHTTP path.
//!
//! Asserts both the functional contract (first claim grants; a second claim for
//! the same account hits the broker's UNIFORM refusal) and the privacy contract
//! that is the whole reason `/v1/register` rides the relay (leak L16): the
//! account pubkey is inside the OHTTP capsule, so the relay — the only party
//! that sees the originator IP — never sees `account_pk` in the clear.

use std::sync::{Arc, Mutex};

use axum::Router;
use tokio::net::TcpListener;

use lluma_broker::{router as broker_router, BrokerConfig, BrokerState, Store};
use lluma_client::Client;
use lluma_gateway::{router as gateway_router, GatewayConfig};

use lluma_core::wire::{HostPublicKey, Mnemonic};

// ---- minimal recorder (records the cleartext HTTP bytes each hop sees) ----
#[derive(Clone)]
struct Rec(Arc<Mutex<Vec<Vec<u8>>>>);
impl Rec {
    fn new() -> Self {
        Rec(Arc::new(Mutex::new(Vec::new())))
    }
    fn contains(&self, needle: &[u8]) -> bool {
        let g = self.0.lock().unwrap();
        g.iter().any(|b| win(b, needle))
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
    let bodyb = axum::body::to_bytes(body, usize::MAX).await.unwrap_or_default().to_vec();
    rec.0.lock().unwrap().push(bodyb.clone());
    let req = axum::extract::Request::from_parts(parts, axum::body::Body::from(bodyb));
    next.run(req).await
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
    p.push(format!("lluma-trial-{}-{}.redb", std::process::id(), C.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_file(&p);
    p
}

#[tokio::test]
async fn trial_register_grants_then_uniform_refusal_and_account_pk_stays_off_the_relay() {
    let mut orng = rand_core::OsRng;
    let mut brng = blind_rsa_signatures::DefaultRng;
    let (_issuer_sk, issuer_pk) = lluma_crypto::tokens::issuer_keygen(&mut brng).unwrap();
    let (gw_sk, gw_kc) = lluma_crypto::ohttp::ohttp_keygen(&mut orng, 1).unwrap();
    let (acct_sk, acct_pk) =
        lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([13u8; 16])).unwrap();
    // The trial body serializes `account: [u8;32]` as a JSON int-array, so the
    // needle is that exact serialized form (not the raw 32 bytes). It must never
    // appear in relay cleartext (it rides inside the OHTTP capsule).
    let acct_arr: [u8; 32] = acct_pk.0.as_slice().try_into().unwrap();
    let acct_needle = serde_json::to_vec(&acct_arr).unwrap();

    // ---- broker (core router carries /v1/register) over a shared durable store ----
    let store = Store::open(&tmp_redb()).unwrap();
    let cfg = BrokerConfig::for_test(); // low PoW difficulty; nonzero epoch_salt
    let (reg_key_sk, _reg_key_pk) =
        lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([11u8; 16])).unwrap();
    let broker_state = BrokerState::new(
        issuer_pk,
        store.clone(),
        cfg.clone(),
        reg_key_sk,
        "test-admin".to_string(),
        real_now,
    );

    let origin_rec = Rec::new();
    let origin_url = serve(wrap(broker_router(broker_state), &origin_rec)).await;

    // ---- gateway: allowlist /v1/register (mirrors the deployed prefix set) ----
    let gw = gateway_router(GatewayConfig {
        secret: gw_sk,
        origin_url: origin_url.clone(),
        allowed_path_prefixes: vec!["/v1/register".into()],
    });
    let gw_url = serve(wrap(gw, &Rec::new())).await;

    // ---- relay (records cleartext it forwards; this is the IP-seeing hop) ----
    let relay_rec = Rec::new();
    let relay = lluma_relay::router(lluma_relay::RelayConfig {
        gateway_url: gw_url,
        max_body_bytes: 64 * 1024,
        per_ip: lluma_relay::RateLimitConfig { capacity: 1000, refill_per_sec: 1000 },
        pow_difficulty: 0,
        bootstrap_blob: None,
    });
    let relay_url = serve_conninfo(wrap(relay, &relay_rec)).await;

    let client = Client::new(
        &relay_url,
        gw_kc,
        acct_sk,
        acct_pk,
        HostPublicKey(vec![0u8; 32]),
        [0u8; 32],
    );

    // First claim: granted.
    let first = client
        .trial_register(&cfg.epoch_salt, cfg.pow_difficulty)
        .await
        .expect("trial_register transport");
    assert!(first, "a brand-new account gets its one-time trial grant");

    // Second claim for the SAME account: the broker's uniform refusal (429) →
    // Ok(false), not an error.
    let second = client
        .trial_register(&cfg.epoch_salt, cfg.pow_difficulty)
        .await
        .expect("trial_register transport");
    assert!(!second, "a second claim is refused (AlreadyGranted, uniform 429)");

    // Privacy (leak L16): the account pubkey reaches the broker (positive control
    // — the gateway decapsulated the OHTTP capsule) but NEVER the relay in the
    // clear (it stayed inside the capsule the relay only ferried).
    assert!(
        origin_rec.contains(&acct_needle),
        "positive control: the broker receives account_pk (scanner works)"
    );
    assert!(
        !relay_rec.contains(&acct_needle),
        "account_pk must never appear in relay cleartext (leak L16)"
    );
}
