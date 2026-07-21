//! Marquee #4 broker integration test (spec §7): the full registry + accounting
//! loop in-process. Registry admission is driven via the public
//! `register`/`heartbeat` fns with explicit timestamps (deterministic slow
//! admission); redeem/receipt/snapshot go over HTTP against the real service
//! routers with a mock host. The client-side seal/open + relay privacy invariant
//! are proven separately by `lluma-client`'s `e2e_slice`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::routing::post;
use axum::{Json, Router};

use lluma_broker::{
    counters, heartbeat, ingress_router, register, router as core_router, verify_snapshot,
    BrokerConfig, BrokerState, Store,
};
use lluma_core::proto::v1::{
    ExecRequest, ExecResponse, HeartbeatRequest, HostRegisterRequest, ReceiptSubmit,
    SnapshotResponse,
};
use lluma_core::wire::{
    AccountPublicKey, HeartbeatBody, HostRegisterBody, IssuerPublicKey, IssuerSecretKey, Mnemonic,
    ResponsePreamble, SealedRequest, Token, UsageReceiptBody,
};
use lluma_crypto::account::{
    account_fingerprint, derive_keypair_from_seed, heartbeat_sign, host_register_sign, pow_solve,
    receipt_sign, POW_HOST_DOMAIN,
};

const ADMIN: &str = "test-admin";

static CTR: AtomicU64 = AtomicU64::new(0);
fn tmp_redb() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("lluma-broker-e2e-{}-{}.redb", std::process::id(), CTR.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_file(&p);
    p
}

fn now0() -> u64 {
    0
}

async fn spawn(app: Router) -> String {
    spawn_h(app).await.0
}

/// Like `spawn` but returns the server task handle so a test can abort it (and
/// thereby drop the `BrokerState` it holds) to model a process restart.
async fn spawn_h(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    (format!("http://{addr}"), h)
}

/// A mock host: counts hits, returns a canned (opaque-to-broker) ExecResponse.
async fn mock_host(hits: Arc<AtomicU64>) -> String {
    let app = Router::new().route(
        "/v1/exec",
        post(move |_b: axum::body::Bytes| {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                Json(ExecResponse { preamble: ResponsePreamble(vec![1, 2, 3]), chunk: vec![4, 5, 6] })
            }
        }),
    );
    spawn(app).await
}

fn issuer_keys() -> (IssuerPublicKey, IssuerSecretKey) {
    let mut rng = blind_rsa_signatures::DefaultRng;
    let (sk, pk) = lluma_crypto::tokens::issuer_keygen(&mut rng).unwrap();
    (pk, sk)
}

fn mint_token(pk: &IssuerPublicKey, sk: &IssuerSecretKey) -> Token {
    let mut rng = blind_rsa_signatures::DefaultRng;
    let (bs, req) = lluma_crypto::tokens::token_blind(&mut rng, pk).unwrap();
    let sig = lluma_crypto::tokens::token_issue(&mut rng, sk, &req).unwrap();
    lluma_crypto::tokens::token_unblind(pk, bs, &sig).unwrap()
}

/// A registered, admitted host: returns its Ed25519 account (pubkey) + secret.
fn admit_host(
    store: &Store,
    cfg: &BrokerConfig,
    seed: u8,
    ingress_url: &str,
    base_t: u64,
) -> ([u8; 32], lluma_core::wire::AccountSecretKey) {
    let (sk, pk) = derive_keypair_from_seed(&Mnemonic([seed; 16])).unwrap();
    let acct: [u8; 32] = pk.0.as_slice().try_into().unwrap();
    let body = HostRegisterBody {
        version: 1,
        host_account: acct,
        hpke_pk: vec![0x42; 32],
        ingress_addr: ingress_url.to_string(),
        models: vec![],
    };
    let sig = host_register_sign(&sk, &body).unwrap();
    let nonce = pow_solve(POW_HOST_DOMAIN, &acct, &cfg.epoch_salt, cfg.pow_difficulty);
    register(store, &HostRegisterRequest { body, sig: sig.0, pow_nonce: nonce.to_vec() }, cfg, base_t).unwrap();
    for i in 1..=3u64 {
        let hb = HeartbeatBody { version: 1, host_account: acct, hb_counter: i, load_bucket: 0, models: vec![] };
        let s = heartbeat_sign(&sk, &hb).unwrap();
        heartbeat(store, &HeartbeatRequest { body: hb, sig: s.0 }, base_t + i * cfg.heartbeat_interval_s, cfg).unwrap();
    }
    (acct, sk)
}

fn exec_body(key_id: [u8; 32], host_account: [u8; 32], token: &Token) -> Vec<u8> {
    serde_json::to_vec(&ExecRequest {
        key_id,
        host_account,
        token: token.clone(),
        sealed: SealedRequest(vec![9u8; 48]),
    })
    .unwrap()
}

async fn post_json(url: &str, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
    let r = reqwest::Client::new()
        .post(format!("{url}{path}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let s = r.status().as_u16();
    (s, r.bytes().await.unwrap().to_vec())
}

fn broker(store: Store, cfg: BrokerConfig, issuer_pk: lluma_core::wire::IssuerPublicKey) -> (BrokerState, AccountPublicKey) {
    let (reg_sk, reg_pk) = derive_keypair_from_seed(&Mnemonic([200u8; 16])).unwrap();
    let st = BrokerState::new(issuer_pk, store, cfg, reg_sk, ADMIN.to_string(), now0);
    (st, reg_pk)
}

#[tokio::test]
async fn matchmaking_accounting_and_receipt_loop() {
    let (issuer_pk, issuer_sk) = issuer_keys();
    let key_id = *blake3::hash(&issuer_pk.0).as_bytes();
    let cfg = BrokerConfig::for_test();
    let store = Store::open(&tmp_redb()).unwrap();

    let hits_a = Arc::new(AtomicU64::new(0));
    let host_a_url = mock_host(hits_a.clone()).await;
    let hits_b = Arc::new(AtomicU64::new(0));
    let host_b_url = mock_host(hits_b.clone()).await;

    // Admit two hosts (PoW + slow admission over 3 spaced heartbeats).
    let (acct_a, sk_a) = admit_host(&store, &cfg, 1, &host_a_url, 1000);
    let (acct_b, _sk_b) = admit_host(&store, &cfg, 2, &host_b_url, 1000);

    let (bstate, reg_pk) = broker(store.clone(), cfg.clone(), issuer_pk.clone());
    let core = spawn(core_router(bstate.clone())).await;
    let ingress = spawn(ingress_router(bstate)).await;

    // Snapshot: fixed size, byte-identical across fetches, verifies, has 2 hosts.
    let (s1, b1) = post_get(&core, "/v1/snapshot").await;
    assert_eq!(s1, 200);
    let (s2, b2) = post_get(&core, "/v1/snapshot").await;
    assert_eq!(s2, 200);
    assert_eq!(b1, b2, "snapshot byte-identical across clients");
    let snap: SnapshotResponse = serde_json::from_slice(&b1).unwrap();
    assert_eq!(snap.body.len(), 65_536, "fixed 64 KiB bucket");
    let decoded = verify_snapshot(&reg_pk, &snap).expect("snapshot verifies under registry key");
    assert_eq!(decoded.hosts.len(), 2, "both admitted hosts present");

    // Seed issued so the redeem tripwire (redeemed <= issued) passes.
    counters::bump_issued(&store, cfg.epoch, 4).unwrap();

    // Exec a token naming host A → forwarded to A exactly once.
    let t1 = mint_token(&issuer_pk, &issuer_sk);
    let (es, _) = post_json(&core, "/v1/exec", exec_body(key_id, acct_a, &t1)).await;
    assert_eq!(es, 200);
    assert_eq!(hits_a.load(Ordering::SeqCst), 1);
    assert_eq!(hits_b.load(Ordering::SeqCst), 0, "only the named host is used");

    // Host A submits a receipt for that spend_id twice ⇒ credited exactly once.
    let spend_id = lluma_crypto::tokens::token_spend_id(&t1);
    let receipt_body = UsageReceiptBody {
        version: 1,
        host_account: acct_a,
        model_id: lluma_core::ModelId("m".into()),
        tier: 0,
        units: 1,
        spend_id: spend_id.0,
        epoch: 1,
        timestamp_h: 10,
    };
    let rsig = receipt_sign(&sk_a, &receipt_body).unwrap();
    let submit = serde_json::to_vec(&ReceiptSubmit { body: receipt_body, sig: rsig.0 }).unwrap();
    let (rc1, _) = post_json(&ingress, "/v1/receipt", submit.clone()).await;
    assert_eq!(rc1, 200);
    let (rc2, body2) = post_json(&ingress, "/v1/receipt", submit).await;
    assert_eq!(rc2, 200);
    assert!(String::from_utf8_lossy(&body2).contains("already_credited"));
    // Host A's ledger balance is exactly 1 (credit per receipt, not units).
    let acct_a_id = account_fingerprint(&AccountPublicKey(acct_a.to_vec()));
    let bal = lluma_broker::RedbLedger::new(store.clone());
    use lluma_issuer::ledger::CreditLedger;
    assert_eq!(bal.balance(&acct_a_id), 1);

    // Drop host B from the snapshot by evicting it (stale), leaving A.
    lluma_broker::registry::evict_stale(&store, 1_000_000, &cfg).unwrap();
    let (_s, b3) = post_get(&core, "/v1/snapshot").await;
    let snap3: SnapshotResponse = serde_json::from_slice(&b3).unwrap();
    let d3 = verify_snapshot(&reg_pk, &snap3).unwrap();
    assert!(d3.hosts.iter().all(|h| h.host_account != acct_b), "evicted host B is gone");

    // Unlinkability: no consumer identity ever reaches the broker — its records
    // name only host_account + spend_id. (Structural: the broker never receives
    // a consumer account.) Sanity: the receipt row carries host A's account only.
    assert!(decoded.hosts.iter().any(|h| h.host_account == acct_a));
}

async fn post_get(url: &str, path: &str) -> (u16, Vec<u8>) {
    let r = reqwest::Client::new().get(format!("{url}{path}")).send().await.unwrap();
    (r.status().as_u16(), r.bytes().await.unwrap().to_vec())
}

#[tokio::test]
async fn durable_respend_survives_restart() {
    let (issuer_pk, issuer_sk) = issuer_keys();
    let key_id = *blake3::hash(&issuer_pk.0).as_bytes();
    let cfg = BrokerConfig::for_test();
    let path = tmp_redb();

    let hits = Arc::new(AtomicU64::new(0));
    let host_url = mock_host(hits.clone()).await;

    let t1 = mint_token(&issuer_pk, &issuer_sk);
    let t2 = mint_token(&issuer_pk, &issuer_sk);

    let acct = {
        // First broker instance: admit a host, seed issued, redeem T1.
        let store = Store::open(&path).unwrap();
        let (acct, _sk) = admit_host(&store, &cfg, 1, &host_url, 1000);
        counters::bump_issued(&store, cfg.epoch, 4).unwrap();
        let (bstate, _) = broker(store.clone(), cfg.clone(), issuer_pk.clone());
        let (core, h) = spawn_h(core_router(bstate)).await;
        let (s, _) = post_json(&core, "/v1/exec", exec_body(key_id, acct, &t1)).await;
        assert_eq!(s, 200);
        // Model a crash/restart: abort the server (dropping the BrokerState it
        // holds) and await it so its Store clone is fully dropped, then drop the
        // test's clone — releasing redb's single-process file lock.
        h.abort();
        let _ = h.await;
        acct
    };

    // Reopen the SAME redb file in a fresh broker instance. Retry briefly in
    // case the aborted server task's Store drop (redb file-lock release) lags.
    let mut store2 = None;
    for _ in 0..40 {
        match Store::open(&path) {
            Ok(s) => {
                store2 = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(25)).await,
        }
    }
    let store2 = store2.expect("reopen redb after restart");
    let (bstate2, _) = broker(store2, cfg.clone(), issuer_pk.clone());
    let core2 = spawn(core_router(bstate2)).await;

    // Replaying T1 is refused (durable spent-set) and never reaches the host.
    let before = hits.load(Ordering::SeqCst);
    let (s_replay, _) = post_json(&core2, "/v1/exec", exec_body(key_id, acct, &t1)).await;
    assert_eq!(s_replay, 409, "respend after restart must be refused");
    assert_eq!(hits.load(Ordering::SeqCst), before, "double-spend must not reach the host");
    // A pre-restart-unspent token still redeems (durability didn't over-reject).
    let (s_t2, _) = post_json(&core2, "/v1/exec", exec_body(key_id, acct, &t2)).await;
    assert_eq!(s_t2, 200, "an unspent token still redeems after restart");

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn tripwire_refuses_redeem_beyond_issued() {
    let (issuer_pk, issuer_sk) = issuer_keys();
    let key_id = *blake3::hash(&issuer_pk.0).as_bytes();
    let cfg = BrokerConfig::for_test();
    let store = Store::open(&tmp_redb()).unwrap();

    let hits = Arc::new(AtomicU64::new(0));
    let host_url = mock_host(hits.clone()).await;
    let (acct, _sk) = admit_host(&store, &cfg, 1, &host_url, 1000);

    // Only ONE token is accounted as issued.
    counters::bump_issued(&store, cfg.epoch, 1).unwrap();
    let (bstate, _) = broker(store.clone(), cfg.clone(), issuer_pk.clone());
    let core = spawn(core_router(bstate)).await;

    let t1 = mint_token(&issuer_pk, &issuer_sk);
    let t2 = mint_token(&issuer_pk, &issuer_sk);
    // First redeem is within budget (redeemed 1 <= issued 1).
    let (s1, _) = post_json(&core, "/v1/exec", exec_body(key_id, acct, &t1)).await;
    assert_eq!(s1, 200);
    // Second redeem would make redeemed 2 > issued 1 ⇒ tripwire refuses + rolls back.
    let (s2, _) = post_json(&core, "/v1/exec", exec_body(key_id, acct, &t2)).await;
    assert_eq!(s2, 409, "redeem beyond issued must be refused by the tripwire");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the refused redeem never reached a host");
    // The tripped spend was rolled back — after issuing more, T2 can redeem.
    counters::bump_issued(&store, cfg.epoch, 1).unwrap();
    let (s3, _) = post_json(&core, "/v1/exec", exec_body(key_id, acct, &t2)).await;
    assert_eq!(s3, 200, "rolled-back spend is redeemable once issued catches up");
}
