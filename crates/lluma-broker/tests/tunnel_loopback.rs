//! End-to-end loopback for the reverse tunnel (spec §Track 1 correctness gate):
//! a real `lluma-host` tunnel client WS-connects to an in-process broker,
//! authenticates, the broker pushes a sealed `Job` down the socket, the host
//! serves it, and the client opens the sealed response. Mirrors the existing
//! dial-in serving round-trip, but over the tunnel. Also asserts the auth
//! handshake rejects a host that binds the wrong `broker_key_id`, that an
//! unregistered account cannot bind a socket (review C1), and that a reconnect
//! replaces the prior socket (generation swap, review M6).

use std::sync::Arc;
use std::time::Duration;

use lluma_broker::config::BrokerConfig;
use lluma_broker::service::{ingress_router, BrokerState};
use lluma_broker::tunnel::{dispatch, reserve_tunnel, Reservation, TUNNEL_SENTINEL_ADDR};
use lluma_broker::{register, Store};
use lluma_core::proto::v1::HostRegisterRequest;
use lluma_core::wire::{AccountSecretKey, HostRegisterBody, IssuerPublicKey, Mnemonic, SpendId};
use lluma_core::ModelId;
use lluma_crypto::account::{host_register_sign, pow_solve, POW_HOST_DOMAIN};
use lluma_host::tunnel::{serve_once, TunnelConfig};
use lluma_host::EchoUpstream;

fn now() -> u64 {
    100
}

fn tmp_db() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("lluma-tunnel-test-{}-{}.redb", std::process::id(), n));
    let _ = std::fs::remove_file(&p);
    p
}

/// Build a broker state (returning its registry pk + config) and serve its
/// ingress router (which carries the ws endpoint) on a fresh TCP port.
async fn spawn_broker() -> (BrokerState, [u8; 32], BrokerConfig, String) {
    let (registry_sk, registry_pk) =
        lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([11u8; 16])).unwrap();
    let registry_pk32: [u8; 32] = registry_pk.0.as_slice().try_into().unwrap();

    let cfg = BrokerConfig::for_test(); // low PoW difficulty + loopback ingress
    let store = Store::open(&tmp_db()).unwrap();
    let st = BrokerState::new(
        IssuerPublicKey(vec![7u8; 32]), // unused on the tunnel path
        store,
        cfg.clone(),
        registry_sk,
        "admin-secret".into(),
        now,
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = ingress_router(st.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (st, registry_pk32, cfg, format!("ws://{addr}/v1/host/tunnel"))
}

/// PoW-register `host_account` in the store (tunnel-mode: sentinel ingress), so
/// the handshake's C1 authorization check passes.
fn register_host(st: &BrokerState, cfg: &BrokerConfig, account_sk: &AccountSecretKey, host_account: [u8; 32]) {
    let body = HostRegisterBody {
        version: 1,
        host_account,
        hpke_pk: vec![0x42; 32],
        ingress_addr: TUNNEL_SENTINEL_ADDR.into(),
        models: vec![ModelId("m".into())],
    };
    let sig = host_register_sign(account_sk, &body).unwrap();
    let nonce = pow_solve(POW_HOST_DOMAIN, &host_account, &cfg.epoch_salt, cfg.pow_difficulty);
    let req = HostRegisterRequest { body, sig: sig.0, pow_nonce: nonce.to_vec() };
    register(&st.store, &req, cfg, now()).unwrap();
}

/// Wait until the tunnel registry holds exactly `n` sockets, or time out.
async fn await_sockets(st: &BrokerState, n: usize) -> bool {
    for _ in 0..100 {
        if st.tunnels.socket_count() == n {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    st.tunnels.socket_count() == n
}

fn host_keys(seed: u8) -> ([u8; 32], AccountSecretKey) {
    let (sk, pk) = lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([seed; 16])).unwrap();
    let acct: [u8; 32] = pk.0.as_slice().try_into().unwrap();
    (acct, sk)
}

#[tokio::test]
async fn tunnel_push_serve_open_roundtrip() {
    let (st, registry_pk32, cfg, url) = spawn_broker().await;
    let (host_account, account_sk) = host_keys(22);
    register_host(&st, &cfg, &account_sk, host_account);

    let mut rng = rand_core::OsRng;
    let (host_hpke_sk, host_hpke_pk) = lluma_crypto::e2e::host_keygen(&mut rng).unwrap();

    let tcfg = TunnelConfig { url, host_account, account_sk, broker_key_id: registry_pk32 };
    let host_sk = Arc::new(host_hpke_sk);
    let upstream = Arc::new(EchoUpstream { sentinel: b"A:".to_vec() });
    let serve = tokio::spawn(async move { serve_once(&tcfg, host_sk, upstream).await });

    assert!(await_sockets(&st, 1).await, "registered host should bind a socket after auth");

    // Client seals a prompt to the host HPKE key (aad = spend_id).
    let (sess_sk, sess_pk) = lluma_crypto::e2e::session_keygen(&mut rng).unwrap();
    let spend_id = SpendId([5u8; 32]);
    let prompt = b"ping over the tunnel";
    let sealed =
        lluma_crypto::e2e::e2e_seal(&mut rng, &host_hpke_pk, &spend_id.0, prompt, &sess_pk).unwrap();

    // Broker-side: reserve capacity (as exec does before the spend), then push.
    let guard = match reserve_tunnel(&st.tunnels, &host_account) {
        Reservation::Reserved(g) => g,
        _ => panic!("expected a reservable tunnel socket"),
    };
    let resp = dispatch(&guard, spend_id, sealed).await.expect("dispatch should succeed");

    // Client opens the sealed response.
    let mut cctx = lluma_crypto::e2e::response_setup_client(&sess_sk, &resp.preamble).unwrap();
    let (answer, is_final) = lluma_crypto::e2e::response_open_chunk(&mut cctx, &resp.chunk).unwrap();
    assert!(is_final);
    assert_eq!(answer, b"A:ping over the tunnel".to_vec());

    serve.abort();
}

#[tokio::test]
async fn tunnel_auth_rejects_wrong_broker_key_id() {
    let (st, _registry_pk32, cfg, url) = spawn_broker().await;
    let (host_account, account_sk) = host_keys(33);
    register_host(&st, &cfg, &account_sk, host_account); // registered, so only the key is wrong

    let mut rng = rand_core::OsRng;
    let (host_hpke_sk, _pk) = lluma_crypto::e2e::host_keygen(&mut rng).unwrap();

    // WRONG broker_key_id ⇒ the signature won't verify ⇒ no socket may register.
    let tcfg = TunnelConfig { url, host_account, account_sk, broker_key_id: [0xEE; 32] };
    let host_sk = Arc::new(host_hpke_sk);
    let upstream = Arc::new(EchoUpstream { sentinel: b"A:".to_vec() });
    let serve = tokio::spawn(async move { serve_once(&tcfg, host_sk, upstream).await });

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(st.tunnels.socket_count(), 0, "a bad-auth host must not register");
    serve.abort();
}

#[tokio::test]
async fn tunnel_rejects_unregistered_account() {
    // Review C1: a valid signature from an UNREGISTERED account must not bind a
    // socket (else throwaway keys could exhaust the socket table).
    let (st, registry_pk32, _cfg, url) = spawn_broker().await;
    let (host_account, account_sk) = host_keys(44); // NOT registered

    let mut rng = rand_core::OsRng;
    let (host_hpke_sk, _pk) = lluma_crypto::e2e::host_keygen(&mut rng).unwrap();
    let tcfg = TunnelConfig { url, host_account, account_sk, broker_key_id: registry_pk32 };
    let host_sk = Arc::new(host_hpke_sk);
    let upstream = Arc::new(EchoUpstream { sentinel: b"A:".to_vec() });
    let serve = tokio::spawn(async move { serve_once(&tcfg, host_sk, upstream).await });

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(st.tunnels.socket_count(), 0, "an unregistered account must not bind a socket");
    serve.abort();
}

#[tokio::test]
async fn tunnel_reconnect_replaces_socket() {
    // Review M6: a second connection for the same account replaces the first;
    // the registry never accumulates duplicate sockets.
    let (st, registry_pk32, cfg, url) = spawn_broker().await;
    let (host_account, account_sk) = host_keys(55);
    register_host(&st, &cfg, &account_sk, host_account);

    let mut rng = rand_core::OsRng;
    let (host_sk1, _pk1) = lluma_crypto::e2e::host_keygen(&mut rng).unwrap();
    let (host_sk2, _pk2) = lluma_crypto::e2e::host_keygen(&mut rng).unwrap();

    let mk = |sk| {
        let tcfg = TunnelConfig {
            url: url.clone(),
            host_account,
            account_sk: account_sk.clone(),
            broker_key_id: registry_pk32,
        };
        let up = Arc::new(EchoUpstream { sentinel: b"A:".to_vec() });
        tokio::spawn(async move { serve_once(&tcfg, Arc::new(sk), up).await })
    };

    let first = mk(host_sk1);
    assert!(await_sockets(&st, 1).await, "first socket should register");
    let second = mk(host_sk2);
    // The count must settle back to exactly 1 (replacement, not accumulation).
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(st.tunnels.socket_count(), 1, "reconnect must replace, not accumulate");

    first.abort();
    second.abort();
}
