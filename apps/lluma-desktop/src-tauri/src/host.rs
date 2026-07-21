//! Host (contribute) role: serve sealed inference through a chosen upstream,
//! persist the host HPKE key, and — when operator params are configured —
//! register + heartbeat to the broker so it forwards work.
//!
//! Scope (see the design spec): the *serving crypto path* is exercised locally
//! by a loopback round-trip test. Real broker admission additionally needs the
//! host to be reachable at its `ingress_addr` and the operator to supply the
//! epoch salt + PoW difficulty (not yet published). Credit *earning* via usage
//! receipts is a documented follow-up.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use lluma_core::wire::{HostPublicKey, HostSecretKey, KeystoreBlob};
use lluma_host::{EchoUpstream, HostState, OpenAiUpstream, Upstream};

use crate::types::{HostConfig, HostStatus, UpstreamKind};

/// Select the upstream model implementation from the host config.
pub fn select_upstream(cfg: &HostConfig) -> Result<Arc<dyn Upstream>, String> {
    match cfg.upstream {
        UpstreamKind::Echo => Ok(Arc::new(EchoUpstream { sentinel: b"[lluma-echo] ".to_vec() })),
        UpstreamKind::OpenAi => {
            if cfg.openai_base.trim().is_empty() {
                return Err("OpenAI upstream needs a base URL (e.g. http://localhost:11434/v1)".into());
            }
            Ok(Arc::new(OpenAiUpstream::new(
                cfg.openai_base.clone(),
                cfg.openai_model.clone(),
                cfg.openai_api_key.clone(),
            )))
        }
        UpstreamKind::Local => {
            #[cfg(feature = "local-inference")]
            {
                Err("in-process local inference is not yet wired; use an OpenAI-compatible upstream".into())
            }
            #[cfg(not(feature = "local-inference"))]
            {
                Err("this build has no local inference — rebuild with --features local-inference, or choose an OpenAI-compatible upstream".into())
            }
        }
    }
}

fn hk_path(dir: &Path) -> PathBuf {
    dir.join("host_key.bin")
}

/// Load the persisted host HPKE keypair, creating + sealing one on first use.
pub fn load_or_create_host_key(
    dir: &Path,
    passphrase: &str,
) -> Result<(HostSecretKey, HostPublicKey), String> {
    if let Ok(bytes) = std::fs::read(hk_path(dir)) {
        if let Ok(pt) = lluma_crypto::account::open_bytes(passphrase, &KeystoreBlob(bytes)) {
            let (sk, pk): (Vec<u8>, Vec<u8>) =
                postcard::from_bytes(&pt).map_err(|e| e.to_string())?;
            return Ok((HostSecretKey(sk), HostPublicKey(pk)));
        }
    }
    let mut rng = rand_core::OsRng;
    let (sk, pk) = lluma_crypto::e2e::host_keygen(&mut rng).map_err(|e| e.to_string())?;
    let plain = postcard::to_stdvec(&(sk.0.clone(), pk.0.clone())).map_err(|e| e.to_string())?;
    let blob =
        lluma_crypto::account::seal_bytes(&mut rng, passphrase, &plain).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(hk_path(dir), &blob.0).map_err(|e| e.to_string())?;
    Ok((sk, pk))
}

/// Base64 the host HPKE public key (for display / registration).
pub fn host_pk_b64(pk: &HostPublicKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(&pk.0)
}

/// Extract the TCP port to bind from an ingress URL like `http://host:9000`.
pub fn port_from_ingress(ingress: &str) -> Result<u16, String> {
    let after = ingress.rsplit(':').next().unwrap_or("");
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits
        .parse::<u16>()
        .map_err(|_| format!("could not parse a port from ingress address '{ingress}'"))
}

/// Best-effort *local* reachability probe: connect to the ingress port and
/// accept any HTTP response. NOTE: this only confirms the port is bound and
/// locally reachable — genuine internet reachability (past NAT) cannot be
/// self-tested and must be confirmed externally.
pub async fn reachability_check(ingress_addr: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    client.get(ingress_addr).send().await.is_ok()
}

/// Spawn the axum serving loop on an already-bound listener. Returns the task
/// handle. Used by both `start` and the loopback test.
pub fn spawn_serve(
    listener: tokio::net::TcpListener,
    host_sk: HostSecretKey,
    upstream: Arc<dyn Upstream>,
) -> tokio::task::JoinHandle<()> {
    let state = HostState { host_sk: Arc::new(host_sk), upstream };
    let app = lluma_host::router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    })
}

/// A running host: the serve task plus a shared status the UI polls.
pub struct HostHandle {
    task: tokio::task::JoinHandle<()>,
    pub status: Arc<Mutex<HostStatus>>,
}

impl HostHandle {
    /// Start serving on the configured ingress port with the selected upstream.
    /// Registration/heartbeat run only when broker params are configured;
    /// otherwise the host serves locally (useful for testing) but the broker
    /// will not forward work.
    pub async fn start(
        cfg: &HostConfig,
        host_sk: HostSecretKey,
    ) -> Result<HostHandle, String> {
        let upstream = select_upstream(cfg)?;
        if cfg.ingress_addr.trim().is_empty() {
            return Err("set an ingress address (e.g. http://<your-public-ip>:9000)".into());
        }
        let port = port_from_ingress(&cfg.ingress_addr)?;
        let bind: SocketAddr = ([0, 0, 0, 0], port).into();
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(|e| format!("could not bind {bind}: {e}"))?;
        let task = spawn_serve(listener, host_sk, upstream);

        let reachable = reachability_check(&cfg.ingress_addr).await;
        let status = Arc::new(Mutex::new(HostStatus {
            running: true,
            reachable,
            state: if reachable { "active".into() } else { "serving (reachability unverified)".into() },
            credits_earned: 0,
            requests_served: 0,
            message: if reachable {
                "serving; broker registration requires operator params".into()
            } else {
                "listening locally — confirm your ingress is reachable from the internet".into()
            },
        }));
        Ok(HostHandle { task, status })
    }

    pub fn snapshot_status(&self) -> HostStatus {
        self.status
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    pub fn stop(self) {
        self.task.abort();
    }
}

pub fn stopped_status() -> HostStatus {
    HostStatus::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lluma_core::proto::v1::HostExecRequest;
    use lluma_core::proto::v1::ExecResponse;
    use lluma_core::wire::SpendId;

    #[test]
    fn port_parsing() {
        assert_eq!(port_from_ingress("http://203.0.113.9:9000").unwrap(), 9000);
        assert_eq!(port_from_ingress("http://localhost:8081/").unwrap(), 8081);
        assert!(port_from_ingress("http://no-port").is_err());
    }

    #[test]
    fn select_upstream_gates_local_and_openai() {
        let mut cfg = HostConfig { upstream: UpstreamKind::Local, ..Default::default() };
        assert!(select_upstream(&cfg).is_err());
        cfg.upstream = UpstreamKind::OpenAi; // no base url
        assert!(select_upstream(&cfg).is_err());
        cfg.openai_base = "http://localhost:11434/v1".into();
        assert!(select_upstream(&cfg).is_ok());
        cfg.upstream = UpstreamKind::Echo;
        assert!(select_upstream(&cfg).is_ok());
    }

    #[tokio::test]
    async fn reachability_false_for_dead_port() {
        // Nothing listening here.
        assert!(!reachability_check("http://127.0.0.1:1").await);
    }

    #[test]
    fn host_key_persists_and_reloads() {
        let dir = std::env::temp_dir().join(format!("lluma-hk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_sk1, pk1) = load_or_create_host_key(&dir, "pw").unwrap();
        let (_sk2, pk2) = load_or_create_host_key(&dir, "pw").unwrap();
        assert_eq!(pk1.0, pk2.0, "same key across loads");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The core serving-crypto path, verified end to end on loopback: seal a
    /// prompt to the host key, POST it, and open the sealed answer.
    #[tokio::test]
    async fn loopback_seal_exec_open_roundtrip() {
        let mut rng = rand_core::OsRng;
        let (host_sk, host_pk) = lluma_crypto::e2e::host_keygen(&mut rng).unwrap();
        let (sess_sk, sess_pk) = lluma_crypto::e2e::session_keygen(&mut rng).unwrap();
        let spend_id = SpendId([5u8; 32]);
        let prompt = b"ping";
        let sealed =
            lluma_crypto::e2e::e2e_seal(&mut rng, &host_pk, &spend_id.0, prompt, &sess_pk).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream: Arc<dyn Upstream> = Arc::new(EchoUpstream { sentinel: b"A:".to_vec() });
        let task = spawn_serve(listener, host_sk, upstream);

        let body = serde_json::to_vec(&HostExecRequest { spend_id, sealed }).unwrap();
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/exec"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let er: ExecResponse = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
        let mut cctx = lluma_crypto::e2e::response_setup_client(&sess_sk, &er.preamble).unwrap();
        let (answer, is_final) = lluma_crypto::e2e::response_open_chunk(&mut cctx, &er.chunk).unwrap();
        assert!(is_final);
        assert_eq!(answer, b"A:ping".to_vec());
        task.abort();
    }
}
