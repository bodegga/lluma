//! Thin wrappers over `lluma-client`: settings decoding, client construction,
//! the encrypted local token store, and the network/acquire/chat flows.

use std::path::{Path, PathBuf};

use base64::Engine;
use lluma_client::{Client, ClientError};
use lluma_core::wire::{
    AccountPublicKey, AccountSecretKey, HostPublicKey, KeystoreBlob, OhttpKeyConfig, Token,
};

use crate::types::{ChatReply, NetworkStatus, Settings};

fn b64d(s: &str, what: &str) -> Result<Vec<u8>, String> {
    if s.trim().is_empty() {
        return Err(format!(
            "{what} is not set — enter it under Advanced (get it from your operator)"
        ));
    }
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| format!("{what} is not valid base64"))
}

/// The trusted network parameters for a session. Established ONLY by a verified
/// path: a signed bootstrap checked against the pinned registry key (anchored
/// builds), or explicit manual entry (self-host/dev builds). Never sourced from
/// unverified relay data. Held in memory — persisted settings are display-only.
#[derive(Clone, Debug)]
pub struct VerifiedNet {
    pub gateway_kc: OhttpKeyConfig,
    pub registry_pk: AccountPublicKey,
    /// Pinned issuer key-id, when known (from the signed bootstrap).
    pub issuer_key_id: Option<[u8; 32]>,
    /// Reverse-tunnel endpoint (wss://…/v1/host/tunnel) from the signed bootstrap,
    /// when the network offers NAT-free hosting. Trusted because it's registry-signed.
    pub tunnel_url: Option<String>,
    /// Published host-registration params (also registry-signed) so this device
    /// can self-register as a tunnel host: current epoch PoW salt + difficulty.
    pub epoch_salt: Option<[u8; 32]>,
    pub pow_difficulty: Option<u32>,
}

/// Decode manually-entered endpoint material (self-host/dev only) into a
/// `VerifiedNet`. This is an explicit user-trust path — there is no signature.
pub fn manual_verified(s: &Settings) -> Result<VerifiedNet, String> {
    let gateway_kc = OhttpKeyConfig(b64d(&s.gateway_kc_b64, "gateway key-config")?);
    let registry_pk = AccountPublicKey(b64d(&s.registry_pk_b64, "registry pubkey")?);
    // Self-host/dev builds don't carry signed tunnel/registration params.
    Ok(VerifiedNet {
        gateway_kc,
        registry_pk,
        issuer_key_id: None,
        tunnel_url: None,
        epoch_salt: None,
        pow_difficulty: None,
    })
}

/// Build a `Client` from the relay URL + account keys + the session's verified
/// network params. Host params are per-message (snapshot-selected).
pub fn build_client(
    relay_url: &str,
    sk: &AccountSecretKey,
    pk: &AccountPublicKey,
    v: &VerifiedNet,
) -> Client {
    let mut c = Client::new(
        relay_url.to_string(),
        v.gateway_kc.clone(),
        sk.clone(),
        pk.clone(),
        HostPublicKey(vec![0u8; 32]),
        [0u8; 32],
    );
    if let Some(kid) = v.issuer_key_id {
        c = c.with_expected_issuer_key_id(kid);
    }
    c
}

/// Unspent blind tokens (bearer credits), encrypted at rest under the account
/// passphrase.
#[derive(Default)]
pub struct TokenStore {
    pub tokens: Vec<Token>,
}

fn ts_path(dir: &Path) -> PathBuf {
    dir.join("tokens.bin")
}

impl TokenStore {
    /// Load + decrypt the token store. Missing/corrupt/wrong-passphrase yields
    /// an empty store (balance 0) rather than an error, so the app always opens.
    pub fn load(dir: &Path, passphrase: &str) -> TokenStore {
        let tokens = std::fs::read(ts_path(dir))
            .ok()
            .and_then(|b| lluma_crypto::account::open_bytes(passphrase, &KeystoreBlob(b)).ok())
            .and_then(|pt| postcard::from_bytes::<Vec<Token>>(&pt).ok())
            .unwrap_or_default();
        TokenStore { tokens }
    }

    pub fn save(&self, dir: &Path, passphrase: &str) -> Result<(), String> {
        let mut rng = rand_core::OsRng;
        let plain = postcard::to_stdvec(&self.tokens).map_err(|e| e.to_string())?;
        let blob =
            lluma_crypto::account::seal_bytes(&mut rng, passphrase, &plain).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        std::fs::write(ts_path(dir), &blob.0).map_err(|e| e.to_string())
    }

    pub fn balance(&self) -> usize {
        self.tokens.len()
    }
}

/// Probe the network: fetch the issuer key-config over the relay and report
/// reachability + epoch/denomination + latency.
pub async fn network_status(client: &Client) -> NetworkStatus {
    let started = std::time::Instant::now();
    match client.key_config().await {
        Ok(kc) => NetworkStatus {
            reachable: true,
            epoch: kc.epoch,
            denomination: kc.denomination,
            latency_ms: started.elapsed().as_millis() as u64,
            message: "connected".into(),
        },
        Err(e) => NetworkStatus {
            reachable: false,
            epoch: 0,
            denomination: 0,
            latency_ms: started.elapsed().as_millis() as u64,
            message: format!("relay unreachable: {e}"),
        },
    }
}

/// Acquire `n` blind tokens, appending them to `store` and persisting it.
/// Returns the new balance.
pub async fn acquire(
    client: &Client,
    store: &mut TokenStore,
    dir: &Path,
    passphrase: &str,
    n: usize,
) -> Result<usize, String> {
    if n == 0 {
        return Err("count must be at least 1".into());
    }
    let kc = client.key_config().await.map_err(|e| e.to_string())?;
    let mut fresh = client.acquire(&kc, n).await.map_err(|e| {
        format!("could not acquire tokens ({e}) — is your account funded? copy your account id from Status")
    })?;
    store.tokens.append(&mut fresh);
    store.save(dir, passphrase)?;
    Ok(store.balance())
}

/// Self-serve trial credits: solve the trial PoW (bound to this account + the
/// bootstrap-published `epoch_salt`) and register over the relay→gateway path.
/// Returns a user-facing status message. `epoch_salt`/`pow_difficulty` come from
/// the signed bootstrap — self-host/dev builds (which carry neither) can't claim.
pub async fn claim_trial(client: &Client, v: &VerifiedNet) -> Result<String, String> {
    let (Some(salt), Some(difficulty)) = (v.epoch_salt, v.pow_difficulty) else {
        return Err(
            "self-serve credits aren't offered on this network — ask your operator for a grant"
                .into(),
        );
    };
    match client.trial_register(&salt, difficulty).await {
        Ok(true) => Ok("Starter credits granted — acquire tokens to start chatting.".into()),
        // Uniform refusal: already claimed, or the daily trial budget is spent.
        Ok(false) => Err(
            "starter credits are unavailable right now — you may have already claimed them, or the daily pool is spent. Try again tomorrow."
                .into(),
        ),
        Err(e) => Err(format!("could not claim starter credits ({e}) — check your connection")),
    }
}

/// Send one chat message: discover a host from the signed snapshot, spend one
/// token, and return the sealed answer. Persists the reduced token store.
pub async fn send_message(
    client: &Client,
    store: &mut TokenStore,
    registry_pk: &AccountPublicKey,
    dir: &Path,
    passphrase: &str,
    prompt: &str,
) -> Result<ChatReply, String> {
    if store.tokens.is_empty() {
        return Err("no credits — fund your account (copy your account id from Status)".into());
    }
    // Stage-labelled errors: a bare "transport" can't tell a gateway allowlist
    // gap from a dead host directory from a failed exec. Name the stage that
    // failed (and preserve the underlying status, e.g. "relay/gateway status 502").
    let kc = client
        .key_config()
        .await
        .map_err(|e| format!("connect check failed ({e})"))?;
    let mut hosts = client
        .snapshot(registry_pk)
        .await
        .map_err(|e| format!("host discovery failed ({e}) — the network's host directory is unreachable"))?;
    if hosts.is_empty() {
        return Err("no active hosts in the network right now".into());
    }
    // Prefer hosts advertising a real model (genuine inference) over model-less
    // demo/echo hosts — `sort_by_key` puts `models.is_empty() == false` first and
    // is stable, so snapshot order is otherwise preserved.
    hosts.sort_by_key(|h| h.models.is_empty());

    // Try each host in turn instead of hard-failing on the first. A snapshot host
    // can be ACTIVE in the directory yet momentarily unservable (e.g. a tunnel
    // host whose socket dropped) — the broker answers `no_host` for that BEFORE
    // spending, so the same token is still valid for the next host. Reusing one
    // token across attempts is safe: the broker's durable spent-set means that if
    // an attempt DID spend then failed to deliver, the next attempt returns 409
    // (double-spend), which we treat as terminal rather than retrying.
    let token = store.tokens.last().cloned().ok_or("no credits")?;
    let n = hosts.len();
    let mut last_err = String::new();
    for (i, host) in hosts.iter().enumerate() {
        match client.exec_with_host(&kc, token.clone(), host, prompt.as_bytes()).await {
            Ok(answer) => {
                store.tokens.pop(); // consumed by a successful spend
                store.save(dir, passphrase)?;
                return Ok(ChatReply {
                    answer: String::from_utf8_lossy(&answer).to_string(),
                    spent: 1,
                    balance: store.balance(),
                });
            }
            // The token was spent, then the host failed to deliver — it cannot be
            // reused, and no other host will accept it. Consume it and stop.
            Err(ClientError::Server(409)) => {
                store.tokens.pop();
                store.save(dir, passphrase)?;
                return Err(
                    "the credit was spent but the host didn't return a result — please try again"
                        .into(),
                );
            }
            // Unservable host (no_host / upstream / gateway timeout): the token was
            // not confirmed spent, so fall through to the next candidate.
            Err(e) => {
                last_err = format!("host {}/{n}: {e}", i + 1);
            }
        }
    }
    // Every host declined before confirming a spend — keep the (untouched) token.
    store.save(dir, passphrase)?;
    Err(format!("no host could serve this request right now ({last_err})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_store_round_trips_empty() {
        let dir = std::env::temp_dir().join(format!("lluma-tok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ts = TokenStore::default();
        ts.save(&dir, "pw").unwrap();
        let back = TokenStore::load(&dir, "pw");
        assert_eq!(back.balance(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manual_verified_reports_missing_material() {
        let s = Settings::default(); // gateway/registry empty
        let err = manual_verified(&s).unwrap_err();
        assert!(err.contains("gateway key-config"));
    }

    #[test]
    fn wrong_passphrase_load_yields_empty() {
        let dir = std::env::temp_dir().join(format!("lluma-tok2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        TokenStore::default().save(&dir, "right").unwrap();
        // Wrong passphrase → empty store, not a panic.
        assert_eq!(TokenStore::load(&dir, "wrong").balance(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
