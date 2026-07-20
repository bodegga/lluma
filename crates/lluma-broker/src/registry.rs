//! Host registry: PoW-gated registration with slow admission, replay-proof
//! heartbeats, staleness eviction, and SSRF-safe ingress-address policy.
//! Controller-authored (security-critical, Fable rulings R8/R9 + must-fix 7).
//!
//! `host_account` throughout is the host's raw Ed25519 **public key** (32 B) —
//! the only key material able to verify its register/heartbeat/receipt
//! signatures (mirrors the `account`-is-pubkey convention in `IssueRequestBody`).
//! The credit ledger is keyed by `account_fingerprint(host_account)`.

use std::net::IpAddr;

use redb::ReadableTable;

use lluma_core::proto::v1::{HeartbeatRequest, HostRegisterRequest};
use lluma_core::wire::{AccountPublicKey, ReceiptSignature};

use crate::config::BrokerConfig;
use crate::error::BrokerError;
use crate::store::{HostRow, Store, HOSTS, HOST_ACTIVE, HOST_PENDING};

#[derive(Debug, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// A new pending host was recorded (awaiting M heartbeats to go active).
    Registered,
    /// An existing host's addr/models were refreshed (status preserved).
    Updated,
    BadSignature,
    BadPow,
    BadAddress,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HeartbeatOutcome {
    Accepted { active: bool },
    UnknownHost,
    BadSignature,
    Replay,
}

/// Verify PoW under the host domain, accepting the current epoch salt and (if
/// present) the previous one to bound precomputation across a rotation.
fn host_pow_ok(cfg: &BrokerConfig, account_pk: &[u8; 32], nonce: &[u8; 8]) -> bool {
    use lluma_crypto::account::{pow_verify, POW_HOST_DOMAIN};
    if pow_verify(POW_HOST_DOMAIN, account_pk, nonce, &cfg.epoch_salt, cfg.pow_difficulty) {
        return true;
    }
    matches!(cfg.epoch_salt_prev, Some(prev)
        if pow_verify(POW_HOST_DOMAIN, account_pk, nonce, &prev, cfg.pow_difficulty))
}

/// SSRF policy for a host's advertised ingress URL. Requires an http(s) scheme.
/// Unless `allow_loopback` (test only), rejects IP literals in loopback,
/// unspecified, RFC1918-private, or link-local ranges. Hostnames are allowed
/// (DNS-rebind to internal is a documented residual — hosts are expected to use
/// public addresses; the exec-time forwarder additionally sets redirect-none).
fn ingress_addr_ok(addr: &str, allow_loopback: bool) -> bool {
    let url = match reqwest::Url::parse(addr) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    let host = match url.host_str() {
        Some(h) => h,
        None => return false,
    };
    if allow_loopback {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified())
        }
        Ok(IpAddr::V6(v6)) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return false;
            }
            // Best-effort reject of ULA (fc00::/7) and link-local (fe80::/10);
            // std lacks stable helpers for these.
            let seg0 = v6.segments()[0];
            (seg0 & 0xfe00) != 0xfc00 && (seg0 & 0xffc0) != 0xfe80
        }
        // Not an IP literal → a hostname; allowed (residual noted above).
        Err(_) => true,
    }
}

/// Register (or idempotently refresh) a host. Signature + PoW + address policy
/// are checked BEFORE any write. A new host is recorded `pending`; only M valid
/// heartbeats promote it to `active` (slow admission).
pub fn register(
    store: &Store,
    req: &HostRegisterRequest,
    cfg: &BrokerConfig,
    now_unix_s: u64,
) -> Result<RegisterOutcome, BrokerError> {
    if req.validate().is_err() {
        return Ok(RegisterOutcome::BadAddress);
    }
    let body = &req.body;
    let pk = AccountPublicKey(body.host_account.to_vec());
    let sig = ReceiptSignature(req.sig.clone());
    if lluma_crypto::account::host_register_verify(&pk, body, &sig).is_err() {
        return Ok(RegisterOutcome::BadSignature);
    }
    let nonce: [u8; 8] = match req.pow_nonce.as_slice().try_into() {
        Ok(n) => n,
        Err(_) => return Ok(RegisterOutcome::BadPow),
    };
    if !host_pow_ok(cfg, &body.host_account, &nonce) {
        return Ok(RegisterOutcome::BadPow);
    }
    if !ingress_addr_ok(&body.ingress_addr, cfg.allow_loopback_ingress) {
        return Ok(RegisterOutcome::BadAddress);
    }

    store.with_write(|w| {
        let mut hosts = w.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
        let key: &[u8] = &body.host_account;
        let existing = hosts
            .get(key)
            .map_err(|_| BrokerError::Storage)?
            .map(|v| v.value().to_vec());
        let (row, outcome) = match existing {
            Some(bytes) => {
                let mut r: HostRow =
                    postcard::from_bytes(&bytes).map_err(|_| BrokerError::Storage)?;
                r.hpke_pk = body.hpke_pk.clone();
                r.ingress_addr = body.ingress_addr.clone();
                r.models = body.models.clone();
                (r, RegisterOutcome::Updated)
            }
            None => (
                HostRow {
                    hpke_pk: body.hpke_pk.clone(),
                    ingress_addr: body.ingress_addr.clone(),
                    models: body.models.clone(),
                    status: HOST_PENDING,
                    hb_counter: 0,
                    last_hb: now_unix_s,
                    load_bucket: 0,
                    admit_progress: 0,
                },
                RegisterOutcome::Registered,
            ),
        };
        let bytes = postcard::to_stdvec(&row).map_err(|_| BrokerError::Storage)?;
        hosts.insert(key, bytes.as_slice()).map_err(|_| BrokerError::Storage)?;
        Ok(outcome)
    })
}

/// Process a heartbeat: cheap unknown-host prefilter (a table `get`) BEFORE the
/// Ed25519 verify, monotonic-counter replay rejection, load update, and slow
/// admission (`admit_progress += 1`; `→ active` at `M`).
pub fn heartbeat(
    store: &Store,
    req: &HeartbeatRequest,
    now_unix_s: u64,
    cfg: &BrokerConfig,
) -> Result<HeartbeatOutcome, BrokerError> {
    if req.validate().is_err() {
        return Ok(HeartbeatOutcome::BadSignature);
    }
    let body = &req.body;
    store.with_write(|w| {
        let mut hosts = w.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
        let key: &[u8] = &body.host_account;
        // Prefilter: unknown key rejected before the expensive signature verify.
        let row_bytes = match hosts.get(key).map_err(|_| BrokerError::Storage)? {
            Some(v) => v.value().to_vec(),
            None => return Ok(HeartbeatOutcome::UnknownHost),
        };
        let pk = AccountPublicKey(body.host_account.to_vec());
        let sig = ReceiptSignature(req.sig.clone());
        if lluma_crypto::account::heartbeat_verify(&pk, body, &sig).is_err() {
            return Ok(HeartbeatOutcome::BadSignature);
        }
        let mut row: HostRow =
            postcard::from_bytes(&row_bytes).map_err(|_| BrokerError::Storage)?;
        // Monotonic counter — a replayed or stale heartbeat is refused.
        if body.hb_counter <= row.hb_counter {
            return Ok(HeartbeatOutcome::Replay);
        }
        row.hb_counter = body.hb_counter;
        row.last_hb = now_unix_s;
        row.load_bucket = body.load_bucket;
        row.admit_progress = row.admit_progress.saturating_add(1);
        if row.admit_progress >= cfg.admission_m {
            row.status = HOST_ACTIVE;
        }
        let active = row.status == HOST_ACTIVE;
        let bytes = postcard::to_stdvec(&row).map_err(|_| BrokerError::Storage)?;
        hosts.insert(key, bytes.as_slice()).map_err(|_| BrokerError::Storage)?;
        Ok(HeartbeatOutcome::Accepted { active })
    })
}

/// Demote hosts whose last heartbeat is older than `3 × interval` back to
/// `pending` (removing them from snapshot eligibility). Returns the count.
pub fn evict_stale(
    store: &Store,
    now_unix_s: u64,
    cfg: &BrokerConfig,
) -> Result<usize, BrokerError> {
    let threshold = cfg.heartbeat_interval_s.saturating_mul(3);
    store.with_write(|w| {
        let mut hosts = w.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
        let mut stale: Vec<([u8; 32], HostRow)> = Vec::new();
        {
            let iter = hosts.iter().map_err(|_| BrokerError::Storage)?;
            for entry in iter {
                let (k, v) = entry.map_err(|_| BrokerError::Storage)?;
                let acct: [u8; 32] = match k.value().try_into() {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                let mut row: HostRow =
                    postcard::from_bytes(v.value()).map_err(|_| BrokerError::Storage)?;
                let stale_now = now_unix_s.saturating_sub(row.last_hb) > threshold;
                if stale_now && (row.status == HOST_ACTIVE || row.admit_progress > 0) {
                    row.status = HOST_PENDING;
                    row.admit_progress = 0;
                    stale.push((acct, row));
                }
            }
        }
        for (k, row) in &stale {
            let bytes = postcard::to_stdvec(row).map_err(|_| BrokerError::Storage)?;
            hosts.insert(k.as_slice(), bytes.as_slice()).map_err(|_| BrokerError::Storage)?;
        }
        Ok(stale.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lluma_core::wire::{HeartbeatBody, HostRegisterBody, Mnemonic};
    use lluma_core::ModelId;
    use lluma_crypto::account::{
        derive_keypair_from_seed, heartbeat_sign, host_register_sign, pow_solve, POW_HOST_DOMAIN,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);
    fn tmp() -> std::path::PathBuf {
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!("lluma-broker-reg-{}-{}.redb", std::process::id(), n));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn keypair(seed: u8) -> ([u8; 32], lluma_core::wire::AccountSecretKey) {
        let (sk, pk) = derive_keypair_from_seed(&Mnemonic([seed; 16])).unwrap();
        let pk32: [u8; 32] = pk.0.as_slice().try_into().unwrap();
        (pk32, sk)
    }

    fn signed_register(
        seed: u8,
        addr: &str,
        cfg: &BrokerConfig,
    ) -> HostRegisterRequest {
        let (pk32, sk) = keypair(seed);
        let body = HostRegisterBody {
            version: 1,
            host_account: pk32,
            hpke_pk: vec![0x42; 32],
            ingress_addr: addr.into(),
            models: vec![ModelId("m".into())],
        };
        let sig = host_register_sign(&sk, &body).unwrap();
        let nonce = pow_solve(POW_HOST_DOMAIN, &pk32, &cfg.epoch_salt, cfg.pow_difficulty);
        HostRegisterRequest { body, sig: sig.0, pow_nonce: nonce.to_vec() }
    }

    fn signed_heartbeat(seed: u8, counter: u64) -> HeartbeatRequest {
        let (pk32, sk) = keypair(seed);
        let body = HeartbeatBody {
            version: 1,
            host_account: pk32,
            hb_counter: counter,
            load_bucket: 1,
            models: vec![ModelId("m".into())],
        };
        let sig = heartbeat_sign(&sk, &body).unwrap();
        HeartbeatRequest { body, sig: sig.0 }
    }

    #[test]
    fn register_pending_then_active_after_m_heartbeats() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        let req = signed_register(1, "http://127.0.0.1:9000", &cfg);
        assert_eq!(register(&s, &req, &cfg, 100).unwrap(), RegisterOutcome::Registered);
        // M = 3 heartbeats to promote.
        assert_eq!(heartbeat(&s, &signed_heartbeat(1, 1), 130, &cfg).unwrap(), HeartbeatOutcome::Accepted { active: false });
        assert_eq!(heartbeat(&s, &signed_heartbeat(1, 2), 160, &cfg).unwrap(), HeartbeatOutcome::Accepted { active: false });
        assert_eq!(heartbeat(&s, &signed_heartbeat(1, 3), 190, &cfg).unwrap(), HeartbeatOutcome::Accepted { active: true });
    }

    #[test]
    fn register_bad_pow_rejected() {
        // Difficulty 24 so a zero nonce fails deterministically (P(pass) ≈ 2^-24);
        // no solving needed for the negative case.
        let mut cfg = BrokerConfig::for_test();
        cfg.pow_difficulty = 24;
        let s = Store::open(&tmp()).unwrap();
        let (pk32, sk) = keypair(2);
        let body = HostRegisterBody {
            version: 1,
            host_account: pk32,
            hpke_pk: vec![0x42; 32],
            ingress_addr: "http://127.0.0.1:9000".into(),
            models: vec![ModelId("m".into())],
        };
        let sig = host_register_sign(&sk, &body).unwrap();
        let req = HostRegisterRequest { body, sig: sig.0, pow_nonce: vec![0u8; 8] };
        assert_eq!(register(&s, &req, &cfg, 100).unwrap(), RegisterOutcome::BadPow);
    }

    #[test]
    fn register_private_ingress_rejected_in_prod() {
        let mut cfg = BrokerConfig::for_test();
        cfg.allow_loopback_ingress = false; // prod policy
        let s = Store::open(&tmp()).unwrap();
        let req = signed_register(3, "http://10.1.2.3:9000", &cfg);
        assert_eq!(register(&s, &req, &cfg, 100).unwrap(), RegisterOutcome::BadAddress);
        // A public address is accepted under the same policy.
        let req2 = signed_register(4, "http://203.0.113.7:9000", &cfg);
        assert_eq!(register(&s, &req2, &cfg, 100).unwrap(), RegisterOutcome::Registered);
    }

    #[test]
    fn heartbeat_unknown_host_rejected() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        assert_eq!(heartbeat(&s, &signed_heartbeat(9, 1), 100, &cfg).unwrap(), HeartbeatOutcome::UnknownHost);
    }

    #[test]
    fn heartbeat_replayed_counter_rejected() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        register(&s, &signed_register(5, "http://127.0.0.1:9001", &cfg), &cfg, 100).unwrap();
        assert!(matches!(heartbeat(&s, &signed_heartbeat(5, 5), 130, &cfg).unwrap(), HeartbeatOutcome::Accepted { .. }));
        // Same counter (5) again ⇒ replay; and a lower counter ⇒ replay.
        assert_eq!(heartbeat(&s, &signed_heartbeat(5, 5), 160, &cfg).unwrap(), HeartbeatOutcome::Replay);
        assert_eq!(heartbeat(&s, &signed_heartbeat(5, 4), 190, &cfg).unwrap(), HeartbeatOutcome::Replay);
    }

    #[test]
    fn heartbeat_bad_signature_rejected() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        register(&s, &signed_register(6, "http://127.0.0.1:9002", &cfg), &cfg, 100).unwrap();
        let mut hb = signed_heartbeat(6, 1);
        hb.sig[0] ^= 0xff;
        assert_eq!(heartbeat(&s, &hb, 130, &cfg).unwrap(), HeartbeatOutcome::BadSignature);
    }

    #[test]
    fn evict_stale_demotes_active_host() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        register(&s, &signed_register(7, "http://127.0.0.1:9003", &cfg), &cfg, 100).unwrap();
        for c in 1..=3 {
            heartbeat(&s, &signed_heartbeat(7, c), 100 + c * 30, &cfg).unwrap();
        }
        // Now far in the future (> 3 × 30 s past last_hb) ⇒ evicted.
        let evicted = evict_stale(&s, 100_000, &cfg).unwrap();
        assert_eq!(evicted, 1);
        // A fresh heartbeat must re-admit through M again (admit_progress reset).
        assert_eq!(heartbeat(&s, &signed_heartbeat(7, 10), 100_030, &cfg).unwrap(), HeartbeatOutcome::Accepted { active: false });
    }
}
