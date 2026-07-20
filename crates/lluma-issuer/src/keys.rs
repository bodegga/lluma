//! Persistence and loading of the issuer epoch keypair.
//!
//! The epoch keypair is the long-lived RSA blind-signing secret the issuer uses
//! to mint entitlement tokens. It is stored on disk as JSON (`epoch`, base64
//! `sk_der`, base64 `pk_der`) and written **atomically** (temp file + rename)
//! so a crash mid-write never leaves a truncated key file.
//!
//! ## Privacy & threat notes
//! - The secret key is stored **in plaintext** on disk. This is acceptable for
//!   the Phase-1 MVP because the issuer machine itself is trusted for credit
//!   integrity (compromise = credit forgery, not deanonymization). Phase #N
//!   moves it under a KMS / OS keychain — see spec §8/§11.
//! - BLAKE3 is the content-addressing hash for `key_id` — never truncated.
//! - The RNG used for `issuer_keygen` is `blind_rsa_signatures::DefaultRng`
//!   (the rand_core 0.10 RNG the blind-rsa crate requires) — NOT rand_core
//!   0.6 `OsRng`. See the Global RNG-split constraint and `tokens.rs`'s note.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use lluma_core::wire::{IssuerPublicKey, IssuerSecretKey};
use lluma_crypto::tokens;
use serde::{Deserialize, Serialize};

use crate::IssuerError;

/// An issuer epoch's signing keypair and its content-addressed `key_id`.
/// `key_id` is the full 32-byte `BLAKE3(public.0)` — never truncated.
pub struct EpochKeys {
    pub epoch: u64,
    pub secret: IssuerSecretKey,
    pub public: IssuerPublicKey,
}

impl EpochKeys {
    /// `key_id = BLAKE3(public DER)`, full 32 bytes — the client pins this and
    /// the handler rejects any `IssueRequest` whose `body.key_id` differs.
    pub fn key_id(&self) -> [u8; 32] {
        *blake3::hash(&self.public.0).as_bytes()
    }
}

/// On-disk JSON schema: epoch + base64-encoded DER blobs.
#[derive(Serialize, Deserialize)]
struct KeyFile {
    epoch: u64,
    sk_der: String,
    pk_der: String,
}

/// Load epoch keys from `path`; if absent, generate a fresh RSA-2048 keypair
/// with `blind_rsa_signatures::DefaultRng`, persist it atomically, and return.
/// All IO/encoding failures map to `IssuerError::Internal` — no inner error
/// text reaches the caller (leak L8).
pub fn load_or_create(path: &Path, epoch: u64) -> Result<EpochKeys, IssuerError> {
    if path.exists() {
        read_keys(path)
    } else {
        create_keys(path, epoch)
    }
}

fn read_keys(path: &Path) -> Result<EpochKeys, IssuerError> {
    let bytes = fs::read(path).map_err(|_| IssuerError::Internal)?;
    let kf: KeyFile = serde_json::from_slice(&bytes).map_err(|_| IssuerError::Internal)?;
    let sk = B64.decode(kf.sk_der).map_err(|_| IssuerError::Internal)?;
    let pk = B64.decode(kf.pk_der).map_err(|_| IssuerError::Internal)?;
    Ok(EpochKeys {
        epoch: kf.epoch,
        secret: IssuerSecretKey(sk),
        public: IssuerPublicKey(pk),
    })
}

fn create_keys(path: &Path, epoch: u64) -> Result<EpochKeys, IssuerError> {
    // RNG split: blind-rsa's own DefaultRng (rand_core 0.10), never OsRng 0.6.
    let mut rng = blind_rsa_signatures::DefaultRng;
    let (secret, public) = tokens::issuer_keygen(&mut rng)?;
    let keys = EpochKeys {
        epoch,
        secret,
        public,
    };
    persist_atomic(path, &keys)?;
    Ok(keys)
}

/// Serialize `keys` to JSON, write to `path.tmp`, then `rename` over `path`.
/// `rename` is atomic on the same filesystem; the temp file sits next to the
/// target so they share a mount. A crash between `write` and `rename` leaves
/// behind a stray `.tmp` file but never corrupts an existing key file.
fn persist_atomic(path: &Path, keys: &EpochKeys) -> Result<(), IssuerError> {
    let kf = KeyFile {
        epoch: keys.epoch,
        sk_der: B64.encode(&keys.secret.0),
        pk_der: B64.encode(&keys.public.0),
    };
    let json = serde_json::to_vec(&kf).map_err(|_| IssuerError::Internal)?;

    let mut tmp_path = PathBuf::from(path);
    let mut name = tmp_path
        .file_name()
        .ok_or(IssuerError::Internal)?
        .to_os_string();
    name.push(".tmp");
    tmp_path.set_file_name(name);

    // Restrictive perms best-effort: on Unix, create with 0600; on non-Unix,
    // `File::create_new` is the best we can do without platform-specific deps.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|_| IssuerError::Internal)?;
        f.write_all(&json).map_err(|_| IssuerError::Internal)?;
        let _ = f.sync_all();
    }
    #[cfg(not(unix))]
    {
        let mut f = fs::File::create(&tmp_path).map_err(|_| IssuerError::Internal)?;
        f.write_all(&json).map_err(|_| IssuerError::Internal)?;
        f.sync_all().map_err(|_| IssuerError::Internal)?;
    }

    fs::rename(&tmp_path, path).map_err(|_| IssuerError::Internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blind_rsa_signatures::DefaultRng;
    use lluma_core::wire::{BlindingState, BlindedTokenRequest};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    // Each test gets a unique temp path under the system temp dir. We use a
    // global counter + PID so concurrent test runs and threads don't collide.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "lluma-issuer-keys-test-{}-{}.json",
            std::process::id(),
            n
        ));
        p
    }

    // Serialize cleanup across tests so a panic in one doesn't leak temp files
    // that another later test would mistake for a pre-existing key. Each test
    // registers its path on entry and removes it on exit via RAII guard.
    struct TempPath(PathBuf);
    impl TempPath {
        fn new() -> Self {
            let p = unique_path();
            // stale file from a crashed previous run would skew the "fresh"
            // assertions, so remove any pre-existing entry first.
            let _ = std::fs::remove_file(&p);
            TempPath(p)
        }
    }
    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let mut tmp = self.0.clone();
            tmp.set_extension("json.tmp");
            let _ = std::fs::remove_file(&tmp);
        }
    }

    // proptest can rerun a single test body many times in one process; the
    // Mutex serializes path allocation so the `unique_path` counter doesn't
    // race and a cleanup in one iteration doesn't fight another's `Drop`.
    static PATH_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn load_or_create_on_absent_path_creates_file_and_key_id_is_blake3() {
        let _g = PATH_LOCK.lock().unwrap();
        let tp = TempPath::new();
        let keys = load_or_create(&tp.0, 7).expect("create");
        // File was created.
        assert!(tp.0.exists(), "key file should exist after create");
        // key_id == BLAKE3(public.0).
        let want = *blake3::hash(&keys.public.0).as_bytes();
        assert_eq!(keys.key_id(), want);
        assert_eq!(keys.epoch, 7);
    }

    #[test]
    fn second_load_or_create_returns_same_key_id() {
        let _g = PATH_LOCK.lock().unwrap();
        let tp = TempPath::new();
        let first = load_or_create(&tp.0, 3).expect("first create");
        let id1 = first.key_id();
        // Reload — must NOT regenerate.
        let second = load_or_create(&tp.0, 3).expect("reload");
        assert_eq!(second.key_id(), id1, "reloaded key_id must equal first");
        assert_eq!(second.public.0, first.public.0);
        assert_eq!(second.secret.0, first.secret.0);
        assert_eq!(second.epoch, first.epoch);
    }

    #[test]
    fn token_issued_under_first_load_verifies_under_reloaded_public() {
        let _g = PATH_LOCK.lock().unwrap();
        let tp = TempPath::new();
        let first = load_or_create(&tp.0, 1).expect("first create");
        let second = load_or_create(&tp.0, 1).expect("reload");

        // Blind → issue under FIRST loaded secret → unblind with first pk.
        let mut rng = DefaultRng;
        let (state, req): (BlindingState, BlindedTokenRequest) =
            tokens::token_blind(&mut rng, &first.public).expect("blind");
        let blind_sig = tokens::token_issue(&mut rng, &first.secret, &req).expect("issue");
        let token = tokens::token_unblind(&first.public, state, &blind_sig).expect("unblind");

        // The token must verify under the RELOADED public key — persistence is
        // faithful, not regenerated.
        tokens::token_verify(&second.public, &token).expect("verify under reloaded pk");
    }

    #[test]
    fn load_or_create_is_atomic_no_tmp_left_on_success() {
        let _g = PATH_LOCK.lock().unwrap();
        let tp = TempPath::new();
        let _keys = load_or_create(&tp.0, 1).expect("create");
        let mut tmp = tp.0.clone();
        tmp.set_extension("json.tmp");
        assert!(!tmp.exists(), "temp file must have been renamed away");
    }

    #[test]
    fn load_or_create_round_trips_epoch() {
        let _g = PATH_LOCK.lock().unwrap();
        let tp = TempPath::new();
        let _ = load_or_create(&tp.0, 42).expect("create");
        let reloaded = load_or_create(&tp.0, 99).expect("reload");
        // The on-disk epoch is preserved; the `epoch` passed to a present-file
        // load is the FALLBACK only used when creating — reloaded must carry
        // the persisted epoch, not the new argument.
        assert_eq!(reloaded.epoch, 42);
    }
}