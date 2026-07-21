//! Self-custodial account: create / import / unlock, sealed at rest under a
//! user passphrase (Argon2id + XChaCha20-Poly1305, via `lluma-crypto`).

use std::path::{Path, PathBuf};

use lluma_core::wire::{AccountPublicKey, AccountSecretKey, KeystoreBlob, Mnemonic};
use lluma_crypto::account::{
    account_fingerprint, account_mnemonic_new, derive_keypair_from_seed, mnemonic_from_phrase,
    mnemonic_to_phrase, open_keystore, seal_keystore,
};

/// An unlocked account held in memory. The mnemonic is retained so the UI can
/// show the recovery phrase on demand (backup), but it is never persisted in
/// the clear.
pub struct Account {
    pub sk: AccountSecretKey,
    pub pk: AccountPublicKey,
    mnemonic: Mnemonic,
}

fn ks_path(dir: &Path) -> PathBuf {
    dir.join("keystore.bin")
}

impl Account {
    pub fn exists(dir: &Path) -> bool {
        ks_path(dir).exists()
    }

    fn from_mnemonic(m: Mnemonic) -> Result<Account, String> {
        let (sk, pk) = derive_keypair_from_seed(&m).map_err(|e| e.to_string())?;
        Ok(Account { sk, pk, mnemonic: m })
    }

    fn persist(dir: &Path, m: &Mnemonic, passphrase: &str) -> Result<(), String> {
        let mut rng = rand_core::OsRng;
        let blob = seal_keystore(&mut rng, passphrase, m).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        std::fs::write(ks_path(dir), &blob.0).map_err(|e| e.to_string())
    }

    /// Generate a fresh account and persist it sealed under `passphrase`.
    pub fn create(dir: &Path, passphrase: &str) -> Result<Account, String> {
        if passphrase.is_empty() {
            return Err("passphrase must not be empty".into());
        }
        let mut rng = rand_core::OsRng;
        let m = account_mnemonic_new(&mut rng).map_err(|e| e.to_string())?;
        Self::persist(dir, &m, passphrase)?;
        Self::from_mnemonic(m)
    }

    /// Import an existing 12-word recovery phrase and persist it sealed.
    pub fn import(dir: &Path, phrase: &str, passphrase: &str) -> Result<Account, String> {
        if passphrase.is_empty() {
            return Err("passphrase must not be empty".into());
        }
        let m = mnemonic_from_phrase(phrase).map_err(|e| e.to_string())?;
        Self::persist(dir, &m, passphrase)?;
        Self::from_mnemonic(m)
    }

    /// Unlock the persisted keystore with `passphrase`.
    pub fn unlock(dir: &Path, passphrase: &str) -> Result<Account, String> {
        let bytes = std::fs::read(ks_path(dir)).map_err(|e| e.to_string())?;
        let m = open_keystore(passphrase, &KeystoreBlob(bytes))
            .map_err(|_| "wrong passphrase".to_string())?;
        Self::from_mnemonic(m)
    }

    /// Hex account fingerprint (`account_id`) — the value an operator funds.
    pub fn account_id_hex(&self) -> String {
        let id = account_fingerprint(&self.pk);
        id.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The 12-word recovery phrase, for the user to write down.
    pub fn recovery_phrase(&self) -> Result<String, String> {
        mnemonic_to_phrase(&self.mnemonic).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("lluma-acct-{}-{:?}", std::process::id(), ks_tmp_id()))
    }
    fn ks_tmp_id() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        C.fetch_add(1, Ordering::SeqCst)
    }

    #[test]
    fn create_then_unlock_yields_same_account() {
        let dir = tmp();
        let _ = std::fs::remove_dir_all(&dir);
        let a = Account::create(&dir, "hunter2").unwrap();
        let id1 = a.account_id_hex();
        assert_eq!(a.recovery_phrase().unwrap().split_whitespace().count(), 12);
        let b = Account::unlock(&dir, "hunter2").unwrap();
        assert_eq!(id1, b.account_id_hex());
        assert!(Account::unlock(&dir, "wrong").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_recovers_same_account() {
        let dir = tmp();
        let _ = std::fs::remove_dir_all(&dir);
        let a = Account::create(&dir, "pw").unwrap();
        let phrase = a.recovery_phrase().unwrap();
        let id = a.account_id_hex();

        let dir2 = tmp();
        let _ = std::fs::remove_dir_all(&dir2);
        let b = Account::import(&dir2, &phrase, "other-pw").unwrap();
        assert_eq!(id, b.account_id_hex());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn empty_passphrase_rejected() {
        let dir = tmp();
        assert!(Account::create(&dir, "").is_err());
    }
}
