//! Static host directory for the end-to-end slice (ADR-0003). Config-listed
//! hosts only — PoW registration, signed snapshots, heartbeats, and matchmaking
//! are deferred (they defend availability/quality, not the linkage invariant).

use lluma_core::wire::{AccountId, HostPublicKey};

#[derive(Clone)]
pub struct HostEntry {
    pub host_account: AccountId,
    pub ingress_url: String,
    pub host_pk: HostPublicKey,
}

#[derive(Clone, Default)]
pub struct StaticHostDirectory {
    entries: Vec<HostEntry>,
}

impl StaticHostDirectory {
    pub fn new(entries: Vec<HostEntry>) -> Self {
        Self { entries }
    }

    /// Resolve a host by account id; `None` (fail closed) if unknown.
    pub fn resolve(&self, account: &AccountId) -> Option<&HostEntry> {
        self.entries.iter().find(|e| &e.host_account == account)
    }

    /// The single configured host for the slice (there is no selection yet).
    pub fn first(&self) -> Option<&HostEntry> {
        self.entries.first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u8) -> HostEntry {
        HostEntry {
            host_account: AccountId([n; 32]),
            ingress_url: format!("http://127.0.0.1:{}", 9000 + n as u16),
            host_pk: HostPublicKey(vec![n; 32]),
        }
    }

    #[test]
    fn resolves_known_and_fails_closed_unknown() {
        let d = StaticHostDirectory::new(vec![entry(1), entry(2)]);
        assert_eq!(d.resolve(&AccountId([1; 32])).unwrap().ingress_url, entry(1).ingress_url);
        assert!(d.resolve(&AccountId([9; 32])).is_none());
        assert_eq!(d.first().unwrap().host_account, AccountId([1; 32]));
    }

    #[test]
    fn empty_directory_first_is_none() {
        let d = StaticHostDirectory::default();
        assert!(d.first().is_none());
    }
}
