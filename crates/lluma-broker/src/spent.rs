//! `RedbSpentSet` — the durable per-epoch spent-set: the double-spend arbiter.
//! It implements the #2 `SpentSet` trait and **fails closed** on any storage
//! error (returns `AlreadySpent` — refuse the redeem — never `Inserted`), so a
//! disk fault can never be turned into a double-spend. This closes the
//! restart-respend hole demonstrated by #2's in-memory spent-set.

use redb::ReadableTable;

use lluma_core::wire::SpendId;
use lluma_issuer::spent_set::{InsertOutcome, SpentSet};

use crate::error::BrokerError;
use crate::store::{Store, SPENT};

pub struct RedbSpentSet {
    store: Store,
    epoch: u64,
}

impl RedbSpentSet {
    pub fn new(store: Store, epoch: u64) -> Self {
        Self { store, epoch }
    }

    fn try_insert(&self, id: &SpendId) -> Result<InsertOutcome, BrokerError> {
        let key: &[u8] = &id.0;
        let w = self.store.db().begin_write().map_err(|_| BrokerError::Storage)?;
        let outcome = {
            let mut t = w.open_table(SPENT).map_err(|_| BrokerError::Storage)?;
            if t.get(key).map_err(|_| BrokerError::Storage)?.is_some() {
                InsertOutcome::AlreadySpent
            } else {
                t.insert(key, self.epoch).map_err(|_| BrokerError::Storage)?;
                InsertOutcome::Inserted
            }
        };
        w.commit().map_err(|_| BrokerError::Storage)?;
        Ok(outcome)
    }
}

impl SpentSet for RedbSpentSet {
    fn insert(&self, id: SpendId) -> InsertOutcome {
        match self.try_insert(&id) {
            Ok(o) => o,
            Err(_) => {
                // Fail closed: never let a storage fault permit a double-spend.
                tracing::error!("spent_set insert storage error (failing closed to AlreadySpent)");
                InsertOutcome::AlreadySpent
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);
    fn tmp() -> std::path::PathBuf {
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!("lluma-broker-spent-{}-{}.redb", std::process::id(), n));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn insert_then_dup_is_already_spent() {
        let path = tmp();
        let ss = RedbSpentSet::new(Store::open(&path).unwrap(), 1);
        let id = SpendId([7u8; 32]);
        assert_eq!(ss.insert(id), InsertOutcome::Inserted);
        assert_eq!(ss.insert(id), InsertOutcome::AlreadySpent);
        assert_eq!(ss.insert(SpendId([8u8; 32])), InsertOutcome::Inserted);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn spent_set_survives_restart() {
        // The #2 restart-respend hole, CLOSED: a spent token stays spent after
        // the process (Store) is dropped and the same file is reopened.
        let path = tmp();
        let id = SpendId([9u8; 32]);
        {
            let ss = RedbSpentSet::new(Store::open(&path).unwrap(), 1);
            assert_eq!(ss.insert(id), InsertOutcome::Inserted);
        } // drop Store — models a crash/restart
        {
            let ss = RedbSpentSet::new(Store::open(&path).unwrap(), 1);
            assert_eq!(
                ss.insert(id),
                InsertOutcome::AlreadySpent,
                "durable spent-set MUST reject a respend after restart"
            );
        }
        let _ = std::fs::remove_file(&path);
    }
}
