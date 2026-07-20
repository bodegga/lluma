//! The durable redb store shared by the ledger and spent-set. redb is a pure-
//! Rust ACID embedded database (no C toolchain — see spec R4). One `Database`
//! behind an `Arc`; redb serializes writers internally.

use std::path::Path;
use std::sync::Arc;

use redb::{Database, TableDefinition};

use crate::error::BrokerError;

/// spent-set: `spend_id (32 B) -> epoch`. Presence = spent (double-spend arbiter).
pub(crate) const SPENT: TableDefinition<&[u8], u64> = TableDefinition::new("spent_set");
/// ledger: `account_id (32 B) -> postcard(LedgerRow)`.
pub(crate) const LEDGER: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ledger");

/// A handle to the durable database. Cheaply cloneable (shared `Arc`).
#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
}

impl Store {
    /// Open (or create) the database at `path` and ensure the tables exist.
    pub fn open(path: &Path) -> Result<Self, BrokerError> {
        let db = Database::create(path).map_err(|_| BrokerError::Storage)?;
        let w = db.begin_write().map_err(|_| BrokerError::Storage)?;
        {
            w.open_table(SPENT).map_err(|_| BrokerError::Storage)?;
            w.open_table(LEDGER).map_err(|_| BrokerError::Storage)?;
        }
        w.commit().map_err(|_| BrokerError::Storage)?;
        Ok(Store { db: Arc::new(db) })
    }

    pub(crate) fn db(&self) -> &Database {
        &self.db
    }
}
