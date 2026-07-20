//! The durable redb store shared by the ledger, spent-set, registry, receipts,
//! counters, and anti-Sybil trial accounting. redb is a pure-Rust ACID embedded
//! database (no C toolchain — see spec R4). One `Database` behind an `Arc`; redb
//! serializes writers internally.
//!
//! Multi-table atomic units go through [`Store::with_write`] — a single write
//! transaction the caller composes across tables (receipt ingest = RECEIPTS +
//! LEDGER; trial grant = TRIAL_ACCTS + TRIAL_BUDGET + LEDGER + COUNTERS; redeem =
//! SPENT + SPEND_HOST + COUNTERS). **No write transaction is ever held across an
//! `.await`** — async handlers wrap store calls in `spawn_blocking`. Never call a
//! method that opens its own write-txn (e.g. `RedbLedger::grant`) from inside a
//! `with_write` closure: redb is single-writer and that self-deadlocks.

use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadTransaction, ReadableDatabase, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};

use lluma_core::ModelId;

use crate::error::BrokerError;

/// spent-set: `spend_id (32 B) -> epoch`. Presence = spent (double-spend arbiter).
pub(crate) const SPENT: TableDefinition<&[u8], u64> = TableDefinition::new("spent_set");
/// ledger: `account_id (32 B) -> postcard(LedgerRow)`.
pub(crate) const LEDGER: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ledger");
/// receipts: `spend_id (32 B) -> postcard(ReceiptRow)`. Presence = credited (host idempotency).
pub(crate) const RECEIPTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("receipts");
/// hosts: `host_account (32 B) -> postcard(HostRow)`.
pub(crate) const HOSTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("hosts");
/// counters: `token_epoch -> postcard(CounterRow)` (keyed by TOKEN epoch, not wall-clock).
pub(crate) const COUNTERS: TableDefinition<u64, &[u8]> = TableDefinition::new("counters");
/// trial accounts: `account (32 B) -> day` (one trial grant per account; never purged).
pub(crate) const TRIAL_ACCTS: TableDefinition<&[u8], u64> = TableDefinition::new("trial_accts");
/// trial budget: `day -> credits granted that day` (global daily Sybil bound).
pub(crate) const TRIAL_BUDGET: TableDefinition<u64, u64> = TableDefinition::new("trial_budget");
/// spend→host binding: `spend_id (32 B) -> host_account (32 B)`. Records which
/// host a spend was forwarded to, so a receipt can only be claimed by that host.
pub(crate) const SPEND_HOST: TableDefinition<&[u8], &[u8]> = TableDefinition::new("spend_host");

/// A registered host. `status`: 0 = pending, 1 = active. Only active hosts enter
/// the signed snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRow {
    pub hpke_pk: Vec<u8>,
    pub ingress_addr: String,
    pub models: Vec<ModelId>,
    pub status: u8,
    pub hb_counter: u64,
    pub last_hb: u64,
    pub load_bucket: u8,
    pub admit_progress: u32,
}

/// Host status constants for `HostRow::status`.
pub const HOST_PENDING: u8 = 0;
pub const HOST_ACTIVE: u8 = 1;

/// A credited usage receipt (persisted for idempotency + audit). `units` is an
/// audit/metering bound only — it is NEVER multiplied into credited amount
/// (exactly 1 credit per receipt; Fable ruling — prevents self-dealing inflation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptRow {
    pub host_account: [u8; 32],
    pub model_id: ModelId,
    pub tier: u8,
    pub units: u32,
    pub epoch: u64,
    pub timestamp_h: u32,
    pub sig: Vec<u8>,
}

/// Per-token-epoch invariant counters. The tripwire refuses redeem the instant
/// `redeemed > issued`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CounterRow {
    pub issued: u64,
    pub redeemed: u64,
    pub trial_granted: u64,
}

/// A handle to the durable database. Cheaply cloneable (shared `Arc`).
#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
}

impl Store {
    /// Open (or create) the database at `path` and ensure every table exists.
    pub fn open(path: &Path) -> Result<Self, BrokerError> {
        let db = Database::create(path).map_err(|_| BrokerError::Storage)?;
        let w = db.begin_write().map_err(|_| BrokerError::Storage)?;
        {
            w.open_table(SPENT).map_err(|_| BrokerError::Storage)?;
            w.open_table(LEDGER).map_err(|_| BrokerError::Storage)?;
            w.open_table(RECEIPTS).map_err(|_| BrokerError::Storage)?;
            w.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
            w.open_table(COUNTERS).map_err(|_| BrokerError::Storage)?;
            w.open_table(TRIAL_ACCTS).map_err(|_| BrokerError::Storage)?;
            w.open_table(TRIAL_BUDGET).map_err(|_| BrokerError::Storage)?;
            w.open_table(SPEND_HOST).map_err(|_| BrokerError::Storage)?;
        }
        w.commit().map_err(|_| BrokerError::Storage)?;
        Ok(Store { db: Arc::new(db) })
    }

    pub(crate) fn db(&self) -> &Database {
        &self.db
    }

    /// Run `f` inside ONE write transaction spanning any tables it opens.
    /// Commits iff `f` returns `Ok`; on `Err` (or panic) the transaction is
    /// dropped uncommitted → redb aborts it, leaving NO partial writes. This is
    /// the multi-table atomicity backbone; fail-closed to `BrokerError::Storage`.
    ///
    /// The closure MUST NOT `.await` and MUST NOT call another method that opens
    /// its own write-txn (single-writer self-deadlock).
    pub fn with_write<T>(
        &self,
        f: impl FnOnce(&WriteTransaction) -> Result<T, BrokerError>,
    ) -> Result<T, BrokerError> {
        let w = self.db.begin_write().map_err(|_| BrokerError::Storage)?;
        let out = f(&w)?; // Err ⇒ `w` dropped uncommitted ⇒ aborted (no partial writes).
        w.commit().map_err(|_| BrokerError::Storage)?;
        Ok(out)
    }

    /// Run `f` inside a read transaction (a consistent point-in-time snapshot).
    pub fn with_read<T>(
        &self,
        f: impl FnOnce(&ReadTransaction) -> Result<T, BrokerError>,
    ) -> Result<T, BrokerError> {
        let r = self.db.begin_read().map_err(|_| BrokerError::Storage)?;
        f(&r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::ReadableDatabase;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);
    fn tmp() -> std::path::PathBuf {
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!("lluma-broker-store-{}-{}.redb", std::process::id(), n));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn with_write_commits_all_tables_atomically() {
        let path = tmp();
        let s = Store::open(&path).unwrap();
        // Write to two tables in one txn.
        s.with_write(|w| {
            let mut hosts = w.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
            let row = HostRow {
                hpke_pk: vec![1, 2, 3],
                ingress_addr: "http://127.0.0.1:9000".into(),
                models: vec![ModelId("m".into())],
                status: HOST_ACTIVE,
                hb_counter: 5,
                last_hb: 100,
                load_bucket: 2,
                admit_progress: 3,
            };
            let bytes = postcard::to_stdvec(&row).map_err(|_| BrokerError::Storage)?;
            hosts.insert([7u8; 32].as_slice(), bytes.as_slice()).map_err(|_| BrokerError::Storage)?;
            let mut counters = w.open_table(COUNTERS).map_err(|_| BrokerError::Storage)?;
            let c = CounterRow { issued: 9, redeemed: 1, trial_granted: 0 };
            let cb = postcard::to_stdvec(&c).map_err(|_| BrokerError::Storage)?;
            counters.insert(1u64, cb.as_slice()).map_err(|_| BrokerError::Storage)?;
            Ok(())
        })
        .unwrap();

        // Both writes are visible.
        let r = s.db().begin_read().unwrap();
        let hosts = r.open_table(HOSTS).unwrap();
        let hb = hosts.get([7u8; 32].as_slice()).unwrap().unwrap();
        let hr: HostRow = postcard::from_bytes(hb.value()).unwrap();
        assert_eq!(hr.hb_counter, 5);
        let counters = r.open_table(COUNTERS).unwrap();
        let cb = counters.get(1u64).unwrap().unwrap();
        let cr: CounterRow = postcard::from_bytes(cb.value()).unwrap();
        assert_eq!(cr.issued, 9);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn with_write_err_rolls_back_all_writes() {
        let path = tmp();
        let s = Store::open(&path).unwrap();
        // A closure that writes then returns Err must leave NOTHING behind.
        let res: Result<(), BrokerError> = s.with_write(|w| {
            let mut hosts = w.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
            hosts.insert([8u8; 32].as_slice(), [0u8; 4].as_slice()).map_err(|_| BrokerError::Storage)?;
            Err(BrokerError::Storage) // abort
        });
        assert!(res.is_err());
        let r = s.db().begin_read().unwrap();
        let hosts = r.open_table(HOSTS).unwrap();
        assert!(hosts.get([8u8; 32].as_slice()).unwrap().is_none(), "aborted write must not persist");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rows_persist_across_reopen() {
        let path = tmp();
        {
            let s = Store::open(&path).unwrap();
            s.with_write(|w| {
                let mut t = w.open_table(RECEIPTS).map_err(|_| BrokerError::Storage)?;
                let row = ReceiptRow {
                    host_account: [4u8; 32],
                    model_id: ModelId("m".into()),
                    tier: 0,
                    units: 3,
                    epoch: 1,
                    timestamp_h: 42,
                    sig: vec![9u8; 64],
                };
                let b = postcard::to_stdvec(&row).map_err(|_| BrokerError::Storage)?;
                t.insert([5u8; 32].as_slice(), b.as_slice()).map_err(|_| BrokerError::Storage)?;
                Ok(())
            })
            .unwrap();
        }
        {
            let s = Store::open(&path).unwrap();
            let r = s.db().begin_read().unwrap();
            let t = r.open_table(RECEIPTS).unwrap();
            let v = t.get([5u8; 32].as_slice()).unwrap().unwrap();
            let row: ReceiptRow = postcard::from_bytes(v.value()).unwrap();
            assert_eq!(row.units, 3);
            assert_eq!(row.host_account, [4u8; 32]);
        }
        let _ = std::fs::remove_file(&path);
    }
}
