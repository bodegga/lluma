//! `RedbLedger` — the durable credit ledger. Implements the #2 `CreditLedger`
//! trait and **fails closed** on storage errors (`debit → InsufficientCredits`,
//! `balance → 0`, `grant → best-effort + log`), so a disk fault denies service
//! rather than minting or over-spending credits.

use redb::{ReadableDatabase, ReadableTable};

use lluma_core::wire::AccountId;
use lluma_issuer::ledger::CreditLedger;
use lluma_issuer::IssuerError;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;
use crate::store::{Store, LEDGER};

#[derive(Debug, Default, Serialize, Deserialize)]
struct LedgerRow {
    balance: u64,
    earned: u64,
    spent: u64,
}

pub struct RedbLedger {
    store: Store,
}

impl RedbLedger {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    fn read_balance(&self, account: &AccountId) -> Result<u64, BrokerError> {
        let r = self.store.db().begin_read().map_err(|_| BrokerError::Storage)?;
        let t = r.open_table(LEDGER).map_err(|_| BrokerError::Storage)?;
        let key: &[u8] = &account.0;
        match t.get(key).map_err(|_| BrokerError::Storage)? {
            Some(v) => Ok(postcard::from_bytes::<LedgerRow>(v.value())
                .map_err(|_| BrokerError::Storage)?
                .balance),
            None => Ok(0),
        }
    }

    /// Read-modify-write a row under one write transaction. `f` mutates the row
    /// and returns the caller-facing result; storage failures are surfaced as
    /// the outer `Err`.
    fn mutate(
        &self,
        account: &AccountId,
        f: impl FnOnce(&mut LedgerRow) -> Result<(), IssuerError>,
    ) -> Result<Result<(), IssuerError>, BrokerError> {
        let key: &[u8] = &account.0;
        let w = self.store.db().begin_write().map_err(|_| BrokerError::Storage)?;
        let outcome = {
            let mut t = w.open_table(LEDGER).map_err(|_| BrokerError::Storage)?;
            let mut row = match t.get(key).map_err(|_| BrokerError::Storage)? {
                Some(v) => {
                    postcard::from_bytes::<LedgerRow>(v.value()).map_err(|_| BrokerError::Storage)?
                }
                None => LedgerRow::default(),
            };
            let res = f(&mut row);
            if res.is_ok() {
                let bytes = postcard::to_stdvec(&row).map_err(|_| BrokerError::Storage)?;
                t.insert(key, bytes.as_slice()).map_err(|_| BrokerError::Storage)?;
            }
            res
        };
        w.commit().map_err(|_| BrokerError::Storage)?;
        Ok(outcome)
    }
}

impl CreditLedger for RedbLedger {
    fn balance(&self, account: &AccountId) -> u64 {
        self.read_balance(account).unwrap_or_else(|_| {
            tracing::error!("ledger balance storage error (failing closed to 0)");
            0
        })
    }

    fn grant(&self, account: &AccountId, amount: u64) {
        let res = self.mutate(account, |row| {
            row.balance = row.balance.saturating_add(amount);
            row.earned = row.earned.saturating_add(amount);
            Ok(())
        });
        if res.is_err() {
            tracing::error!("ledger grant storage error (grant dropped)");
        }
    }

    fn debit(&self, account: &AccountId, amount: u64) -> Result<(), IssuerError> {
        match self.mutate(account, |row| {
            if row.balance >= amount {
                row.balance -= amount;
                row.spent = row.spent.saturating_add(amount);
                Ok(())
            } else {
                Err(IssuerError::InsufficientCredits)
            }
        }) {
            Ok(inner) => inner,
            Err(_) => {
                // Fail closed: a storage fault must never mint or over-spend.
                tracing::error!("ledger debit storage error (failing closed to InsufficientCredits)");
                Err(IssuerError::InsufficientCredits)
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
        p.push(format!("lluma-broker-ledger-{}-{}.redb", std::process::id(), n));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn aid(n: u8) -> AccountId {
        AccountId([n; 32])
    }

    #[test]
    fn grant_debit_balance() {
        let path = tmp();
        let l = RedbLedger::new(Store::open(&path).unwrap());
        l.grant(&aid(1), 5);
        assert_eq!(l.balance(&aid(1)), 5);
        assert!(l.debit(&aid(1), 3).is_ok());
        assert_eq!(l.balance(&aid(1)), 2);
        assert!(matches!(l.debit(&aid(1), 3), Err(IssuerError::InsufficientCredits)));
        assert_eq!(l.balance(&aid(1)), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ledger_persists_across_restart() {
        let path = tmp();
        {
            let l = RedbLedger::new(Store::open(&path).unwrap());
            l.grant(&aid(3), 10);
            assert!(l.debit(&aid(3), 3).is_ok());
            assert_eq!(l.balance(&aid(3)), 7);
        }
        {
            let l = RedbLedger::new(Store::open(&path).unwrap());
            assert_eq!(l.balance(&aid(3)), 7, "balance must survive restart");
            assert!(l.debit(&aid(3), 7).is_ok());
            assert!(matches!(l.debit(&aid(3), 1), Err(IssuerError::InsufficientCredits)));
        }
        let _ = std::fs::remove_file(&path);
    }
}
