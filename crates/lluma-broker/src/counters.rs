//! Per-token-epoch invariant counters and the double-spend/key-compromise
//! tripwire (Fable R11 + must-fix 5). Counters are keyed by the **token's
//! epoch** (not wall-clock) so a legitimately-redeemed `k−1` token during window
//! `k` cannot false-trip `redeemed(k) > issued(k)`.
//!
//! `issued` is bumped in the issuer's issuance transaction before signatures are
//! released (undercount would false-trip the alarm); `redeemed` is bumped in the
//! broker's redeem transaction (same write-txn as the `SPENT` insert); the redeem
//! path refuses the moment `redeemed > issued`.

use redb::{ReadableTable, ReadTransaction, WriteTransaction};

use crate::error::BrokerError;
use crate::store::{CounterRow, Store, COUNTERS};

/// Read the counter row for `epoch` inside an open write transaction.
fn read_txn(w: &WriteTransaction, epoch: u64) -> Result<CounterRow, BrokerError> {
    let t = w.open_table(COUNTERS).map_err(|_| BrokerError::Storage)?;
    let bytes = t
        .get(epoch)
        .map_err(|_| BrokerError::Storage)?
        .map(|v| v.value().to_vec());
    match bytes {
        Some(b) => postcard::from_bytes(&b).map_err(|_| BrokerError::Storage),
        None => Ok(CounterRow::default()),
    }
}

/// Persist the counter row for `epoch` inside an open write transaction.
fn write_txn(w: &WriteTransaction, epoch: u64, row: &CounterRow) -> Result<(), BrokerError> {
    let mut t = w.open_table(COUNTERS).map_err(|_| BrokerError::Storage)?;
    let bytes = postcard::to_stdvec(row).map_err(|_| BrokerError::Storage)?;
    t.insert(epoch, bytes.as_slice()).map_err(|_| BrokerError::Storage)?;
    Ok(())
}

/// Add `n` to `issued` for `epoch` (call within the issuance txn, before
/// signatures are released).
pub fn bump_issued(store: &Store, epoch: u64, n: u64) -> Result<(), BrokerError> {
    store.with_write(|w| {
        let mut c = read_txn(w, epoch)?;
        c.issued = c.issued.saturating_add(n);
        write_txn(w, epoch, &c)
    })
}

/// Add `n` to `trial_granted` for `epoch`.
pub fn bump_trial_granted(store: &Store, epoch: u64, n: u64) -> Result<(), BrokerError> {
    store.with_write(|w| {
        let mut c = read_txn(w, epoch)?;
        c.trial_granted = c.trial_granted.saturating_add(n);
        write_txn(w, epoch, &c)
    })
}

/// Bump `redeemed` for `epoch` inside the caller's write transaction (composed
/// with the `SPENT` insert in the redeem path). Returns `true` iff the invariant
/// `redeemed ≤ issued` still holds; `false` means the tripwire has fired and the
/// caller MUST refuse the redeem + alarm-log.
pub fn note_redeem_txn(w: &WriteTransaction, epoch: u64) -> Result<bool, BrokerError> {
    let mut c = read_txn(w, epoch)?;
    c.redeemed = c.redeemed.saturating_add(1);
    let ok = c.redeemed <= c.issued;
    write_txn(w, epoch, &c)?;
    Ok(ok)
}

/// Read the counter row for `epoch` inside an open read transaction.
fn read_ro(r: &ReadTransaction, epoch: u64) -> Result<CounterRow, BrokerError> {
    let t = r.open_table(COUNTERS).map_err(|_| BrokerError::Storage)?;
    let bytes = t
        .get(epoch)
        .map_err(|_| BrokerError::Storage)?
        .map(|v| v.value().to_vec());
    match bytes {
        Some(b) => postcard::from_bytes(&b).map_err(|_| BrokerError::Storage),
        None => Ok(CounterRow::default()),
    }
}

/// Read the counter row for `epoch` (point-in-time). Uses a READ transaction so
/// an operator dashboard poll never contends for the single global writer.
pub fn read(store: &Store, epoch: u64) -> Result<CounterRow, BrokerError> {
    store.with_read(|r| read_ro(r, epoch))
}

/// Whether the `redeemed ≤ issued` invariant currently holds for `epoch`.
pub fn invariant_holds(store: &Store, epoch: u64) -> Result<bool, BrokerError> {
    let c = read(store, epoch)?;
    Ok(c.redeemed <= c.issued)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);
    fn tmp() -> std::path::PathBuf {
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!("lluma-broker-ctr-{}-{}.redb", std::process::id(), n));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn issued_and_trial_accumulate_per_epoch() {
        let s = Store::open(&tmp()).unwrap();
        bump_issued(&s, 7, 5).unwrap();
        bump_issued(&s, 7, 3).unwrap();
        bump_trial_granted(&s, 7, 20).unwrap();
        let c = read(&s, 7).unwrap();
        assert_eq!(c.issued, 8);
        assert_eq!(c.trial_granted, 20);
        // A different epoch is independent.
        assert_eq!(read(&s, 8).unwrap().issued, 0);
    }

    #[test]
    fn redeem_within_issued_holds_then_extra_redeem_trips() {
        let s = Store::open(&tmp()).unwrap();
        bump_issued(&s, 1, 2).unwrap();
        // Two redeems: invariant holds each time.
        for _ in 0..2 {
            let ok = s.with_write(|w| note_redeem_txn(w, 1)).unwrap();
            assert!(ok, "redeemed <= issued must hold");
        }
        assert!(invariant_holds(&s, 1).unwrap());
        // A synthetic THIRD redeem (no matching issue) trips the tripwire.
        let ok = s.with_write(|w| note_redeem_txn(w, 1)).unwrap();
        assert!(!ok, "3rd redeem with issued=2 must trip the alarm");
        assert!(!invariant_holds(&s, 1).unwrap());
    }

    #[test]
    fn redeemed_keyed_by_token_epoch_not_shared() {
        let s = Store::open(&tmp()).unwrap();
        bump_issued(&s, 5, 1).unwrap(); // epoch k-1
        bump_issued(&s, 6, 1).unwrap(); // epoch k
        // Redeem a k-1 token during window k: charged to epoch 5, not 6.
        assert!(s.with_write(|w| note_redeem_txn(w, 5)).unwrap());
        assert!(invariant_holds(&s, 5).unwrap());
        assert!(invariant_holds(&s, 6).unwrap());
        assert_eq!(read(&s, 6).unwrap().redeemed, 0);
    }
}
