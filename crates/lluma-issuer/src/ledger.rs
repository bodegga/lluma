//! The credit ledger — tracks per-account non-negative balances and atomically
//! debits credits when tokens are minted. The trait seam (spec §8) lets Phase
//! 1 run with an in-memory `HashMap` while #4 drops in a durable broker later.
//!
//! Privacy invariant: an `AccountId` is the BLAKE3 fingerprint of an account's
//! Ed25519 public key (never the raw key) — the ledger stores neither the
//! originator's IP nor any prompt plaintext.

use std::collections::HashMap;
use std::sync::Mutex;

use lluma_core::wire::AccountId;

use crate::IssuerError;

/// Read/grant/debit surface for credit accounting. `Send + Sync` so an axum
/// `State` can hold `Arc<dyn CreditLedger>` (Task 7).
pub trait CreditLedger: Send + Sync {
    /// Current balance for `account`; 0 if never granted.
    fn balance(&self, account: &AccountId) -> u64;
    /// Credit `amount` to `account`. Idempotent add — no upper bound enforced
    /// here (the broker in #4 may cap).
    fn grant(&self, account: &AccountId, amount: u64);
    /// Atomically subtract `amount` if the balance is sufficient, else return
    /// `Err(IssuerError::InsufficientCredits)`. The check-and-subtract MUST
    /// happen under a single guard — no `balance()`-then-`debit()` race.
    fn debit(&self, account: &AccountId, amount: u64) -> Result<(), IssuerError>;
}

/// In-memory `HashMap`-backed ledger for Phase 1 (#4 swaps in a durable impl).
#[derive(Default)]
pub struct InMemoryLedger {
    inner: Mutex<HashMap<AccountId, u64>>,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CreditLedger for InMemoryLedger {
    fn balance(&self, account: &AccountId) -> u64 {
        // Recover-from-poison: a prior holder panicked mid-mutation, but
        // refusing to lock the ledger would cascade a process-wide stall.
        // We take the guard as-is rather than panic/propagate — the trait's
        // signature returns `u64`, not `Result`, and `balance` is best-effort.
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        *guard.get(account).unwrap_or(&0)
    }

    fn grant(&self, account: &AccountId, amount: u64) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(*account).or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    fn debit(&self, account: &AccountId, amount: u64) -> Result<(), IssuerError> {
        // Single critical section: lock once, check + subtract under the guard.
        // No `balance()`-then-`debit()` race possible — `debit` is the only
        // mutate-path that needs the precondition.
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(*account).or_insert(0);
        if *entry >= amount {
            *entry -= amount;
            Ok(())
        } else {
            Err(IssuerError::InsufficientCredits)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::Arc;
    use std::thread;

    fn aid(n: u8) -> AccountId {
        AccountId([n; 32])
    }

    #[test]
    fn grant_then_balance() {
        let l = InMemoryLedger::new();
        l.grant(&aid(1), 5);
        assert_eq!(l.balance(&aid(1)), 5);
    }

    #[test]
    fn debit_partial_succeeds() {
        let l = InMemoryLedger::new();
        l.grant(&aid(1), 5);
        assert!(l.debit(&aid(1), 3).is_ok());
        assert_eq!(l.balance(&aid(1)), 2);
    }

    #[test]
    fn debit_beyond_balance_fails_and_leaves_balance_intact() {
        let l = InMemoryLedger::new();
        l.grant(&aid(1), 5);
        assert!(l.debit(&aid(1), 3).is_ok());
        let res = l.debit(&aid(1), 3);
        assert!(matches!(res, Err(IssuerError::InsufficientCredits)));
        assert_eq!(l.balance(&aid(1)), 2);
    }

    #[test]
    fn debit_to_zero_succeeds() {
        let l = InMemoryLedger::new();
        l.grant(&aid(1), 5);
        assert!(l.debit(&aid(1), 3).is_ok());
        assert!(l.debit(&aid(1), 2).is_ok());
        assert_eq!(l.balance(&aid(1)), 0);
    }

    #[test]
    fn fresh_account_has_zero_balance() {
        let l = InMemoryLedger::new();
        assert_eq!(l.balance(&aid(7)), 0);
    }

    #[test]
    fn debit_on_fresh_account_is_insufficient() {
        let l = InMemoryLedger::new();
        assert!(matches!(
            l.debit(&aid(7), 1),
            Err(IssuerError::InsufficientCredits)
        ));
        assert_eq!(l.balance(&aid(7)), 0);
    }

    fn run_concurrent_debits(n: u32, m: u64) -> (u32, u64) {
        let ledger = Arc::new(InMemoryLedger::new());
        ledger.grant(&aid(1), m);
        let mut handles = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let l = Arc::clone(&ledger);
            handles.push(thread::spawn(move || l.debit(&aid(1), 1).is_ok()));
        }
        let ok = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .filter(|ok| *ok)
            .count() as u32;
        (ok, ledger.balance(&aid(1)))
    }

    #[test]
    fn concurrent_debits_never_underflow() {
        // N threads each debit 1 from starting balance M; exactly min(N,M)
        // succeed and the final balance is max(0, M-N).
        let cases = [(0u32, 0u64), (1, 0), (1, 1), (4, 2), (2, 4), (8, 8), (16, 4)];
        for (n, m) in cases {
            let (ok, bal) = run_concurrent_debits(n, m);
            let expected_ok = n.min(m as u32);
            assert_eq!(ok, expected_ok, "n={n} m={m}: {ok} succeeded, expected {expected_ok}");
            assert_eq!(
                bal,
                m.saturating_sub(n as u64),
                "n={n} m={m}: final balance {bal} underflowed"
            );
        }
    }

    proptest! {
        #[test]
        fn concurrent_debits_balance_invariants(nthreads in 1u32..32, balance in 0u64..64) {
            let (ok, bal) = run_concurrent_debits(nthreads, balance);
            prop_assert_eq!(ok, nthreads.min(balance as u32));
            prop_assert_eq!(bal, balance.saturating_sub(nthreads as u64));
        }
    }
}