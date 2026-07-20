//! The double-spend set — records which `SpendId`s have already been redeemed
//! so a replayed token is rejected. The trait seam (spec §8) lets Phase 1 run
//! with an in-memory `HashSet` while #4 swaps in a durable store (and closes
//! the restart-respend hole documented in the Task 10 tests).
//!
//! Privacy invariant: a `SpendId` is `BLAKE3(token)` — unlinkable to the
//! issuer's blind-signature transcript and carrying no account identity.

use std::collections::HashSet;
use std::sync::Mutex;

use lluma_core::wire::SpendId;

/// Outcome of `insert` — atomically distinguishes first observation from a
/// replay. Spec §6 redeem path returns 409 `double_spend` on `AlreadySpent`.
#[derive(Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    /// First time this id was seen — redeem accepted.
    Inserted,
    /// Already in the set — double-spend attempt rejected.
    AlreadySpent,
}

/// Spent-id tracking. `Send + Sync` for `Arc<dyn SpentSet>` in axum state.
pub trait SpentSet: Send + Sync {
    /// Atomically record `id` if absent. Returns `Inserted` the first time and
    /// `AlreadySpent` every time after — the check-and-set MUST be a single
    /// `HashSet::insert` under one guard.
    fn insert(&self, id: SpendId) -> InsertOutcome;
}

/// In-memory `HashSet`-backed spent set for Phase 1. Lost on restart — the
/// Task 10 restart-respend harness demonstrates this hole (#4 dures it).
#[derive(Default)]
pub struct InMemorySpentSet {
    inner: Mutex<HashSet<SpendId>>,
}

impl InMemorySpentSet {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SpentSet for InMemorySpentSet {
    fn insert(&self, id: SpendId) -> InsertOutcome {
        // `HashSet::insert` returns `true` iff the value was newly inserted —
        // a single atomic op under one lock, so concurrent inserts of the same
        // id observe exactly one `Inserted`.
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.insert(id) {
            InsertOutcome::Inserted
        } else {
            InsertOutcome::AlreadySpent
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::Arc;
    use std::thread;

    fn id(n: u8) -> SpendId {
        SpendId([n; 32])
    }

    #[test]
    fn first_insert_is_inserted() {
        let s = InMemorySpentSet::new();
        assert_eq!(s.insert(id(1)), InsertOutcome::Inserted);
    }

    #[test]
    fn same_id_again_is_already_spent() {
        let s = InMemorySpentSet::new();
        s.insert(id(1));
        assert_eq!(s.insert(id(1)), InsertOutcome::AlreadySpent);
    }

    #[test]
    fn different_id_is_inserted() {
        let s = InMemorySpentSet::new();
        s.insert(id(1));
        assert_eq!(s.insert(id(2)), InsertOutcome::Inserted);
        assert_eq!(s.insert(id(1)), InsertOutcome::AlreadySpent);
    }

    #[test]
    fn concurrent_inserts_of_same_id_yield_exactly_one_inserted() {
        let s = Arc::new(InMemorySpentSet::new());
        let n = 32;
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let s = Arc::clone(&s);
            handles.push(thread::spawn(move || s.insert(id(7)) == InsertOutcome::Inserted));
        }
        let inserted_count = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(inserted_count, 1, "exactly one thread must observe Inserted");
        // Final state confirms the id is durable in the set.
        assert_eq!(s.insert(id(7)), InsertOutcome::AlreadySpent);
    }

    proptest! {
        #[test]
        fn distinct_ids_all_insert(distinct in proptest::collection::vec(any::<u8>(), 1..32)) {
            let s = InMemorySpentSet::new();
            let mut inserted = 0u32;
            for b in &distinct {
                if s.insert(SpendId([*b; 32])) == InsertOutcome::Inserted {
                    inserted += 1;
                }
            }
            // Number of insertions equals number of unique byte values.
            let mut uniq = distinct.clone();
            uniq.sort_unstable();
            uniq.dedup();
            prop_assert_eq!(inserted, uniq.len() as u32);
        }
    }
}