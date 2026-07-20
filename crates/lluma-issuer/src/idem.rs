//! The issue-request idempotency cache with **reserve-on-lookup** semantics.
//!
//! A client may replay a flopped `/issue` request (same
//! `(account, request_id, blinded_batch_hash)`) and receive the
//! **already-issued** signatures without being re-debited; a replay of
//! `(account, request_id)` with a *different* `blinded_batch_hash` is a conflict
//! (spec §5.3).
//!
//! ## Why reserve-on-lookup (concurrency safety — Fable review I-1)
//!
//! A plain "lookup returns Fresh, release the lock, then debit+sign+store" is
//! racy: two identical requests interleaved on axum's multi-threaded runtime
//! both observe `Fresh`, both debit, both sign — the account is debited twice.
//! `begin` closes that window: under a SINGLE lock acquisition it either finds a
//! prior result (`Replay`/`Conflict`), finds an in-flight reservation
//! (`InFlight`), or **inserts a `Pending` reservation and returns `Reserved`**.
//! Only the caller who gets `Reserved` proceeds to debit+sign; concurrent
//! duplicates get `InFlight` and never debit. `store` flips the reservation to
//! `Done`; `release` removes it if the reserved caller fails (debit/sign) so a
//! legitimate later retry is not permanently poisoned.
//!
//! Privacy invariant: keyed by `AccountId` (BLAKE3 fingerprint of the account
//! pubkey — never the raw key) and `request_id` (32 B nonce). No prompt
//! plaintext, no originator IP, no raw account bytes transit this cache.
//!
//! Growth: entries accrete for the process lifetime — the ±10-min `ts_unix_s`
//! window bounds *replayability*, NOT memory (a stale request is rejected before
//! `begin`, but entries already inserted are never swept here). Real TTL
//! eviction is a #4 (broker) concern.

use std::collections::HashMap;
use std::sync::Mutex;

use lluma_core::proto::v1::IssueResponse;
use lluma_core::wire::AccountId;

/// Outcome of reserving the `(account, request_id)` slot via [`IssueIdempotencyCache::begin`].
#[derive(Debug)]
pub enum BeginOutcome {
    /// Slot was free and is now reserved (`Pending`) for the caller — proceed
    /// to debit + sign + `store`.
    Reserved,
    /// A completed response exists for the SAME `batch_hash` — hand it back with
    /// no debit.
    Replay(IssueResponse),
    /// Same `(account, request_id)` seen with a DIFFERENT `batch_hash`.
    Conflict,
    /// Same `(account, request_id, batch_hash)` is currently being processed by
    /// another task (its reservation is still `Pending`).
    InFlight,
}

/// A slot is either reserved-and-in-progress or completed.
enum Entry {
    /// Reserved with this `batch_hash`; response not yet stored.
    Pending([u8; 32]),
    /// Completed: the `batch_hash` it was issued under, plus the response.
    Done([u8; 32], IssueResponse),
}

/// In-memory idempotency cache. Phase 1 only — #4 adds real TTL eviction.
pub struct IssueIdempotencyCache {
    inner: Mutex<HashMap<(AccountId, [u8; 32]), Entry>>,
}

impl IssueIdempotencyCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Atomically inspect-and-reserve `(account, request_id)` in one critical
    /// section (see the module docs for why this must be one lock acquisition).
    pub fn begin(
        &self,
        account: &AccountId,
        request_id: &[u8; 32],
        batch_hash: &[u8; 32],
    ) -> BeginOutcome {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match guard.get(&(*account, *request_id)) {
            None => {
                guard.insert((*account, *request_id), Entry::Pending(*batch_hash));
                BeginOutcome::Reserved
            }
            Some(Entry::Pending(h)) => {
                if h == batch_hash {
                    BeginOutcome::InFlight
                } else {
                    BeginOutcome::Conflict
                }
            }
            Some(Entry::Done(h, resp)) => {
                if h == batch_hash {
                    BeginOutcome::Replay(resp.clone())
                } else {
                    BeginOutcome::Conflict
                }
            }
        }
    }

    /// Flip a reservation to `Done`, recording the completed response.
    pub fn store(
        &self,
        account: &AccountId,
        request_id: [u8; 32],
        batch_hash: [u8; 32],
        resp: IssueResponse,
    ) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert((*account, request_id), Entry::Done(batch_hash, resp));
    }

    /// Remove a reservation — call after a post-`Reserved` failure (debit
    /// rejected, sign failed) so a legitimate retry stays fresh.
    pub fn release(&self, account: &AccountId, request_id: &[u8; 32]) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(&(*account, *request_id));
    }
}

impl Default for IssueIdempotencyCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lluma_core::wire::BlindSignature;

    fn aid(n: u8) -> AccountId {
        AccountId([n; 32])
    }

    fn resp(tag: u8, count: usize) -> IssueResponse {
        IssueResponse {
            key_id: [tag; 32],
            signatures: vec![BlindSignature(vec![tag; 256]); count],
        }
    }

    fn sigs_eq(a: &IssueResponse, b: &IssueResponse) -> bool {
        a.key_id == b.key_id
            && a.signatures.len() == b.signatures.len()
            && a.signatures.iter().zip(&b.signatures).all(|(x, y)| x.0 == y.0)
    }

    #[test]
    fn unseen_reserves() {
        let c = IssueIdempotencyCache::new();
        assert!(matches!(
            c.begin(&aid(1), &[2u8; 32], &[3u8; 32]),
            BeginOutcome::Reserved
        ));
    }

    #[test]
    fn second_begin_same_triple_is_in_flight_until_stored() {
        let c = IssueIdempotencyCache::new();
        let (a, r, h) = (aid(1), [2u8; 32], [3u8; 32]);
        assert!(matches!(c.begin(&a, &r, &h), BeginOutcome::Reserved));
        // Reserved but not yet stored → a concurrent duplicate is InFlight.
        assert!(matches!(c.begin(&a, &r, &h), BeginOutcome::InFlight));
    }

    #[test]
    fn store_then_same_triple_is_replay_with_equal_signatures() {
        let c = IssueIdempotencyCache::new();
        let (a, r, h) = (aid(1), [2u8; 32], [3u8; 32]);
        assert!(matches!(c.begin(&a, &r, &h), BeginOutcome::Reserved));
        c.store(&a, r, h, resp(7, 3));
        match c.begin(&a, &r, &h) {
            BeginOutcome::Replay(got) => assert!(sigs_eq(&got, &resp(7, 3))),
            other => panic!("expected Replay, got {other:?}"),
        }
    }

    #[test]
    fn different_hash_is_conflict_pending_or_done() {
        let c = IssueIdempotencyCache::new();
        let (a, r, h) = (aid(1), [2u8; 32], [3u8; 32]);
        // While Pending: different hash → Conflict.
        assert!(matches!(c.begin(&a, &r, &h), BeginOutcome::Reserved));
        assert!(matches!(c.begin(&a, &r, &[9u8; 32]), BeginOutcome::Conflict));
        // While Done: different hash → Conflict; same hash still replays.
        c.store(&a, r, h, resp(7, 3));
        assert!(matches!(c.begin(&a, &r, &[9u8; 32]), BeginOutcome::Conflict));
        assert!(matches!(c.begin(&a, &r, &h), BeginOutcome::Replay(_)));
    }

    #[test]
    fn release_frees_a_reservation() {
        let c = IssueIdempotencyCache::new();
        let (a, r, h) = (aid(1), [2u8; 32], [3u8; 32]);
        assert!(matches!(c.begin(&a, &r, &h), BeginOutcome::Reserved));
        c.release(&a, &r);
        // After release, the slot is free again.
        assert!(matches!(c.begin(&a, &r, &h), BeginOutcome::Reserved));
    }

    #[test]
    fn different_account_same_request_id_is_independent() {
        let c = IssueIdempotencyCache::new();
        let (r, h) = ([2u8; 32], [3u8; 32]);
        assert!(matches!(c.begin(&aid(1), &r, &h), BeginOutcome::Reserved));
        assert!(matches!(c.begin(&aid(2), &r, &h), BeginOutcome::Reserved));
    }

    #[test]
    fn concurrent_begins_yield_exactly_one_reserved() {
        use std::sync::Arc;
        let c = Arc::new(IssueIdempotencyCache::new());
        let (a, r, h) = (aid(5), [6u8; 32], [7u8; 32]);
        let mut handles = Vec::new();
        for _ in 0..16 {
            let c = c.clone();
            handles.push(std::thread::spawn(move || {
                matches!(c.begin(&a, &r, &h), BeginOutcome::Reserved)
            }));
        }
        let reserved = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&ok| ok)
            .count();
        assert_eq!(reserved, 1, "exactly one concurrent begin may reserve the slot");
    }
}
