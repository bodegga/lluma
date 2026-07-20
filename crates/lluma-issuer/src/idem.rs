//! The issue-request idempotency cache. Lets a client replay a flopped
//! `/issue` request (same `(account, request_id, blinded_batch_hash)`) and
//! receive the **already-issued** signatures without being re-debited, while a
//! replay of `(account, request_id)` with a *different* `blinded_batch_hash`
//! is rejected as a conflict (spec §5.3).
//!
//! Privacy invariant: keyed by `AccountId` (the BLAKE3 fingerprint of the
//! account pubkey — never the raw key) and `request_id` (32 B nonce). No
//! prompt plaintext, no originator IP, no raw account bytes transit this cache.

use std::collections::HashMap;
use std::sync::Mutex;

use lluma_core::proto::v1::IssueResponse;
use lluma_core::wire::AccountId;

/// Result of an idempotency lookup.
#[derive(Debug)]
pub enum IdemLookup {
    /// Never seen this `(account, request_id)` — proceed with issuance.
    Fresh,
    /// Seen with the SAME `batch_hash` — replay the stored response (no debit).
    Replay(IssueResponse),
    /// Seen with a DIFFERENT `batch_hash` — reject as conflict.
    Conflict,
}

/// Stored entry: the `batch_hash` the response was issued under, plus the
/// response itself. (`key_id` is part of `IssueResponse`.)
type Entry = ([u8; 32], IssueResponse);

/// In-memory idempotency cache. Phase 1 only — #4 adds real TTL eviction.
/// For now, growth is bounded by the ±10-min `ts_unix_s` window enforced in
/// the Task 7 handler (stale requests are rejected before `lookup`), so the
/// map need only hold the last ~10 minutes of issued batches.
pub struct IssueIdempotencyCache {
    inner: Mutex<HashMap<(AccountId, [u8; 32]), Entry>>,
}

impl IssueIdempotencyCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Look up `(account, request_id)`. `batch_hash` is the candidate batch the
    /// caller is about to issue; it is compared against the stored hash to
    /// distinguish an exact replay from a same-request-id/different-batch
    /// conflict.
    pub fn lookup(
        &self,
        account: &AccountId,
        request_id: &[u8; 32],
        batch_hash: &[u8; 32],
    ) -> IdemLookup {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match guard.get(&(*account, *request_id)) {
            None => IdemLookup::Fresh,
            Some((stored_hash, resp)) => {
                if stored_hash == batch_hash {
                    // Clone the stored response so the caller can hand it back
                    // to the client without re-running `token_issue` or
                    // re-debiting the ledger.
                    IdemLookup::Replay(resp.clone())
                } else {
                    IdemLookup::Conflict
                }
            }
        }
    }

    /// Record a completed response under `(account, request_id, batch_hash)`.
    /// Overwrites any prior entry for the same `(account, request_id)` — but
    /// the handler's `lookup`-then-`store` discipline (Task 7) guarantees we
    /// only `store` after a `Fresh` `lookup`, so a conflicting replay hits the
    /// `Conflict` branch before reaching here.
    pub fn store(
        &self,
        account: &AccountId,
        request_id: [u8; 32],
        batch_hash: [u8; 32],
        resp: IssueResponse,
    ) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert((*account, request_id), (batch_hash, resp));
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

    fn signatures_match(a: &IssueResponse, b: &IssueResponse) -> bool {
        if a.key_id != b.key_id || a.signatures.len() != b.signatures.len() {
            return false;
        }
        a.signatures
            .iter()
            .zip(b.signatures.iter())
            .all(|(x, y)| x.0 == y.0)
    }

    #[test]
    fn unseen_is_fresh() {
        let c = IssueIdempotencyCache::new();
        let r = c.lookup(&aid(1), &[2u8; 32], &[3u8; 32]);
        assert!(matches!(r, IdemLookup::Fresh));
    }

    #[test]
    fn store_then_same_triple_is_replay_with_equal_signatures() {
        let c = IssueIdempotencyCache::new();
        let account = aid(1);
        let request_id = [2u8; 32];
        let batch_hash = [3u8; 32];
        c.store(&account, request_id, batch_hash, resp(7, 3));

        let r = c.lookup(&account, &request_id, &batch_hash);
        match r {
            IdemLookup::Replay(got) => assert!(signatures_match(&got, &resp(7, 3))),
            other => panic!("expected Replay, got {other:?}"),
        }
    }

    #[test]
    fn same_account_request_id_different_hash_is_conflict() {
        let c = IssueIdempotencyCache::new();
        let account = aid(1);
        let request_id = [2u8; 32];
        let batch_hash = [3u8; 32];
        c.store(&account, request_id, batch_hash, resp(7, 3));

        let different_hash = [4u8; 32];
        let r = c.lookup(&account, &request_id, &different_hash);
        assert!(matches!(r, IdemLookup::Conflict));

        // The original triple still replays — the conflicting lookup must NOT
        // clobber the stored entry.
        let r2 = c.lookup(&account, &request_id, &batch_hash);
        assert!(matches!(r2, IdemLookup::Replay(_)));
    }

    #[test]
    fn different_account_same_request_id_is_fresh() {
        let c = IssueIdempotencyCache::new();
        let request_id = [2u8; 32];
        let batch_hash = [3u8; 32];
        c.store(&aid(1), request_id, batch_hash, resp(7, 1));

        // Another account using the same `request_id` is independent — no
        // cross-account idempotency coupling.
        let r = c.lookup(&aid(2), &request_id, &batch_hash);
        assert!(matches!(r, IdemLookup::Fresh));
    }

    #[test]
    fn different_request_id_same_account_is_fresh() {
        let c = IssueIdempotencyCache::new();
        let account = aid(1);
        let batch_hash = [3u8; 32];
        c.store(&account, [2u8; 32], batch_hash, resp(7, 1));

        let r = c.lookup(&account, &[9u8; 32], &batch_hash);
        assert!(matches!(r, IdemLookup::Fresh));
    }
}