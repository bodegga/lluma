//! Anti-Sybil trial-grant core (issuer `/v1/register`; Fable R8 + must-fix 3).
//! Controller-authored (security-critical).
//!
//! A brand-new account may claim ONE trial grant, gated by proof-of-work
//! (domain `lluma-pow-trial-v1`) and bounded by a **global daily trial-credit
//! budget** — the real Sybil boundary (PoW is only a not-free gate; a GPU
//! trivializes any feasible difficulty). All state moves in ONE write
//! transaction (TRIAL_ACCTS + TRIAL_BUDGET + LEDGER + COUNTERS).
//!
//! The HTTP layer (see broker `service.rs`) MUST return a **uniform** error for
//! both `AlreadyGranted` and `BudgetExhausted` refusals so budget state leaks no
//! per-account signal. `/v1/register` is mounted on the broker **core** router —
//! the relay→gateway-reachable, path-allowlisted surface — never the direct
//! host-ingress listener, so a consumer's `account_pk` never lands at the broker
//! alongside its IP (leak L16).

use redb::ReadableTable;

use lluma_core::proto::v1::TrialRegisterRequest;
use lluma_core::wire::AccountPublicKey;

use crate::config::BrokerConfig;
use crate::error::BrokerError;
use crate::store::{LedgerRow, Store, COUNTERS, LEDGER, TRIAL_ACCTS, TRIAL_BUDGET};

#[derive(Debug, PartialEq, Eq)]
pub enum TrialOutcome {
    /// Trial credits granted to the account.
    Granted,
    /// The account already claimed its one-time trial (per-account state — safe
    /// to signal to that account).
    AlreadyGranted,
    /// The global daily budget is exhausted (map to a UNIFORM error at the wire).
    BudgetExhausted,
    BadPow,
    BadRequest,
}

fn trial_pow_ok(cfg: &BrokerConfig, account_pk: &[u8; 32], nonce: &[u8; 8]) -> bool {
    use lluma_crypto::account::{pow_verify, POW_TRIAL_DOMAIN};
    if pow_verify(POW_TRIAL_DOMAIN, account_pk, nonce, &cfg.epoch_salt, cfg.pow_difficulty) {
        return true;
    }
    matches!(cfg.epoch_salt_prev, Some(prev)
        if pow_verify(POW_TRIAL_DOMAIN, account_pk, nonce, &prev, cfg.pow_difficulty))
}

/// Grant the one-time trial allowance for `req.body.account` on `day`, or refuse.
pub fn grant_trial(
    store: &Store,
    req: &TrialRegisterRequest,
    cfg: &BrokerConfig,
    day: u64,
) -> Result<TrialOutcome, BrokerError> {
    if req.validate().is_err() {
        return Ok(TrialOutcome::BadRequest);
    }
    let account = req.body.account;
    let nonce: [u8; 8] = match req.pow_nonce.as_slice().try_into() {
        Ok(n) => n,
        Err(_) => return Ok(TrialOutcome::BadPow),
    };
    if !trial_pow_ok(cfg, &account, &nonce) {
        return Ok(TrialOutcome::BadPow);
    }
    let account_id = lluma_crypto::account::account_fingerprint(&AccountPublicKey(account.to_vec()));

    store.with_write(|w| {
        let acct_key: &[u8] = &account;

        // One trial per account (forever guard).
        {
            let accts = w.open_table(TRIAL_ACCTS).map_err(|_| BrokerError::Storage)?;
            if accts.get(acct_key).map_err(|_| BrokerError::Storage)?.is_some() {
                return Ok(TrialOutcome::AlreadyGranted);
            }
        }
        // Global daily budget.
        let granted_today = {
            let budget = w.open_table(TRIAL_BUDGET).map_err(|_| BrokerError::Storage)?;
            let got = budget.get(day).map_err(|_| BrokerError::Storage)?;
            got.map(|v| v.value()).unwrap_or(0)
        };
        if granted_today.saturating_add(cfg.trial_grant) > cfg.daily_trial_budget {
            return Ok(TrialOutcome::BudgetExhausted);
        }

        // Commit all four tables together.
        {
            let mut accts = w.open_table(TRIAL_ACCTS).map_err(|_| BrokerError::Storage)?;
            accts.insert(acct_key, day).map_err(|_| BrokerError::Storage)?;
        }
        {
            let mut budget = w.open_table(TRIAL_BUDGET).map_err(|_| BrokerError::Storage)?;
            budget
                .insert(day, granted_today.saturating_add(cfg.trial_grant))
                .map_err(|_| BrokerError::Storage)?;
        }
        {
            let mut ledger = w.open_table(LEDGER).map_err(|_| BrokerError::Storage)?;
            let lkey: &[u8] = &account_id.0;
            let mut lrow: LedgerRow = match ledger.get(lkey).map_err(|_| BrokerError::Storage)? {
                Some(v) => postcard::from_bytes(v.value()).map_err(|_| BrokerError::Storage)?,
                None => LedgerRow::default(),
            };
            lrow.balance = lrow.balance.saturating_add(cfg.trial_grant);
            lrow.earned = lrow.earned.saturating_add(cfg.trial_grant);
            let lb = postcard::to_stdvec(&lrow).map_err(|_| BrokerError::Storage)?;
            ledger.insert(lkey, lb.as_slice()).map_err(|_| BrokerError::Storage)?;
        }
        {
            let mut counters = w.open_table(COUNTERS).map_err(|_| BrokerError::Storage)?;
            let mut crow: crate::store::CounterRow =
                match counters.get(cfg.epoch).map_err(|_| BrokerError::Storage)? {
                    Some(v) => postcard::from_bytes(v.value()).map_err(|_| BrokerError::Storage)?,
                    None => crate::store::CounterRow::default(),
                };
            crow.trial_granted = crow.trial_granted.saturating_add(cfg.trial_grant);
            let cb = postcard::to_stdvec(&crow).map_err(|_| BrokerError::Storage)?;
            counters.insert(cfg.epoch, cb.as_slice()).map_err(|_| BrokerError::Storage)?;
        }
        Ok(TrialOutcome::Granted)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lluma_core::wire::{AccountId, Mnemonic, TrialRegisterBody};
    use lluma_crypto::account::{
        account_fingerprint, derive_keypair_from_seed, pow_solve, POW_TRIAL_DOMAIN,
    };
    use redb::ReadableDatabase;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);
    fn tmp() -> std::path::PathBuf {
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!("lluma-broker-trial-{}-{}.redb", std::process::id(), n));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn account_pk(seed: u8) -> [u8; 32] {
        let (_sk, pk) = derive_keypair_from_seed(&Mnemonic([seed; 16])).unwrap();
        pk.0.as_slice().try_into().unwrap()
    }

    fn trial_req(account: [u8; 32], cfg: &BrokerConfig) -> TrialRegisterRequest {
        let nonce = pow_solve(POW_TRIAL_DOMAIN, &account, &cfg.epoch_salt, cfg.pow_difficulty);
        TrialRegisterRequest {
            body: TrialRegisterBody { version: 1, account },
            pow_nonce: nonce.to_vec(),
        }
    }

    fn balance(s: &Store, acct: &AccountId) -> u64 {
        let r = s.db().begin_read().unwrap();
        let t = r.open_table(LEDGER).unwrap();
        t.get(acct.0.as_slice())
            .unwrap()
            .map(|v| postcard::from_bytes::<LedgerRow>(v.value()).unwrap().balance)
            .unwrap_or(0)
    }

    #[test]
    fn first_grant_credits_then_second_is_idempotent_refusal() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        let acct = account_pk(1);
        let id = account_fingerprint(&AccountPublicKey(acct.to_vec()));
        assert_eq!(grant_trial(&s, &trial_req(acct, &cfg), &cfg, 20_000).unwrap(), TrialOutcome::Granted);
        assert_eq!(balance(&s, &id), cfg.trial_grant);
        // Second attempt for the same account is refused, no extra credit.
        assert_eq!(grant_trial(&s, &trial_req(acct, &cfg), &cfg, 20_000).unwrap(), TrialOutcome::AlreadyGranted);
        assert_eq!(balance(&s, &id), cfg.trial_grant);
        // trial_granted counter reflects exactly one grant.
        assert_eq!(crate::counters::read(&s, cfg.epoch).unwrap().trial_granted, cfg.trial_grant);
    }

    #[test]
    fn daily_budget_exhaustion_is_fail_closed() {
        let mut cfg = BrokerConfig::for_test();
        cfg.daily_trial_budget = cfg.trial_grant; // room for exactly one grant/day
        let s = Store::open(&tmp()).unwrap();
        assert_eq!(grant_trial(&s, &trial_req(account_pk(2), &cfg), &cfg, 5).unwrap(), TrialOutcome::Granted);
        // A different account the same day is refused — budget exhausted.
        let acct_b = account_pk(3);
        let id_b = account_fingerprint(&AccountPublicKey(acct_b.to_vec()));
        assert_eq!(grant_trial(&s, &trial_req(acct_b, &cfg), &cfg, 5).unwrap(), TrialOutcome::BudgetExhausted);
        assert_eq!(balance(&s, &id_b), 0, "refused account must not be credited");
        // The next day the budget resets.
        assert_eq!(grant_trial(&s, &trial_req(acct_b, &cfg), &cfg, 6).unwrap(), TrialOutcome::Granted);
    }

    #[test]
    fn bad_pow_rejected() {
        let mut cfg = BrokerConfig::for_test();
        cfg.pow_difficulty = 24; // zero nonce ~never passes
        let s = Store::open(&tmp()).unwrap();
        let req = TrialRegisterRequest {
            body: TrialRegisterBody { version: 1, account: account_pk(4) },
            pow_nonce: vec![0u8; 8],
        };
        assert_eq!(grant_trial(&s, &req, &cfg, 5).unwrap(), TrialOutcome::BadPow);
    }
}
