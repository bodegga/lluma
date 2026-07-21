//! Usage-receipt ingest — the host-crediting path. Controller-authored
//! (security-critical; Fable must-fix 1 + 4).
//!
//! A receipt credits its host **exactly 1 credit** (single `DENOMINATION`) — the
//! `units` field is an audit/metering bound only and is NEVER multiplied into the
//! credited amount. This makes a self-dealing host+consumer loop strictly
//! zero-sum, so Sybil loss stays bounded by the daily trial budget (R8) instead
//! of inflating without limit.
//!
//! Acceptance requires, atomically in ONE write transaction (RECEIPTS + LEDGER):
//!   1. the host is registered (`HOSTS`);
//!   2. the receipt signature verifies under the host's pubkey (`host_account`);
//!   3. `units ≤ units_audit_cap`;
//!   4. the `spend_id` is burned (present in `SPENT`) — no receipt without work;
//!   5. `SPEND_HOST[spend_id] == host_account` — the spend was forwarded to THIS
//!      host (blocks receipt theft if a spend_id ever leaks);
//!   6. RECEIPTS insert-if-absent (host idempotency) — a resubmit is credited once.

use redb::ReadableTable;

use lluma_core::proto::v1::ReceiptSubmit;
use lluma_core::wire::{AccountPublicKey, ReceiptSignature};

use crate::config::BrokerConfig;
use crate::error::BrokerError;
use crate::store::{
    LedgerRow, ReceiptRow, Store, HOSTS, LEDGER, RECEIPTS, SPEND_HOST, SPENT,
};

#[derive(Debug, PartialEq, Eq)]
pub enum IngestOutcome {
    /// Recorded and credited exactly 1 to the host.
    Credited,
    /// A receipt for this `spend_id` was already credited (idempotent no-op).
    AlreadyCredited,
    UnknownHost,
    /// Malformed DTO (shape/length) — distinct from a signature failure.
    BadRequest,
    BadSignature,
    /// The `spend_id` was never burned (not present in the spent-set).
    NoBurnedSpend,
    /// The spend was forwarded to a different host than the receipt claims.
    WrongHost,
    /// `units` exceeds the audit cap.
    OverCap,
}

/// Ingest a signed usage receipt. See module docs for the acceptance rules.
pub fn ingest(
    store: &Store,
    submit: &ReceiptSubmit,
    cfg: &BrokerConfig,
) -> Result<IngestOutcome, BrokerError> {
    if submit.validate().is_err() {
        return Ok(IngestOutcome::BadRequest);
    }
    let body = &submit.body;
    let host_pk = AccountPublicKey(body.host_account.to_vec());
    let sig = ReceiptSignature(submit.sig.clone());
    // Verify the signature FIRST — never act on unauthenticated body fields
    // (Fable should-fix 4: verify-then-inspect).
    if lluma_crypto::account::receipt_verify(&host_pk, body, &sig).is_err() {
        return Ok(IngestOutcome::BadSignature);
    }
    // `units` is authenticated now; it is an audit bound only (never credited).
    if body.units > cfg.units_audit_cap {
        return Ok(IngestOutcome::OverCap);
    }
    let account_id = lluma_crypto::account::account_fingerprint(&host_pk);

    store.with_write(|w| {
        let spend_key: &[u8] = &body.spend_id;

        // (1) host registered?
        {
            let hosts = w.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
            if hosts
                .get(&body.host_account[..])
                .map_err(|_| BrokerError::Storage)?
                .is_none()
            {
                return Ok(IngestOutcome::UnknownHost);
            }
        }
        // (4) spend_id burned?
        {
            let spent = w.open_table(SPENT).map_err(|_| BrokerError::Storage)?;
            if spent.get(spend_key).map_err(|_| BrokerError::Storage)?.is_none() {
                return Ok(IngestOutcome::NoBurnedSpend);
            }
        }
        // (5) spend forwarded to THIS host?
        {
            let sh = w.open_table(SPEND_HOST).map_err(|_| BrokerError::Storage)?;
            let bound = sh
                .get(spend_key)
                .map_err(|_| BrokerError::Storage)?
                .map(|v| v.value().to_vec());
            if bound.as_deref() != Some(&body.host_account[..]) {
                return Ok(IngestOutcome::WrongHost);
            }
        }
        // (6) idempotency + (record + credit) atomically.
        let mut receipts = w.open_table(RECEIPTS).map_err(|_| BrokerError::Storage)?;
        if receipts
            .get(spend_key)
            .map_err(|_| BrokerError::Storage)?
            .is_some()
        {
            return Ok(IngestOutcome::AlreadyCredited);
        }
        let row = ReceiptRow {
            host_account: body.host_account,
            model_id: body.model_id.clone(),
            tier: body.tier,
            units: body.units,
            epoch: body.epoch as u64, // widen u32 → u64 at the store boundary
            timestamp_h: body.timestamp_h,
            sig: submit.sig.clone(),
        };
        let rb = postcard::to_stdvec(&row).map_err(|_| BrokerError::Storage)?;
        receipts.insert(spend_key, rb.as_slice()).map_err(|_| BrokerError::Storage)?;

        // Credit the host ledger EXACTLY 1 (never `units`).
        let mut ledger = w.open_table(LEDGER).map_err(|_| BrokerError::Storage)?;
        let lkey: &[u8] = &account_id.0;
        let mut lrow: LedgerRow = match ledger.get(lkey).map_err(|_| BrokerError::Storage)? {
            Some(v) => postcard::from_bytes(v.value()).map_err(|_| BrokerError::Storage)?,
            None => LedgerRow::default(),
        };
        lrow.balance = lrow.balance.saturating_add(1);
        lrow.earned = lrow.earned.saturating_add(1);
        let lb = postcard::to_stdvec(&lrow).map_err(|_| BrokerError::Storage)?;
        ledger.insert(lkey, lb.as_slice()).map_err(|_| BrokerError::Storage)?;

        Ok(IngestOutcome::Credited)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lluma_core::wire::{AccountId, Mnemonic, UsageReceiptBody};
    use lluma_core::ModelId;
    use lluma_crypto::account::{account_fingerprint, derive_keypair_from_seed, receipt_sign};
    use redb::ReadableDatabase;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);
    fn tmp() -> std::path::PathBuf {
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!("lluma-broker-rcpt-{}-{}.redb", std::process::id(), n));
        let _ = std::fs::remove_file(&p);
        p
    }

    // Register a host row + burn a spend bound to it, so a receipt can be valid.
    fn setup_host_and_spend(
        s: &Store,
        seed: u8,
        spend_id: [u8; 32],
    ) -> ([u8; 32], lluma_core::wire::AccountSecretKey) {
        let (sk, pk) = derive_keypair_from_seed(&Mnemonic([seed; 16])).unwrap();
        let pk32: [u8; 32] = pk.0.as_slice().try_into().unwrap();
        s.with_write(|w| {
            use crate::store::{HostRow, HOST_ACTIVE};
            let mut hosts = w.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
            let row = HostRow {
                hpke_pk: vec![1; 32],
                ingress_addr: "http://203.0.113.1:9000".into(),
                models: vec![ModelId("m".into())],
                status: HOST_ACTIVE,
                hb_counter: 1,
                last_hb: 0,
                load_bucket: 0,
                admit_progress: 3,
            };
            let b = postcard::to_stdvec(&row).unwrap();
            hosts.insert(pk32.as_slice(), b.as_slice()).map_err(|_| BrokerError::Storage)?;
            let mut spent = w.open_table(SPENT).map_err(|_| BrokerError::Storage)?;
            spent.insert(spend_id.as_slice(), 1u64).map_err(|_| BrokerError::Storage)?;
            let mut sh = w.open_table(SPEND_HOST).map_err(|_| BrokerError::Storage)?;
            sh.insert(spend_id.as_slice(), pk32.as_slice()).map_err(|_| BrokerError::Storage)?;
            Ok(())
        })
        .unwrap();
        (pk32, sk)
    }

    fn receipt(
        host_account: [u8; 32],
        sk: &lluma_core::wire::AccountSecretKey,
        spend_id: [u8; 32],
        units: u32,
    ) -> ReceiptSubmit {
        let body = UsageReceiptBody {
            version: 1,
            host_account,
            model_id: ModelId("m".into()),
            tier: 0,
            units,
            spend_id,
            epoch: 1,
            timestamp_h: 100,
        };
        let sig = receipt_sign(sk, &body).unwrap();
        ReceiptSubmit { body, sig: sig.0 }
    }

    fn balance(s: &Store, acct: &AccountId) -> u64 {
        s.db()
            .begin_read()
            .ok()
            .and_then(|r| r.open_table(LEDGER).ok().map(|t| (r, t)))
            .and_then(|(_r, t)| t.get(acct.0.as_slice()).ok().flatten().map(|v| {
                postcard::from_bytes::<LedgerRow>(v.value()).map(|x| x.balance).unwrap_or(0)
            }))
            .unwrap_or(0)
    }

    #[test]
    fn valid_receipt_credits_exactly_one_and_is_idempotent() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        let spend = [3u8; 32];
        let (host, sk) = setup_host_and_spend(&s, 1, spend);
        let acct = account_fingerprint(&AccountPublicKey(host.to_vec()));
        // units = 4 (the cap) but credit is exactly 1 regardless.
        let r = receipt(host, &sk, spend, 4);
        assert_eq!(ingest(&s, &r, &cfg).unwrap(), IngestOutcome::Credited);
        assert_eq!(balance(&s, &acct), 1, "credit is 1, NOT units");
        // Resubmit ⇒ credited once.
        assert_eq!(ingest(&s, &r, &cfg).unwrap(), IngestOutcome::AlreadyCredited);
        assert_eq!(balance(&s, &acct), 1);
    }

    #[test]
    fn over_cap_units_rejected() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        let spend = [4u8; 32];
        let (host, sk) = setup_host_and_spend(&s, 2, spend);
        let r = receipt(host, &sk, spend, cfg.units_audit_cap + 1);
        assert_eq!(ingest(&s, &r, &cfg).unwrap(), IngestOutcome::OverCap);
    }

    #[test]
    fn receipt_without_burned_spend_rejected() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        // Host registered, but the spend_id was never burned.
        let (sk, pk) = derive_keypair_from_seed(&Mnemonic([5u8; 16])).unwrap();
        let host: [u8; 32] = pk.0.as_slice().try_into().unwrap();
        s.with_write(|w| {
            use crate::store::{HostRow, HOST_ACTIVE};
            let mut hosts = w.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
            let row = HostRow { hpke_pk: vec![1;32], ingress_addr: "http://203.0.113.2:9000".into(), models: vec![ModelId("m".into())], status: HOST_ACTIVE, hb_counter: 1, last_hb: 0, load_bucket: 0, admit_progress: 3 };
            let b = postcard::to_stdvec(&row).unwrap();
            hosts.insert(host.as_slice(), b.as_slice()).map_err(|_| BrokerError::Storage)?;
            Ok(())
        }).unwrap();
        let r = receipt(host, &sk, [9u8; 32], 1);
        assert_eq!(ingest(&s, &r, &cfg).unwrap(), IngestOutcome::NoBurnedSpend);
    }

    #[test]
    fn receipt_for_wrong_host_rejected() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        let spend = [6u8; 32];
        let (_host_a, _sk_a) = setup_host_and_spend(&s, 6, spend); // spend bound to host A
        // Host B is registered too, and signs a receipt for A's spend.
        let (sk_b, pk_b) = derive_keypair_from_seed(&Mnemonic([7u8; 16])).unwrap();
        let host_b: [u8; 32] = pk_b.0.as_slice().try_into().unwrap();
        s.with_write(|w| {
            use crate::store::{HostRow, HOST_ACTIVE};
            let mut hosts = w.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
            let row = HostRow { hpke_pk: vec![1;32], ingress_addr: "http://203.0.113.3:9000".into(), models: vec![ModelId("m".into())], status: HOST_ACTIVE, hb_counter: 1, last_hb: 0, load_bucket: 0, admit_progress: 3 };
            let b = postcard::to_stdvec(&row).unwrap();
            hosts.insert(host_b.as_slice(), b.as_slice()).map_err(|_| BrokerError::Storage)?;
            Ok(())
        }).unwrap();
        let r = receipt(host_b, &sk_b, spend, 1);
        assert_eq!(ingest(&s, &r, &cfg).unwrap(), IngestOutcome::WrongHost);
    }

    #[test]
    fn bad_signature_rejected() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        let spend = [8u8; 32];
        let (host, sk) = setup_host_and_spend(&s, 8, spend);
        let mut r = receipt(host, &sk, spend, 1);
        r.sig[0] ^= 0xff;
        assert_eq!(ingest(&s, &r, &cfg).unwrap(), IngestOutcome::BadSignature);
    }

    #[test]
    fn unregistered_host_rejected() {
        let cfg = BrokerConfig::for_test();
        let s = Store::open(&tmp()).unwrap();
        // Burn a spend but never register the host.
        let spend = [10u8; 32];
        let (sk, pk) = derive_keypair_from_seed(&Mnemonic([11u8; 16])).unwrap();
        let host: [u8; 32] = pk.0.as_slice().try_into().unwrap();
        s.with_write(|w| {
            let mut spent = w.open_table(SPENT).map_err(|_| BrokerError::Storage)?;
            spent.insert(spend.as_slice(), 1u64).map_err(|_| BrokerError::Storage)?;
            let mut sh = w.open_table(SPEND_HOST).map_err(|_| BrokerError::Storage)?;
            sh.insert(spend.as_slice(), host.as_slice()).map_err(|_| BrokerError::Storage)?;
            Ok(())
        }).unwrap();
        let r = receipt(host, &sk, spend, 1);
        assert_eq!(ingest(&s, &r, &cfg).unwrap(), IngestOutcome::UnknownHost);
    }
}
