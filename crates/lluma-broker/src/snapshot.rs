//! Signed registry snapshot (Fable R10 + should-fix 3). Deterministic,
//! fixed-size (64 KiB), zero-padded after a length prefix, and signed whole with
//! the broker's dedicated registry Ed25519 key. Clients select hosts by
//! filtering this snapshot locally — there are no live "pick me a host" queries
//! (R1). Only `active` hosts appear. Controller-authored (the fixed size +
//! padding is the L4 host-count side-channel defense).

use redb::ReadableTable;

use lluma_core::proto::v1::SnapshotResponse;
use lluma_core::wire::{
    AccountPublicKey, AccountSecretKey, ReceiptSignature, SnapshotBody, SnapshotHeader,
    SnapshotHostEntry,
};

use crate::error::BrokerError;
use crate::store::{HostRow, Store, HOSTS, HOST_ACTIVE};

/// The fixed snapshot bucket size in bytes (64 KiB). A snapshot is always
/// exactly this many bytes on the wire regardless of host count (L4).
pub const SNAPSHOT_BUCKET: usize = 65_536;
/// Length-prefix width (a little-endian `u32` giving the encoded-body length).
const LEN_PREFIX: usize = 4;

/// Build a snapshot body from the store's ACTIVE hosts, in ascending
/// `host_account` order (redb key order — deterministic).
pub fn build(store: &Store, header: SnapshotHeader) -> Result<SnapshotBody, BrokerError> {
    let hosts = store.with_read(|r| {
        let table = r.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
        let mut out: Vec<SnapshotHostEntry> = Vec::new();
        let iter = table.iter().map_err(|_| BrokerError::Storage)?;
        for entry in iter {
            let (k, v) = entry.map_err(|_| BrokerError::Storage)?;
            let host_account: [u8; 32] = match k.value().try_into() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let row: HostRow =
                postcard::from_bytes(v.value()).map_err(|_| BrokerError::Storage)?;
            if row.status != HOST_ACTIVE {
                continue;
            }
            out.push(SnapshotHostEntry {
                host_account,
                hpke_pk: row.hpke_pk,
                models: row.models,
                tier_flags: 0,     // reserved (TEE/GPU tiers deferred, R12)
                load_bucket: row.load_bucket,
                freshness_bucket: 0, // reserved (coarse freshness deferred, R12)
            });
        }
        Ok(out)
    })?;
    Ok(SnapshotBody { header, hosts })
}

/// Deterministically encode + length-prefix + zero-pad a body to exactly
/// `SNAPSHOT_BUCKET` bytes. Fails closed if the encoded body does not fit
/// (never silently grows the bucket, which would leak host count).
pub(crate) fn encode_and_pad(body: &SnapshotBody) -> Result<Vec<u8>, BrokerError> {
    let enc = postcard::to_stdvec(body).map_err(|_| BrokerError::Storage)?;
    if LEN_PREFIX + enc.len() > SNAPSHOT_BUCKET {
        return Err(BrokerError::SnapshotTooLarge);
    }
    let mut out = vec![0u8; SNAPSHOT_BUCKET];
    let len = enc.len() as u32;
    out[0..LEN_PREFIX].copy_from_slice(&len.to_le_bytes());
    out[LEN_PREFIX..LEN_PREFIX + enc.len()].copy_from_slice(&enc);
    Ok(out)
}

/// Build, pad, and sign the current snapshot. The signature is over the EXACT
/// 64 KiB of padded bytes the client verifies. Signing is deterministic
/// (Ed25519, RFC 8032), so the same host set yields byte-identical output —
/// clients can cross-check.
pub fn publish(
    store: &Store,
    header: SnapshotHeader,
    registry_sk: &AccountSecretKey,
) -> Result<SnapshotResponse, BrokerError> {
    let body = build(store, header)?;
    let padded = encode_and_pad(&body)?;
    let sig = lluma_crypto::account::snapshot_sign(registry_sk, &padded)
        .map_err(|_| BrokerError::Storage)?;
    Ok(SnapshotResponse { body: padded, sig: sig.0 })
}

/// Client-side: verify the signature over the full padded bytes, strip the
/// padding via the length prefix, and decode. Fails closed on any mismatch.
pub fn verify(
    registry_pk: &AccountPublicKey,
    resp: &SnapshotResponse,
) -> Result<SnapshotBody, BrokerError> {
    if resp.validate().is_err() {
        return Err(BrokerError::SnapshotInvalid);
    }
    let sig = ReceiptSignature(resp.sig.clone());
    if lluma_crypto::account::snapshot_verify(registry_pk, &resp.body, &sig).is_err() {
        return Err(BrokerError::SnapshotInvalid);
    }
    if resp.body.len() < LEN_PREFIX {
        return Err(BrokerError::SnapshotInvalid);
    }
    let len = u32::from_le_bytes([resp.body[0], resp.body[1], resp.body[2], resp.body[3]]) as usize;
    let end = LEN_PREFIX
        .checked_add(len)
        .filter(|e| *e <= resp.body.len())
        .ok_or(BrokerError::SnapshotInvalid)?;
    postcard::from_bytes(&resp.body[LEN_PREFIX..end]).map_err(|_| BrokerError::SnapshotInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lluma_core::wire::Mnemonic;
    use lluma_core::ModelId;
    use lluma_crypto::account::derive_keypair_from_seed;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CTR: AtomicU64 = AtomicU64::new(0);
    fn tmp() -> std::path::PathBuf {
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!("lluma-broker-snap-{}-{}.redb", std::process::id(), n));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn put_host(s: &Store, account: [u8; 32], status: u8) {
        s.with_write(|w| {
            let mut hosts = w.open_table(HOSTS).map_err(|_| BrokerError::Storage)?;
            let row = HostRow {
                hpke_pk: vec![0x42; 32],
                ingress_addr: "http://203.0.113.9:9000".into(),
                models: vec![ModelId("m".into())],
                status,
                hb_counter: 1,
                last_hb: 0,
                load_bucket: 2,
                admit_progress: 3,
            };
            let b = postcard::to_stdvec(&row).unwrap();
            hosts.insert(account.as_slice(), b.as_slice()).map_err(|_| BrokerError::Storage)?;
            Ok(())
        })
        .unwrap();
    }

    fn header() -> SnapshotHeader {
        SnapshotHeader { epoch: 1, issued_at_h: 1000, issuer_key_id: [7u8; 32] }
    }

    fn registry_keys() -> (AccountSecretKey, AccountPublicKey) {
        derive_keypair_from_seed(&Mnemonic([99u8; 16])).unwrap()
    }

    #[test]
    fn only_active_hosts_appear_sorted_by_account() {
        let s = Store::open(&tmp()).unwrap();
        put_host(&s, [3u8; 32], HOST_ACTIVE);
        put_host(&s, [1u8; 32], HOST_ACTIVE);
        put_host(&s, [2u8; 32], 0); // pending — excluded
        let body = build(&s, header()).unwrap();
        assert_eq!(body.hosts.len(), 2);
        assert_eq!(body.hosts[0].host_account, [1u8; 32]);
        assert_eq!(body.hosts[1].host_account, [3u8; 32]);
    }

    #[test]
    fn publish_is_fixed_size_verifies_and_is_byte_identical() {
        let s = Store::open(&tmp()).unwrap();
        put_host(&s, [1u8; 32], HOST_ACTIVE);
        put_host(&s, [2u8; 32], HOST_ACTIVE);
        let (sk, pk) = registry_keys();
        let r1 = publish(&s, header(), &sk).unwrap();
        let r2 = publish(&s, header(), &sk).unwrap();
        assert_eq!(r1.body.len(), SNAPSHOT_BUCKET);
        assert_eq!(r1.body, r2.body, "same host set ⇒ byte-identical padded body");
        assert_eq!(r1.sig, r2.sig, "deterministic Ed25519 ⇒ identical signature");
        let back = verify(&pk, &r1).unwrap();
        assert_eq!(back.hosts.len(), 2);
        assert_eq!(back.header.epoch, 1);
    }

    #[test]
    fn verify_fails_under_wrong_key() {
        let s = Store::open(&tmp()).unwrap();
        put_host(&s, [1u8; 32], HOST_ACTIVE);
        let (sk, _pk) = registry_keys();
        let (_sk2, wrong_pk) = derive_keypair_from_seed(&Mnemonic([50u8; 16])).unwrap();
        let r = publish(&s, header(), &sk).unwrap();
        assert!(matches!(verify(&wrong_pk, &r), Err(BrokerError::SnapshotInvalid)));
    }

    #[test]
    fn verify_fails_on_tampered_body() {
        let s = Store::open(&tmp()).unwrap();
        put_host(&s, [1u8; 32], HOST_ACTIVE);
        let (sk, pk) = registry_keys();
        let mut r = publish(&s, header(), &sk).unwrap();
        r.body[100] ^= 0xff; // flip a byte inside the signed region
        assert!(matches!(verify(&pk, &r), Err(BrokerError::SnapshotInvalid)));
    }

    #[test]
    fn oversize_body_fails_closed() {
        // One entry with an absurd hpke_pk pushes the encoded body past 64 KiB.
        let body = SnapshotBody {
            header: header(),
            hosts: vec![SnapshotHostEntry {
                host_account: [1u8; 32],
                hpke_pk: vec![0u8; SNAPSHOT_BUCKET + 10],
                models: vec![],
                tier_flags: 0,
                load_bucket: 0,
                freshness_bucket: 0,
            }],
        };
        assert!(matches!(encode_and_pad(&body), Err(BrokerError::SnapshotTooLarge)));
    }
}
