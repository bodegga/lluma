//! Client-side snapshot verification (host discovery). Mirrors the broker's
//! signing so we can assert the client accepts a genuine snapshot and rejects
//! a tampered/mis-signed one — without pulling in the broker crate.

use lluma_client::verify_snapshot;
use lluma_core::proto::v1::SnapshotResponse;
use lluma_core::wire::{AccountSecretKey, Mnemonic, SnapshotBody, SnapshotHeader, SnapshotHostEntry};
use lluma_crypto::account::{derive_keypair_from_seed, snapshot_sign};

const BUCKET: usize = 65_536;

fn sign_snapshot(body: &SnapshotBody, sk: &AccountSecretKey) -> SnapshotResponse {
    let enc = postcard::to_stdvec(body).unwrap();
    let mut padded = vec![0u8; BUCKET];
    let len = enc.len() as u32;
    padded[0..4].copy_from_slice(&len.to_le_bytes());
    padded[4..4 + enc.len()].copy_from_slice(&enc);
    let sig = snapshot_sign(sk, &padded).unwrap();
    SnapshotResponse { body: padded, sig: sig.0 }
}

fn sample_body() -> SnapshotBody {
    SnapshotBody {
        header: SnapshotHeader { epoch: 1, issued_at_h: 1000, issuer_key_id: [7u8; 32] },
        hosts: vec![SnapshotHostEntry {
            host_account: [1u8; 32],
            hpke_pk: vec![0x42; 32],
            models: vec![],
            tier_flags: 0,
            load_bucket: 0,
            freshness_bucket: 0,
        }],
    }
}

#[test]
fn accepts_genuine_snapshot() {
    let (sk, pk) = derive_keypair_from_seed(&Mnemonic([99u8; 16])).unwrap();
    let sr = sign_snapshot(&sample_body(), &sk);
    let body = verify_snapshot(&pk, &sr).unwrap();
    assert_eq!(body.hosts.len(), 1);
    assert_eq!(body.hosts[0].host_account, [1u8; 32]);
}

#[test]
fn rejects_wrong_key() {
    let (sk, _pk) = derive_keypair_from_seed(&Mnemonic([99u8; 16])).unwrap();
    let (_sk2, wrong) = derive_keypair_from_seed(&Mnemonic([50u8; 16])).unwrap();
    let sr = sign_snapshot(&sample_body(), &sk);
    assert!(verify_snapshot(&wrong, &sr).is_err());
}

#[test]
fn rejects_tampered_body() {
    let (sk, pk) = derive_keypair_from_seed(&Mnemonic([99u8; 16])).unwrap();
    let mut sr = sign_snapshot(&sample_body(), &sk);
    sr.body[100] ^= 0xff;
    assert!(verify_snapshot(&pk, &sr).is_err());
}

#[test]
fn rejects_wrong_bucket_size() {
    let (sk, pk) = derive_keypair_from_seed(&Mnemonic([99u8; 16])).unwrap();
    let mut sr = sign_snapshot(&sample_body(), &sk);
    sr.body.truncate(1000); // not the fixed 64 KiB bucket
    assert!(verify_snapshot(&pk, &sr).is_err());
}
