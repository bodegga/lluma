//! `lluma-keygen` — generate the operator key material the co-located broker
//! origin needs (see `crates/lluma-broker/src/main.rs` env). Run ONCE, offline;
//! copy the output to the broker host with `0600` perms and back it up securely.
//! The generated files are SECRETS — never commit them.
//!
//! Usage: `lluma-keygen [OUT_DIR]` (default `./lluma-keys`).

use std::path::Path;

use lluma_crypto::tokens::issuer_keygen;

fn main() -> Result<(), String> {
    let out = std::env::args().nth(1).unwrap_or_else(|| "./lluma-keys".to_string());
    let dir = Path::new(&out);
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;

    // Issuer RSA-BSSA (RFC 9474) key pair, DER-encoded.
    let mut rng = blind_rsa_signatures::DefaultRng;
    let (sk, pk) = issuer_keygen(&mut rng).map_err(|e| format!("issuer keygen: {e}"))?;
    write(dir, "issuer_sk.der", &sk.0)?;
    write(dir, "issuer_pk.der", &pk.0)?;
    let key_id = blake3::hash(&pk.0);

    // 32-byte Ed25519 registry secret key (snapshot signing).
    let mut registry_sk = [0u8; 32];
    getrandom::getrandom(&mut registry_sk).map_err(|e| format!("getrandom: {e}"))?;
    write(dir, "registry.sk", &registry_sk)?;

    // 32-byte global PoW epoch salt (must be non-zero; the broker refuses a zero salt).
    let mut epoch_salt = [0u8; 32];
    getrandom::getrandom(&mut epoch_salt).map_err(|e| format!("getrandom: {e}"))?;
    if epoch_salt == [0u8; 32] {
        return Err("generated an all-zero epoch salt (astronomically unlikely) — re-run".into());
    }
    write(dir, "epoch_salt.bin", &epoch_salt)?;

    println!("wrote key material to {}", dir.display());
    println!("  issuer_sk.der  (RSA-BSSA secret, DER)  -> LLUMA_ISSUER_SK_DER_FILE");
    println!("  issuer_pk.der  (RSA-BSSA public, DER)  -> LLUMA_ISSUER_PK_DER_FILE");
    println!("  registry.sk    (32 B Ed25519 secret)   -> LLUMA_REGISTRY_SK_FILE");
    println!("  epoch_salt.bin (32 B, non-zero)        -> LLUMA_EPOCH_SALT_FILE");
    println!("issuer key_id (BLAKE3 of pubkey): {}", hex(key_id.as_bytes()));
    println!("SECRETS — keep offline, chmod 600 on the host, never commit.");
    Ok(())
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(dir.join(name), bytes).map_err(|e| format!("write {name}: {e}"))
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
