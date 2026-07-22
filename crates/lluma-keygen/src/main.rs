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

    // Persistent gateway OHTTP key (`key_id || ikm`). Enables a stable published
    // key-config across gateway restarts, which the signed bootstrap depends on.
    let mut rng = rand_core::OsRng;
    let (gw_sk, gw_kc) = lluma_crypto::ohttp::ohttp_keygen(&mut rng, 1)
        .map_err(|e| format!("gateway keygen: {e}"))?;
    write(dir, "gateway_kc.sk", &gw_sk.0)?;
    let registry_pk = lluma_crypto::account::account_public_from_secret(
        &lluma_core::wire::AccountSecretKey(registry_sk.to_vec()),
    )
    .map_err(|e| format!("registry pubkey: {e}"))?;

    println!("wrote key material to {}", dir.display());
    println!("  issuer_sk.der  (RSA-BSSA secret, DER)  -> LLUMA_ISSUER_SK_DER_FILE");
    println!("  issuer_pk.der  (RSA-BSSA public, DER)  -> LLUMA_ISSUER_PK_DER_FILE");
    println!("  registry.sk    (32 B Ed25519 secret)   -> LLUMA_REGISTRY_SK_FILE");
    println!("  epoch_salt.bin (32 B, non-zero)        -> LLUMA_EPOCH_SALT_FILE");
    println!("  gateway_kc.sk  (OHTTP secret)          -> LLUMA_GATEWAY_KC_SK_FILE");
    println!("issuer key_id (BLAKE3 of pubkey): {}", hex(key_id.as_bytes()));
    println!(
        "registry pubkey (pin in the app as LLUMA_REGISTRY_PK_B64): {}",
        b64(&registry_pk.0)
    );
    println!(
        "gateway key_config (base64, for reference): {}",
        b64(&gw_kc.0)
    );
    println!("SECRETS — keep offline, chmod 600 on the host, never commit.");
    Ok(())
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let path = dir.join(name);
    // Create the file 0600 BEFORE writing on Unix, so the secret bytes are never
    // momentarily world-readable. On other platforms fall back to a plain write
    // (the printed reminder covers host-side hardening).
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("open {name}: {e}"))?;
        f.write_all(bytes).map_err(|e| format!("write {name}: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, bytes).map_err(|e| format!("write {name}: {e}"))?;
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
