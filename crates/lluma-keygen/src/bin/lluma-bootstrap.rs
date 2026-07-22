//! `lluma-bootstrap` — operator tool to (a) print the registry public key to
//! pin in the app, and (b) sign a client bootstrap document the relay mirrors
//! at `GET /v1/bootstrap`. Run offline/on the broker host where `registry.sk`
//! lives; the secret never needs to move.
//!
//! Usage:
//!   lluma-bootstrap pubkey <registry_sk_file>
//!       → prints the registry public key (base64) — set as LLUMA_REGISTRY_PK_B64
//!         when building the app to pin the trust anchor.
//!
//!   lluma-bootstrap sign --registry-sk <file> --relay <url> \
//!       --gateway-kc-b64 <b64> --issuer-key-id-hex <hex64> \
//!       [--issued-at <unix_s>] --out <blob_file>
//!       → writes the signed SignedBootstrap JSON blob to <blob_file>; place it
//!         on the relay and point LLUMA_BOOTSTRAP_FILE at it.

use base64::Engine;

use lluma_core::proto::v1::SignedBootstrap;
use lluma_core::wire::{AccountSecretKey, BootstrapDoc};
use lluma_crypto::account::{account_public_from_secret, bootstrap_sign, bootstrap_verify};

fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn b64d(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| format!("bad base64: {e}"))
}
fn hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err("issuer-key-id-hex must be 64 hex chars (32 bytes)".into());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| format!("bad hex: {e}"))?;
    }
    Ok(out)
}

fn read_sk(path: &str) -> Result<AccountSecretKey, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{path}: registry secret must be 32 bytes, got {}", bytes.len()));
    }
    Ok(AccountSecretKey(bytes))
}

/// Minimal `--flag value` parser.
fn flags(args: &[String]) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    let mut i = 0;
    while i + 1 < args.len() {
        if let Some(k) = args[i].strip_prefix("--") {
            m.insert(k.to_string(), args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    m
}

fn now_unix_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    match cmd {
        "pubkey" => {
            let path = args.get(2).ok_or("usage: lluma-bootstrap pubkey <registry_sk_file>")?;
            let sk = read_sk(path)?;
            let pk = account_public_from_secret(&sk).map_err(|e| e.to_string())?;
            println!("{}", b64e(&pk.0));
            Ok(())
        }
        "sign" => {
            let f = flags(&args[2..]);
            let get = |k: &str| f.get(k).cloned().ok_or_else(|| format!("missing --{k}"));
            let sk = read_sk(&get("registry-sk")?)?;
            let relay_url = get("relay")?;
            let gateway_kc = b64d(&get("gateway-kc-b64")?)?;
            let issuer_key_id = hex32(&get("issuer-key-id-hex")?)?;
            let issued_at_s = match f.get("issued-at") {
                Some(v) => v.parse().map_err(|e| format!("bad --issued-at: {e}"))?,
                None => now_unix_s(),
            };
            let out = get("out")?;

            let doc = BootstrapDoc { version: 1, relay_url, gateway_kc, issuer_key_id, issued_at_s };
            let doc_bytes = postcard::to_stdvec(&doc).map_err(|e| format!("encode: {e}"))?;
            let sig = bootstrap_sign(&sk, &doc_bytes).map_err(|e| e.to_string())?;

            // Self-check: the blob must verify under the registry pubkey.
            let pk = account_public_from_secret(&sk).map_err(|e| e.to_string())?;
            let sb = SignedBootstrap { doc: doc_bytes, sig: sig.0 };
            let sig_check = lluma_core::wire::ReceiptSignature(sb.sig.clone());
            bootstrap_verify(&pk, &sb.doc, &sig_check)
                .map_err(|_| "self-check failed: signed blob does not verify".to_string())?;

            let json = serde_json::to_vec(&sb).map_err(|e| format!("json: {e}"))?;
            std::fs::write(&out, &json).map_err(|e| format!("write {out}: {e}"))?;
            eprintln!("wrote signed bootstrap ({} bytes) to {out}", json.len());
            eprintln!("registry pubkey (pin as LLUMA_REGISTRY_PK_B64): {}", b64e(&pk.0));
            Ok(())
        }
        _ => Err("usage: lluma-bootstrap <pubkey|sign> ...  (see file header)".into()),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
