//! Diagnostic probe for the GUI chat path against the LIVE deployment.
//! Reproduces exactly what `send_message` does up to host discovery, printing
//! the precise stage + error (uses the improved `ClientError` Display).
//!
//! Env:
//!   LLUMA_RELAY_URL        https://relay.n.lluma.bodegga.net   (required)
//!   LLUMA_REGISTRY_PK_B64  pinned registry pubkey, base64      (required)
//!   LLUMA_SMOKE_SEED       throwaway account seed byte (default 201)

use base64::Engine;
use lluma_client::{fetch_bootstrap, Client};
use lluma_core::wire::{AccountPublicKey, HostPublicKey, Mnemonic, OhttpKeyConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let relay = std::env::var("LLUMA_RELAY_URL")?;
    let pk_b64 = std::env::var("LLUMA_REGISTRY_PK_B64")?;
    let seed: u8 = std::env::var("LLUMA_SMOKE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(201);
    let registry_pk = AccountPublicKey(
        base64::engine::general_purpose::STANDARD.decode(pk_b64.trim())?,
    );

    println!("relay: {relay}");
    print!("1) fetch_bootstrap ... ");
    let doc = match fetch_bootstrap(&relay, &registry_pk).await {
        Ok(d) => {
            println!("OK (gateway_kc {} B, tunnel_url={:?}, pow_diff={:?})",
                d.gateway_kc.len(), d.tunnel_url, d.pow_difficulty);
            d
        }
        Err(e) => { println!("FAIL: {e}"); return Ok(()); }
    };

    let (sk, pk) = lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([seed; 16]))?;
    let acct_id = lluma_crypto::account::account_fingerprint(&pk);
    println!("probe account_id: {}", acct_id.0.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let client = Client::new(
        &relay,
        OhttpKeyConfig(doc.gateway_kc.clone()),
        sk, pk,
        HostPublicKey(vec![0u8; 32]),
        [0u8; 32],
    ).with_expected_issuer_key_id(doc.issuer_key_id);

    print!("2) key_config ... ");
    match client.key_config().await {
        Ok(kc) => println!("OK (epoch={} denom={})", kc.epoch, kc.denomination),
        Err(e) => { println!("FAIL: {e}"); return Ok(()); }
    }

    print!("3) snapshot ... ");
    let hosts = match client.snapshot(&registry_pk).await {
        Ok(hosts) => {
            println!("OK ({} host(s))", hosts.len());
            for (i, h) in hosts.iter().enumerate() {
                println!("   host[{i}]: account={} hpke_pk={}B models={:?} tier_flags={} load={} fresh={}",
                    h.host_account.iter().take(4).map(|b| format!("{b:02x}")).collect::<String>(),
                    h.hpke_pk.len(), h.models, h.tier_flags, h.load_bucket, h.freshness_bucket);
            }
            hosts
        }
        Err(e) => { println!("FAIL: {e}"); return Ok(()); }
    };

    // Exec stage — only with a funded account (set LLUMA_PROBE_EXEC=1 after granting).
    if std::env::var("LLUMA_PROBE_EXEC").ok().as_deref() != Some("1") {
        println!("(set LLUMA_PROBE_EXEC=1 — after funding the probe account — to test exec)");
        return Ok(());
    }
    let kc = client.key_config().await?;
    // Self-fund via the new trial flow (no admin secret needed).
    if let (Some(salt), Some(diff)) = (doc.epoch_salt, doc.pow_difficulty) {
        print!("3b) trial_register (self-fund) ... ");
        match client.trial_register(&salt, diff).await {
            Ok(true) => println!("GRANTED"),
            Ok(false) => println!("refused (already claimed / budget) — continuing"),
            Err(e) => println!("FAIL: {e} — continuing"),
        }
    }
    print!("4) acquire 1 token ... ");
    let mut tokens = match client.acquire(&kc, 1).await {
        Ok(t) => { println!("OK"); t }
        Err(e) => { println!("FAIL: {e} (is the probe account funded?)"); return Ok(()); }
    };
    let host = hosts.first().ok_or("no host")?;
    let token = tokens.pop().ok_or("no token")?;
    let idx: usize = std::env::var("LLUMA_PROBE_HOST").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let host = hosts.get(idx).unwrap_or(host);
    println!("5) exec against host[{idx}] (prompt='ping') ...");
    let t0 = std::time::Instant::now();
    match client.exec_with_host(&kc, token, host, b"ping").await {
        Ok(ans) => println!("   OK in {:?}: {:?}", t0.elapsed(), String::from_utf8_lossy(&ans)),
        Err(e) => println!("   FAIL in {:?}: {e}", t0.elapsed()),
    }
    Ok(())
}
