//! Live bootstrap smoke: fetch + verify the signed bootstrap from a relay
//! against a pinned registry public key, exactly as the desktop app does on
//! launch. Proves verified auto-connect end to end against production.
//!
//! Env:
//!   LLUMA_RELAY_URL       https://relay.n.lluma.bodegga.net   (required)
//!   LLUMA_REGISTRY_PK_B64 registry public key, base64          (required)

use base64::Engine;
use lluma_client::fetch_bootstrap;
use lluma_core::wire::AccountPublicKey;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let relay = std::env::var("LLUMA_RELAY_URL")?;
    let pk_b64 = std::env::var("LLUMA_REGISTRY_PK_B64")?;
    let pk = AccountPublicKey(base64::engine::general_purpose::STANDARD.decode(pk_b64.trim())?);

    println!("relay        : {relay}");
    let doc = fetch_bootstrap(&relay, &pk).await?;
    println!("OK bootstrap : VERIFIED against pinned registry key");
    println!("  relay_url    : {}", doc.relay_url);
    println!("  gateway_kc   : {} bytes", doc.gateway_kc.len());
    println!(
        "  issuer_key_id: {}",
        doc.issuer_key_id.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!("  issued_at_s  : {}", doc.issued_at_s);
    println!("BOOTSTRAP SMOKE OK (a fresh install would now be connected)");
    Ok(())
}
