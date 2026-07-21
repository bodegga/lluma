//! Live production smoke test against the deployed relay → gateway → broker → host.
//!
//! Always: OHTTP key-config round-trip. With `LLUMA_SMOKE_N>0`: acquire blind
//! tokens. With the host env set: register + admit a serving host (direct to the
//! broker ingress), then run one full anonymous inference through the relay.
//!
//! Env:
//!   LLUMA_RELAY_URL     http://<relay-ip>:8780                (required)
//!   LLUMA_GW_KC_B64     gateway OHTTP key-config, base64      (required)
//!   LLUMA_SMOKE_SEED    client account seed byte (default 123)
//!   LLUMA_SMOKE_N       tokens to acquire (default 0)
//!   -- full e2e (all four required to run the exec) --
//!   LLUMA_INGRESS_URL   http://<broker-ip>:8081               (broker ingress, direct)
//!   LLUMA_HOST_HPKE_B64 the serving host's HPKE pubkey, base64
//!   LLUMA_HOST_ADDR     ingress_addr to register (e.g. http://<broker-ip>:9000)
//!   LLUMA_EPOCH_SALT_B64 the broker's epoch salt, base64 (to solve host-reg PoW)
//!   LLUMA_POW_DIFFICULTY (default 20), LLUMA_HOST_SEED (default 200)

use base64::Engine;
use lluma_client::Client;
use lluma_core::proto::v1::{HeartbeatRequest, HostRegisterRequest};
use lluma_core::wire::{HeartbeatBody, HostPublicKey, HostRegisterBody, Mnemonic, OhttpKeyConfig};

fn b64(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s.trim())?)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let relay = std::env::var("LLUMA_RELAY_URL")?;
    let gw_kc = OhttpKeyConfig(b64(&std::env::var("LLUMA_GW_KC_B64")?)?);
    let seed: u8 = std::env::var("LLUMA_SMOKE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(123);
    let n: usize = std::env::var("LLUMA_SMOKE_N").ok().and_then(|s| s.parse().ok()).unwrap_or(0);

    let (sk, pk) = lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([seed; 16]))?;
    let acct_id = lluma_crypto::account::account_fingerprint(&pk);
    println!("relay        : {relay}");
    println!("account_id   : {}", hex(&acct_id.0));

    // Full-e2e mode?
    let full = std::env::var("LLUMA_HOST_HPKE_B64").ok();

    // Client host params (real in full mode; dummy otherwise).
    let (host_pk, host_account) = if let Some(ref hpke) = full {
        let hseed: u8 = std::env::var("LLUMA_HOST_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(200);
        let (_hsk, hpk) = lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([hseed; 16]))?;
        let hacct: [u8; 32] = hpk.0.as_slice().try_into().unwrap();
        (HostPublicKey(b64(hpke)?), hacct)
    } else {
        (HostPublicKey(vec![0u8; 32]), [0u8; 32])
    };

    let client = Client::new(&relay, gw_kc, sk, pk, host_pk.clone(), host_account);

    // 1) Key-config round-trip over the live OHTTP path.
    let kc = client.key_config().await?;
    println!("OK key-config: key_id={} epoch={} denom={}", hex(&kc.key_id), kc.epoch, kc.denomination);

    // 2) Acquire tokens (needs credits granted to account_id).
    let mut tokens = if n > 0 || full.is_some() {
        let want = if full.is_some() { n.max(1) } else { n };
        let t = client.acquire(&kc, want).await?;
        println!("OK acquire   : issued {} blind token(s)", t.len());
        t
    } else {
        vec![]
    };

    // 3) Full e2e: register + admit a host, then exec one anonymous inference.
    if full.is_some() {
        let ingress = std::env::var("LLUMA_INGRESS_URL")?;
        let host_addr = std::env::var("LLUMA_HOST_ADDR")?;
        let salt: [u8; 32] = b64(&std::env::var("LLUMA_EPOCH_SALT_B64")?)?.as_slice().try_into().map_err(|_| "salt must be 32 bytes")?;
        let diff: u32 = std::env::var("LLUMA_POW_DIFFICULTY").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
        let hseed: u8 = std::env::var("LLUMA_HOST_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(200);
        let (hsk, hpk) = lluma_crypto::account::derive_keypair_from_seed(&Mnemonic([hseed; 16]))?;
        let hacct: [u8; 32] = hpk.0.as_slice().try_into().unwrap();
        let http = reqwest::Client::new();

        // Register (PoW-gated), direct to the broker ingress.
        let reg_body = HostRegisterBody {
            version: 1,
            host_account: hacct,
            hpke_pk: host_pk.0.clone(),
            ingress_addr: host_addr,
            models: vec![],
        };
        let reg_sig = lluma_crypto::account::host_register_sign(&hsk, &reg_body)?;
        print!("solving host PoW (difficulty {diff})... ");
        let nonce = lluma_crypto::account::pow_solve(lluma_crypto::account::POW_HOST_DOMAIN, &hacct, &salt, diff);
        println!("done");
        let reg = HostRegisterRequest { body: reg_body, sig: reg_sig.0, pow_nonce: nonce.to_vec() };
        let r = http
            .post(format!("{ingress}/v1/host/register"))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&reg)?)
            .send()
            .await?;
        println!("OK register  : HTTP {} {}", r.status().as_u16(), r.text().await.unwrap_or_default().trim());

        // Heartbeat to admission (M=3; admission is TIME-gated, so each heartbeat
        // must be >= one interval after the previous — sleep BEFORE each send, and
        // use wall-clock-based monotonic counters so re-runs aren't replay-rejected).
        let base = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        for c in 1u64..=3 {
            println!("  waiting ~31s before heartbeat {c} (time-gated admission)...");
            tokio::time::sleep(std::time::Duration::from_secs(31)).await;
            let hb = HeartbeatBody { version: 1, host_account: hacct, hb_counter: base + c, load_bucket: 0, models: vec![] };
            let sig = lluma_crypto::account::heartbeat_sign(&hsk, &hb)?;
            let req = HeartbeatRequest { body: hb, sig: sig.0 };
            let r = http
                .post(format!("{ingress}/v1/heartbeat"))
                .header("content-type", "application/json")
                .body(serde_json::to_vec(&req)?)
                .send()
                .await?;
            println!("  heartbeat {c}: HTTP {}", r.status().as_u16());
        }

        // Exec one anonymous inference through the relay.
        let token = tokens.pop().ok_or("no token to exec")?;
        let prompt = b"what is the capital of france?";
        let answer = client.exec(&kc, token, prompt).await?;
        println!("OK exec      : answer = {:?}", String::from_utf8_lossy(&answer));
        assert!(answer.windows(prompt.len()).any(|w| w == prompt), "echo must contain the prompt");
        println!("FULL ANONYMOUS INFERENCE OK (client -> relay -> gateway -> broker -> host -> back)");
    }

    println!("LIVE SMOKE OK");
    Ok(())
}
