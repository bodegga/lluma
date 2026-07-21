# Lluma Desktop Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a launchable Tauri v2 desktop app that does real anonymous inference over the live Lluma relay (client role), shows network/account/privacy status, and — on a reachable machine — contributes compute (host role), all under one account and one credit balance.

**Architecture:** One Tauri app with a pure-Rust default build. `lluma-runtime` (llama.cpp) is made an optional `local-inference` feature so the default build needs no C toolchain. Chat runs over `lluma-client` and discovers hosts from the signed `/v1/snapshot`. Contribute runs `lluma-host` proxying to an OpenAI-compatible upstream. Frontend is static `dist/` assets (no bundler).

**Tech Stack:** Rust, Tauri v2, tokio, reqwest, `lluma-client`, `lluma-host`, `lluma-crypto`, `lluma-core`; vanilla HTML/CSS/JS frontend.

## Global Constraints

- Privacy invariant: no single party ever holds both originator IP and prompt plaintext. Client traffic leaves only through the relay.
- Typed errors via `thiserror`; **no `unwrap()`/`expect()` in library crates** (`lluma-client`). Tauri app commands return `Result<T, String>`; `.map_err(|e| e.to_string())` at the boundary only.
- BLAKE3 for all content addressing.
- Run `cargo test` and `cargo clippy --all-targets -- -D warnings` before claiming a task done.
- Default desktop build must be pure Rust: `cargo build -p lluma-desktop` with no C toolchain. `lluma-runtime` only behind `--features local-inference`.
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Relay URL default (baked in): `https://relay.n.lluma.bodegga.net`.
- Snapshot is a fixed 65536-byte bucket, `LEN_PREFIX = 4` (little-endian u32 body length), signed whole with the broker registry Ed25519 key.

---

## Phase A — `lluma-client` host discovery

### Task 1: Snapshot fetch + verify + host selection in `lluma-client`

**Files:**
- Modify: `crates/lluma-client/src/lib.rs`
- Modify: `crates/lluma-client/Cargo.toml` (ensure `postcard` dep present — already used; add if missing)
- Test: `crates/lluma-client/tests/snapshot.rs` (create)

**Interfaces:**
- Consumes: `lluma_core::proto::v1::SnapshotResponse` (`{ body: Vec<u8>, sig: Vec<u8> }`), `lluma_core::wire::{SnapshotBody, SnapshotHostEntry, AccountPublicKey, ReceiptSignature}`, `lluma_crypto::account::snapshot_verify`.
- Produces: `Client::snapshot(&self, registry_pk: &AccountPublicKey) -> Result<Vec<SnapshotHostEntry>, ClientError>` and a pure helper `verify_snapshot(registry_pk: &AccountPublicKey, sr: &SnapshotResponse) -> Result<SnapshotBody, ClientError>`.

- [ ] **Step 1: Write the failing test** (pure verify path — no network)

Create `crates/lluma-client/tests/snapshot.rs`:

```rust
//! Client-side snapshot verification (host discovery). Mirrors the broker's
//! signing so we can assert the client accepts a genuine snapshot and rejects
//! a tampered/mis-signed one — without pulling in the broker crate.

use lluma_client::verify_snapshot;
use lluma_core::proto::v1::SnapshotResponse;
use lluma_core::wire::{Mnemonic, SnapshotBody, SnapshotHeader, SnapshotHostEntry};
use lluma_crypto::account::{derive_keypair_from_seed, snapshot_sign};

const BUCKET: usize = 65_536;

fn sign_snapshot(body: &SnapshotBody, sk: &lluma_core::wire::AccountSecretKey) -> SnapshotResponse {
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p lluma-client --test snapshot`
Expected: FAIL — `verify_snapshot` not found in `lluma_client`.

- [ ] **Step 3: Implement `verify_snapshot` + `snapshot()` in `lib.rs`**

Add imports near the top of `crates/lluma-client/src/lib.rs`:

```rust
use lluma_core::proto::v1::SnapshotResponse;
use lluma_core::wire::{ReceiptSignature, SnapshotBody, SnapshotHostEntry};
```

Add the fixed-bucket constants and the pure verifier (module-level, `pub`):

```rust
/// Fixed snapshot bucket size (64 KiB) and length-prefix width — must match the
/// broker's `snapshot` module exactly.
const SNAPSHOT_BUCKET: usize = 65_536;
const SNAPSHOT_LEN_PREFIX: usize = 4;

/// Verify a signed registry snapshot and decode its body. Fails closed on any
/// size / signature / length / decode mismatch. Pure (no network) so it is unit
/// testable and reused by [`Client::snapshot`].
pub fn verify_snapshot(
    registry_pk: &AccountPublicKey,
    sr: &SnapshotResponse,
) -> Result<SnapshotBody, ClientError> {
    if sr.body.len() != SNAPSHOT_BUCKET {
        return Err(ClientError::Protocol);
    }
    let sig = ReceiptSignature(sr.sig.clone());
    lluma_crypto::account::snapshot_verify(registry_pk, &sr.body, &sig)
        .map_err(|_| ClientError::Crypto)?;
    let len = u32::from_le_bytes([sr.body[0], sr.body[1], sr.body[2], sr.body[3]]) as usize;
    let end = SNAPSHOT_LEN_PREFIX
        .checked_add(len)
        .filter(|e| *e <= sr.body.len())
        .ok_or(ClientError::Protocol)?;
    postcard::from_bytes(&sr.body[SNAPSHOT_LEN_PREFIX..end]).map_err(|_| ClientError::Protocol)
}
```

Add the network method inside `impl Client`:

```rust
    /// Fetch + verify the signed host snapshot over the relay, returning the
    /// active hosts. The client selects a host locally (there is no live
    /// "pick me a host" query).
    pub async fn snapshot(
        &self,
        registry_pk: &AccountPublicKey,
    ) -> Result<Vec<SnapshotHostEntry>, ClientError> {
        let resp = self
            .agent
            .round_trip(InnerRequest {
                method: "GET".into(),
                path: "/v1/snapshot".into(),
                content_type: None,
                body: Vec::new(),
            })
            .await?;
        if resp.status != 200 {
            return Err(ClientError::Server(resp.status));
        }
        let sr: SnapshotResponse =
            serde_json::from_slice(&resp.body).map_err(|_| ClientError::Protocol)?;
        Ok(verify_snapshot(registry_pk, &sr)?.hosts)
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p lluma-client --test snapshot`
Expected: PASS (3 tests).

- [ ] **Step 5: Clippy**

Run: `cargo clippy -p lluma-client --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/lluma-client/
git commit -m "feat(client): signed-snapshot host discovery (verify + fetch)"
```

---

### Task 2: `exec_with_host` — exec against a snapshot-selected host

**Files:**
- Modify: `crates/lluma-client/src/lib.rs`
- Test: `crates/lluma-client/tests/e2e_slice.rs` (extend — keep existing tests intact)

**Interfaces:**
- Consumes: `SnapshotHostEntry` from Task 1.
- Produces: `Client::exec_with_host(&self, kc: &KeyConfigResponse, token: Token, host: &SnapshotHostEntry, prompt: &[u8]) -> Result<Vec<u8>, ClientError>`. Existing `exec` is retained and delegates to it using the constructor-supplied host (back-compat for `live_smoke`).

- [ ] **Step 1: Add `exec_with_host` and refactor `exec` to delegate**

In `crates/lluma-client/src/lib.rs`, replace the body of `exec` and add the new method. `exec_with_host` is the existing `exec` logic with `host_pk`/`host_account` taken from the passed `host` instead of `self`:

```rust
    /// Execute one anonymous inference against a specific snapshot-selected host.
    pub async fn exec_with_host(
        &self,
        kc: &KeyConfigResponse,
        token: Token,
        host: &SnapshotHostEntry,
        prompt: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let host_pk = HostPublicKey(host.hpke_pk.clone());
        let spend_id = lluma_crypto::tokens::token_spend_id(&token);
        let mut rng = rand_core::OsRng;
        let (sess_sk, sess_pk) = lluma_crypto::e2e::session_keygen(&mut rng)?;
        let sealed =
            lluma_crypto::e2e::e2e_seal(&mut rng, &host_pk, &spend_id.0, prompt, &sess_pk)?;
        let req = ExecRequest {
            key_id: kc.key_id,
            host_account: host.host_account,
            token,
            sealed,
        };
        let json = serde_json::to_vec(&req).map_err(|_| ClientError::Protocol)?;
        let resp = self
            .agent
            .round_trip(InnerRequest {
                method: "POST".into(),
                path: "/v1/exec".into(),
                content_type: Some("application/json".into()),
                body: json,
            })
            .await?;
        if resp.status != 200 {
            return Err(ClientError::Server(resp.status));
        }
        let er: ExecResponse =
            serde_json::from_slice(&resp.body).map_err(|_| ClientError::Protocol)?;
        let mut cctx = lluma_crypto::e2e::response_setup_client(&sess_sk, &er.preamble)?;
        let (answer, is_final) = lluma_crypto::e2e::response_open_chunk(&mut cctx, &er.chunk)?;
        if !is_final {
            return Err(ClientError::NotFinal);
        }
        Ok(answer)
    }
```

Change the existing `exec` to build a `SnapshotHostEntry` from the constructor fields and delegate:

```rust
    pub async fn exec(
        &self,
        kc: &KeyConfigResponse,
        token: Token,
        prompt: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let host = SnapshotHostEntry {
            host_account: self.host_account,
            hpke_pk: self.host_pk.0.clone(),
            models: vec![],
            tier_flags: 0,
            load_bucket: 0,
            freshness_bucket: 0,
        };
        self.exec_with_host(kc, token, &host, prompt).await
    }
```

- [ ] **Step 2: Run existing e2e tests to confirm no regression**

Run: `cargo test -p lluma-client`
Expected: PASS (existing `e2e_slice` tests + Task 1's snapshot tests all green).

- [ ] **Step 3: Clippy**

Run: `cargo clippy -p lluma-client --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 4: Commit**

```bash
git add crates/lluma-client/
git commit -m "refactor(client): exec_with_host; exec delegates for back-compat"
```

---

## Phase B — Desktop app

### Task 3: Feature-gate the runtime; make the default build pure Rust

**Files:**
- Modify: `apps/lluma-desktop/src-tauri/Cargo.toml`
- Modify: `apps/lluma-desktop/src-tauri/src/lib.rs` (gate the runtime-using commands)

**Interfaces:**
- Produces: a `lluma-desktop` crate that builds with default features and no C toolchain; `local-inference` feature re-enables `lluma-runtime`.

- [ ] **Step 1: Rewrite the dependency block**

Replace the `[dependencies]` section of `apps/lluma-desktop/src-tauri/Cargo.toml` with:

```toml
[dependencies]
tauri = { version = "2", features = [] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json"] }
base64 = "0.22"
rand_core = { version = "0.6", features = ["getrandom"] }
thiserror = "2"
blake3 = "1"
postcard = { version = "1", features = ["use-std"] }
lluma-core = { path = "../../../crates/lluma-core" }
lluma-client = { path = "../../../crates/lluma-client" }
lluma-crypto = { path = "../../../crates/lluma-crypto" }
lluma-net = { path = "../../../crates/lluma-net" }
lluma-host = { path = "../../../crates/lluma-host" }
lluma-registry = { path = "../../../crates/lluma-registry" }
lluma-runtime = { path = "../../../crates/lluma-runtime", optional = true }

[features]
default = []
local-inference = ["dep:lluma-runtime"]
```

- [ ] **Step 2: Gate the runtime-dependent commands in `lib.rs`**

The current `lib.rs` imports `lluma_runtime` unconditionally. Wrap those imports and the `recommend_model_cmd` / `start_generate` bodies that use `MockRunner`/`recommend`/`detect_hardware` under `#[cfg(feature = "local-inference")]`. (These are replaced wholesale in Task 8; this step only needs to make the file compile without the feature — the fastest correct move is to let Task 8 rewrite `lib.rs` and here simply reduce `lib.rs` to a minimal compiling stub:)

Replace `apps/lluma-desktop/src-tauri/src/lib.rs` with:

```rust
//! Lluma desktop app entrypoint. Command modules are added in later tasks.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Lluma");
}
```

(The `expect` here is in the *binary* entrypoint, not a library crate — acceptable per the constraint, which scopes the ban to library crates.)

- [ ] **Step 3: Build with default features**

Run: `cargo build -p lluma-desktop`
Expected: SUCCESS, no C toolchain invoked (no `lluma-runtime` / llama.cpp compile).

- [ ] **Step 4: Commit**

```bash
git add apps/lluma-desktop/src-tauri/Cargo.toml apps/lluma-desktop/src-tauri/src/lib.rs
git commit -m "build(desktop): feature-gate lluma-runtime; pure-Rust default build"
```

---

### Task 4: DTOs + Settings module

**Files:**
- Create: `apps/lluma-desktop/src-tauri/src/types.rs`
- Create: `apps/lluma-desktop/src-tauri/src/settings.rs`
- Test: `apps/lluma-desktop/src-tauri/src/settings.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Produces:
  - `types.rs`: `Settings { relay_url: String, gateway_kc_b64: String, registry_pk_b64: String, issuer_key_id_hex: String, host: HostConfig }`, `HostConfig { upstream: UpstreamKind, ingress_addr: String, openai_base: String, openai_model: String, openai_api_key: String }`, `enum UpstreamKind { OpenAi, Echo, Local }`, `NetworkStatus`, `AccountStatus`, `HostStatus`, `ChatReply` — all `#[derive(Serialize, Deserialize, Clone)]`.
  - `settings.rs`: `Settings::default()` (relay_url prefilled, others empty), `Settings::load(dir: &Path) -> Settings` (missing/corrupt → default), `Settings::save(&self, dir: &Path) -> Result<(), String>`.

- [ ] **Step 1: Write `types.rs`**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamKind { OpenAi, Echo, Local }

impl Default for UpstreamKind {
    fn default() -> Self { UpstreamKind::OpenAi }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostConfig {
    pub upstream: UpstreamKind,
    pub ingress_addr: String,
    pub openai_base: String,
    pub openai_model: String,
    pub openai_api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub relay_url: String,
    pub gateway_kc_b64: String,
    pub registry_pk_b64: String,
    pub issuer_key_id_hex: String,
    pub host: HostConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkStatus {
    pub reachable: bool,
    pub epoch: u64,
    pub denomination: u64,
    pub latency_ms: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountStatus {
    pub has_account: bool,
    pub unlocked: bool,
    pub account_id_hex: String,
    pub balance: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostStatus {
    pub running: bool,
    pub reachable: bool,
    pub state: String,       // "stopped" | "registering" | "admitting" | "active"
    pub credits_earned: u64,
    pub requests_served: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatReply {
    pub answer: String,
    pub spent: usize,
    pub balance: usize,
}
```

- [ ] **Step 2: Write the failing test in `settings.rs`**

```rust
use std::path::Path;
use crate::types::Settings;

impl Default for Settings {
    fn default() -> Self {
        Settings {
            relay_url: "https://relay.n.lluma.bodegga.net".into(),
            gateway_kc_b64: String::new(),
            registry_pk_b64: String::new(),
            issuer_key_id_hex: String::new(),
            host: Default::default(),
        }
    }
}

impl Settings {
    pub fn load(dir: &Path) -> Settings {
        let path = dir.join("settings.json");
        std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("settings.json"), bytes).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefills_relay() {
        assert!(Settings::default().relay_url.contains("relay.n.lluma.bodegga.net"));
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("lluma-settings-{}", std::process::id()));
        let mut s = Settings::default();
        s.gateway_kc_b64 = "abc".into();
        s.save(&dir).unwrap();
        let back = Settings::load(&dir);
        assert_eq!(back.gateway_kc_b64, "abc");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_returns_default() {
        let dir = std::env::temp_dir().join("lluma-settings-does-not-exist-xyz");
        assert!(Settings::load(&dir).relay_url.contains("relay.n"));
    }
}
```

- [ ] **Step 3: Register the modules**

Add to `apps/lluma-desktop/src-tauri/src/lib.rs` (top):

```rust
mod types;
mod settings;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p lluma-desktop settings`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add apps/lluma-desktop/src-tauri/src/
git commit -m "feat(desktop): DTOs + persisted settings (relay prefilled)"
```

---

### Task 5: Account module (keystore create/import/unlock)

**Files:**
- Create: `apps/lluma-desktop/src-tauri/src/account.rs`
- Test: inline `#[cfg(test)]` in `account.rs`

**Interfaces:**
- Consumes: `lluma_crypto::account::{account_mnemonic_new, derive_keypair_from_seed, account_fingerprint, seal_keystore, open_keystore}`, `lluma_core::wire::{Mnemonic, KeystoreBlob, AccountSecretKey, AccountPublicKey}`.
- Produces: `struct Account { sk: AccountSecretKey, pk: AccountPublicKey }`; `Account::create(dir, passphrase) -> Result<Account, String>` (generates + seals to `keystore.bin`), `Account::import(dir, phrase_words, passphrase) -> Result<Account, String>`, `Account::unlock(dir, passphrase) -> Result<Account, String>`, `Account::exists(dir) -> bool`, `account.account_id_hex() -> String`.

- [ ] **Step 1: Write `account.rs` with a failing round-trip test**

```rust
use std::path::Path;

use lluma_core::wire::{AccountPublicKey, AccountSecretKey, KeystoreBlob, Mnemonic};
use lluma_crypto::account::{
    account_fingerprint, account_mnemonic_new, derive_keypair_from_seed, open_keystore,
    seal_keystore,
};

pub struct Account {
    pub sk: AccountSecretKey,
    pub pk: AccountPublicKey,
}

fn ks_path(dir: &Path) -> std::path::PathBuf { dir.join("keystore.bin") }

impl Account {
    pub fn exists(dir: &Path) -> bool { ks_path(dir).exists() }

    fn from_mnemonic(m: &Mnemonic) -> Result<Account, String> {
        let (sk, pk) = derive_keypair_from_seed(m).map_err(|e| e.to_string())?;
        Ok(Account { sk, pk })
    }

    fn persist(dir: &Path, m: &Mnemonic, passphrase: &str) -> Result<(), String> {
        let mut rng = rand_core::OsRng;
        let blob = seal_keystore(&mut rng, passphrase, m).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        std::fs::write(ks_path(dir), &blob.0).map_err(|e| e.to_string())
    }

    pub fn create(dir: &Path, passphrase: &str) -> Result<Account, String> {
        let mut rng = rand_core::OsRng;
        let m = account_mnemonic_new(&mut rng).map_err(|e| e.to_string())?;
        Self::persist(dir, &m, passphrase)?;
        Self::from_mnemonic(&m)
    }

    pub fn unlock(dir: &Path, passphrase: &str) -> Result<Account, String> {
        let bytes = std::fs::read(ks_path(dir)).map_err(|e| e.to_string())?;
        let m = open_keystore(passphrase, &KeystoreBlob(bytes)).map_err(|_| "wrong passphrase".to_string())?;
        Self::from_mnemonic(&m)
    }

    pub fn account_id_hex(&self) -> String {
        let id = account_fingerprint(&self.pk);
        id.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_unlock_yields_same_account() {
        let dir = std::env::temp_dir().join(format!("lluma-acct-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = Account::create(&dir, "hunter2").unwrap();
        let id1 = a.account_id_hex();
        let b = Account::unlock(&dir, "hunter2").unwrap();
        assert_eq!(id1, b.account_id_hex());
        assert!(Account::unlock(&dir, "wrong").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
```

Note on import: check the exact `Mnemonic`-from-words API. If `lluma_crypto` exposes a phrase parser use it; otherwise `import` accepts the 12-word phrase, parses via `bip39::Mnemonic::from_str`, and takes `.to_entropy()` into `Mnemonic([u8;16])`. Add `bip39 = "2"` to the desktop `Cargo.toml` deps only if the crypto crate does not already expose a phrase→`Mnemonic` helper (grep `crates/lluma-crypto/src/account.rs` for `from_phrase`/`parse` first; reuse it if present).

- [ ] **Step 2: Register module + run test**

Add `mod account;` to `lib.rs`. Run: `cargo test -p lluma-desktop account`
Expected: PASS.

- [ ] **Step 3: Clippy + commit**

```bash
cargo clippy -p lluma-desktop --all-targets -- -D warnings
git add apps/lluma-desktop/src-tauri/src/account.rs apps/lluma-desktop/src-tauri/src/lib.rs
git commit -m "feat(desktop): account keystore (create/import/unlock, sealed at rest)"
```

---

### Task 6: Client wrappers — network status, token store, chat

**Files:**
- Create: `apps/lluma-desktop/src-tauri/src/client.rs`
- Test: inline `#[cfg(test)]` (token-store round-trip only; network paths are exercised live/manually)

**Interfaces:**
- Consumes: `lluma_client::Client`, `lluma_core::wire::{OhttpKeyConfig, HostPublicKey, AccountPublicKey, Token}`, `Account` (Task 5), `Settings` (Task 4).
- Produces:
  - `decode_settings(s: &Settings) -> Result<(OhttpKeyConfig, AccountPublicKey /*registry*/), String>` (base64 decode gateway KC + registry pk; clear errors if empty/invalid).
  - `build_client(s: &Settings, acct: &Account) -> Result<Client, String>` (constructs `Client` with dummy host params — host is chosen per-message from the snapshot).
  - `TokenStore { tokens: Vec<Token> }` with `load(dir, passphrase) -> TokenStore`, `save(dir, passphrase) -> Result<(),String>` (sealed via `seal_keystore`-style AEAD — reuse the keystore primitive by storing postcard(tokens) as the "mnemonic" payload is NOT valid; instead use `lluma_crypto`'s AEAD directly. If no generic AEAD helper is exposed, persist tokens with the same XChaCha20-Poly1305 KEK derivation — add a tiny `seal_bytes/open_bytes` helper to `lluma-crypto` in this task, TDD'd there).
  - `network_status(client) -> NetworkStatus`, `acquire(client, store, kc, n) -> Result<usize,String>`, `send_message(client, store, registry_pk, prompt) -> Result<ChatReply,String>`.

> Implementation note for the token store: prefer adding `pub fn seal_bytes(rng, passphrase, plaintext) -> KeystoreBlob` and `pub fn open_bytes(passphrase, blob) -> Vec<u8>` to `crates/lluma-crypto/src/account.rs`, generalizing the existing `seal_keystore`/`open_keystore` (which currently hardcode the 16-byte mnemonic). Write these TDD in `lluma-crypto` first (round-trip + wrong-passphrase tests), then use them here. This keeps all crypto in the crypto crate.

- [ ] **Step 1: (in `lluma-crypto`) TDD `seal_bytes`/`open_bytes`**

Add to `crates/lluma-crypto/src/account.rs` generalized variants (mirror `seal_keystore`, but arbitrary-length payload; keep `seal_keystore` delegating to `seal_bytes` for the 16-byte case). Add tests:

```rust
#[test]
fn seal_bytes_round_trips_and_rejects_wrong_pass() {
    let mut rng = rand_core::OsRng;
    let blob = seal_bytes(&mut rng, "pw", b"hello world payload").unwrap();
    assert_eq!(open_bytes("pw", &blob).unwrap(), b"hello world payload");
    assert!(open_bytes("nope", &blob).is_err());
}
```

Run: `cargo test -p lluma-crypto seal_bytes` → PASS. Clippy clean. Commit:
`git commit -m "feat(crypto): seal_bytes/open_bytes (generalize keystore AEAD)"`

- [ ] **Step 2: Write `client.rs` with the token-store round-trip test**

```rust
use std::path::Path;

use lluma_client::Client;
use lluma_core::wire::{AccountPublicKey, HostPublicKey, KeystoreBlob, OhttpKeyConfig, Token};
use base64::Engine;

use crate::account::Account;
use crate::types::{ChatReply, NetworkStatus, Settings};

fn b64d(s: &str, what: &str) -> Result<Vec<u8>, String> {
    if s.trim().is_empty() {
        return Err(format!("{what} is not set — fill it in Settings or use Fetch from relay"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| format!("{what} is not valid base64"))
}

pub fn decode_settings(s: &Settings) -> Result<(OhttpKeyConfig, AccountPublicKey), String> {
    let kc = OhttpKeyConfig(b64d(&s.gateway_kc_b64, "gateway key-config")?);
    let registry = AccountPublicKey(b64d(&s.registry_pk_b64, "registry pubkey")?);
    Ok((kc, registry))
}

pub fn build_client(s: &Settings, acct: &Account) -> Result<Client, String> {
    let (kc, _registry) = decode_settings(s)?;
    // Host params are per-message (snapshot-selected); pass placeholders here.
    Ok(Client::new(
        s.relay_url.clone(),
        kc,
        acct.sk.clone(),
        acct.pk.clone(),
        HostPublicKey(vec![0u8; 32]),
        [0u8; 32],
    ))
}

pub struct TokenStore {
    pub tokens: Vec<Token>,
}

fn ts_path(dir: &Path) -> std::path::PathBuf { dir.join("tokens.bin") }

impl TokenStore {
    pub fn load(dir: &Path, passphrase: &str) -> TokenStore {
        let bytes = std::fs::read(ts_path(dir)).ok().and_then(|b| {
            lluma_crypto::account::open_bytes(passphrase, &KeystoreBlob(b)).ok()
        });
        let tokens = bytes
            .and_then(|b| postcard::from_bytes::<Vec<Token>>(&b).ok())
            .unwrap_or_default();
        TokenStore { tokens }
    }

    pub fn save(&self, dir: &Path, passphrase: &str) -> Result<(), String> {
        let mut rng = rand_core::OsRng;
        let plain = postcard::to_stdvec(&self.tokens).map_err(|e| e.to_string())?;
        let blob = lluma_crypto::account::seal_bytes(&mut rng, passphrase, &plain)
            .map_err(|e| e.to_string())?;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        std::fs::write(ts_path(dir), &blob.0).map_err(|e| e.to_string())
    }
}

pub async fn network_status(client: &Client) -> NetworkStatus {
    let started = std::time::Instant::now();
    match client.key_config().await {
        Ok(kc) => NetworkStatus {
            reachable: true,
            epoch: kc.epoch,
            denomination: kc.denomination,
            latency_ms: started.elapsed().as_millis() as u64,
            message: "connected".into(),
        },
        Err(e) => NetworkStatus {
            reachable: false,
            epoch: 0,
            denomination: 0,
            latency_ms: started.elapsed().as_millis() as u64,
            message: format!("relay unreachable: {e}"),
        },
    }
}

pub async fn send_message(
    client: &Client,
    store: &mut TokenStore,
    registry_pk: &AccountPublicKey,
    prompt: &str,
) -> Result<ChatReply, String> {
    if store.tokens.is_empty() {
        return Err("no credits — fund your account (copy your account id from Status)".into());
    }
    let kc = client.key_config().await.map_err(|e| e.to_string())?;
    let hosts = client.snapshot(registry_pk).await.map_err(|e| e.to_string())?;
    let host = hosts.first().ok_or("no active hosts in the network right now")?;
    let token = store.tokens.pop().ok_or("no credits")?;
    let answer = client
        .exec_with_host(&kc, token, host, prompt.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    Ok(ChatReply {
        answer: String::from_utf8_lossy(&answer).to_string(),
        spent: 1,
        balance: store.tokens.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_store_round_trips() {
        let dir = std::env::temp_dir().join(format!("lluma-tok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ts = TokenStore { tokens: vec![] };
        ts.save(&dir, "pw").unwrap();
        let back = TokenStore::load(&dir, "pw");
        assert_eq!(back.tokens.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
```

Add an `acquire` wrapper that calls `client.acquire(&kc, n)` and appends to the store, then `save`s. (Full body mirrors `send_message`'s error handling; append `tokens` and persist.)

- [ ] **Step 2b: Register module, build, test**

Add `mod client;` to `lib.rs`. Run: `cargo test -p lluma-desktop`
Expected: PASS. Then `cargo clippy -p lluma-desktop --all-targets -- -D warnings`.

- [ ] **Step 3: Commit**

```bash
git add apps/lluma-desktop/src-tauri/src/client.rs apps/lluma-desktop/src-tauri/src/lib.rs
git commit -m "feat(desktop): client wrappers + encrypted token store + chat"
```

---

### Task 7: Host module (lifecycle, upstream, reachability) — scoped

**Files:**
- Create: `apps/lluma-desktop/src-tauri/src/host.rs`
- Test: inline `#[cfg(test)]` (reachability-check parsing only)

**Interfaces:**
- Consumes: `lluma_host` (`router`, `HostState`, `Upstream`, `EchoUpstream`, `OpenAiUpstream`), `HostConfig`/`UpstreamKind` (Task 4), `Account`.
- Produces: `async fn reachability_check(ingress_addr: &str) -> bool` (attempts to hit the host's own health/ingress from an external perspective — best-effort HTTP GET, timeout), `struct HostHandle` with `start(cfg, acct, broker_ingress) -> Result<HostHandle,String>` and `stop(self)`, and `host_status(&Option<HostHandle>) -> HostStatus`. Register+heartbeat+serve loop mirrors `examples/live_smoke.rs` host section (PoW register → 3 time-gated heartbeats → serve). Uses `#[cfg(feature = "local-inference")]` only for the `UpstreamKind::Local` arm.

- [ ] **Step 1: Write `host.rs`**

Implement `reachability_check` (reqwest GET with 3s timeout; `true` on any HTTP response). Implement upstream selection:

```rust
#[cfg(feature = "local-inference")]
fn local_upstream(/* model path from cfg */) -> Box<dyn lluma_host::Upstream> { /* llama.cpp */ unimplemented_local() }
```

For `UpstreamKind::Local` without the feature, return `Err("this build has no local inference — rebuild with --features local-inference, or choose an OpenAI-compatible upstream")`. `OpenAi` → `OpenAiUpstream::new(base, model, api_key)`. `Echo` → `EchoUpstream`.

The register/heartbeat/serve loop runs on a spawned task; expose progress via a shared `HostStatus` behind a `Mutex`. Reachability must pass before `state` becomes `"active"`.

- [ ] **Step 2: Build (both feature sets) + test**

Run: `cargo build -p lluma-desktop` and `cargo build -p lluma-desktop --features local-inference` (the second may fail *only* if no C toolchain — that is expected in this environment; document it and do not block).
Run: `cargo test -p lluma-desktop host`
Expected: default build PASS; feature build documented.

- [ ] **Step 3: Clippy (default) + commit**

```bash
cargo clippy -p lluma-desktop --all-targets -- -D warnings
git add apps/lluma-desktop/src-tauri/src/host.rs apps/lluma-desktop/src-tauri/src/lib.rs
git commit -m "feat(desktop): host lifecycle + upstream selection + reachability check"
```

---

### Task 8: Command layer + managed state (wire `lib.rs`)

**Files:**
- Modify: `apps/lluma-desktop/src-tauri/src/lib.rs`

**Interfaces:**
- Consumes: everything from Tasks 4–7.
- Produces: `AppState` (Mutex-guarded `Settings`, `Option<Account>`, `TokenStore`, `Option<HostHandle>`, app-data `PathBuf`) and the Tauri commands from the spec (§5.3), all registered in `invoke_handler`. App-data dir resolved via Tauri's path API (`app.path().app_data_dir()`).

- [ ] **Step 1: Write `AppState` + commands**

Implement each command as a thin `async` Tauri command that locks state, builds a `Client` on demand via `build_client`, and delegates to the Task 6/7 functions. Every command returns `Result<T, String>`. Long ops (`acquire_tokens`, `send_message`, host loop) run inside the Tokio runtime Tauri provides; emit `token`/`done`/`error`/`host-status` events where useful.

Commands (names must match the frontend in Task 9): `network_status`, `account_status`, `create_account`, `import_account`, `unlock`, `lock`, `acquire_tokens`, `send_message`, `get_settings`, `set_settings`, `fetch_bootstrap`, `host_start`, `host_stop`, `host_status`.

`fetch_bootstrap`: `GET {relay_url}/v1/bootstrap`; on 200 parse `{ gateway_kc_b64, registry_pk_b64, issuer_key_id_hex }`, merge into settings, save; on non-200 return `Err("relay does not publish bootstrap yet — paste values manually")`. (This tolerates the endpoint not existing yet.)

- [ ] **Step 2: Build + clippy**

Run: `cargo build -p lluma-desktop` then `cargo clippy -p lluma-desktop --all-targets -- -D warnings`
Expected: SUCCESS, no warnings.

- [ ] **Step 3: Commit**

```bash
git add apps/lluma-desktop/src-tauri/src/lib.rs
git commit -m "feat(desktop): managed state + Tauri command layer"
```

---

### Task 9: Frontend — four-tab UI (`dist/`)

**Files:**
- Modify: `apps/lluma-desktop/dist/index.html`
- Modify: `apps/lluma-desktop/dist/styles.css`
- Modify: `apps/lluma-desktop/dist/main.js`

**Interfaces:**
- Consumes: the Tauri commands from Task 8 via `window.__TAURI__.core.invoke` and `window.__TAURI__.event.listen`.
- Produces: Chat, Contribute, Status, Settings tabs.

- [ ] **Step 1: `index.html` — four tabs**

Nav buttons: Chat, Contribute, Status, Settings; one `<section>` panel each. Chat: message thread `#thread`, composer `#composer` (textarea + send), disabled-state banner `#fund-banner`. Contribute: upstream `<select>`, ingress input, start/stop buttons, reachability dot, earnings. Status: network dot + epoch/denomination/latency, account id + balance, host status, and a static **privacy explainer** block. Settings: relay/gateway-kc/registry-pk inputs, "Fetch from relay" button, account create/import/unlock, host config.

- [ ] **Step 2: `styles.css` — polished dark thick-client theme**

Match the site's palette (brand-consistent). Tab bar, cards, status dots (green/amber/red), chat bubbles, disabled/empty states. Responsive to window resize; content areas scroll internally.

- [ ] **Step 3: `main.js` — wire commands + events**

Tab switching; on load call `get_settings`, `account_status`, `network_status`. Chat send → `send_message`, append bubbles, update balance; disable composer + show fund banner when `balance == 0`. Settings save → `set_settings`; "Fetch from relay" → `fetch_bootstrap`. Contribute start/stop → `host_start`/`host_stop`; poll/listen `host-status`. Show account id with a copy button. All calls wrapped in try/catch surfacing the `Err(String)` message inline.

- [ ] **Step 4: Build the app**

Run: `cargo build -p lluma-desktop`
Expected: SUCCESS (frontend is static assets; no bundler step).

- [ ] **Step 5: Commit**

```bash
git add apps/lluma-desktop/dist/
git commit -m "feat(desktop): four-tab thick-client UI (chat/contribute/status/settings)"
```

---

### Task 10: End-to-end verification + docs

**Files:**
- Modify: `README.md` (desktop launch instructions)
- Modify: `docs/INFRA.md` (note `/v1/bootstrap` companion task status)

- [ ] **Step 1: Full workspace gate**

Run: `cargo test` (workspace) and `cargo clippy --all-targets -- -D warnings`
Expected: all green.

- [ ] **Step 2: Produce the runnable binary**

Run: `cargo build -p lluma-desktop --release`
Expected: `apps/lluma-desktop/src-tauri/target/release/lluma-desktop.exe` exists. Report the exact path.

- [ ] **Step 3: Document launch + live-config steps**

In `README.md`, add: how to launch the app, that it opens to Settings when unconfigured, how to paste the current gateway key-config + registry pubkey (from the operator / `journalctl -u lluma-gateway | grep key_config`), create/unlock an account, and that chat needs a funded account + an active host.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/INFRA.md
git commit -m "docs: desktop client launch + live-config steps"
```

---

## Self-Review notes (coverage)

- Spec §3 buildability → Task 3. §4.1 client → Tasks 1,2,6. §4.2 host → Task 7. §5.2 persistence → Tasks 4,5,6. §5.3 commands → Task 8. §6 frontend → Task 9. §7 client additions → Tasks 1,2. §8 endpoints/bootstrap → Tasks 4,8,10. §11 verification → Task 10.
- Deferred items (§9) intentionally have no tasks.
- Type consistency: `verify_snapshot`, `snapshot`, `exec_with_host`, `Settings`, `Account`, `TokenStore`, `seal_bytes`/`open_bytes`, and the command names are used identically across tasks.
