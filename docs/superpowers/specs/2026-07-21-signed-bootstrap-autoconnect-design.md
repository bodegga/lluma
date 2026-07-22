# Signed Bootstrap → Zero-Config Auto-Connect — Design

- **Date:** 2026-07-21
- **Status:** Approved for planning
- **Goal:** The desktop app connects to the Lluma network automatically and securely on
  launch, with no manual endpoint entry — while never letting an untrusted relay substitute
  the gateway encryption key.

## 1. Problem

Today the app requires the user to paste the gateway OHTTP key-config and the broker registry
pubkey into Settings. That is confusing and cannot be fixed by *silently* fetching those values
from the relay: the relay is the one party that sees the client IP, so if it also supplies the
gateway key it could hand over a key it controls, decrypt the prompt, and hold IP + plaintext
together — a direct violation of the privacy invariant.

## 2. Trust model

The app ships with the network's **registry Ed25519 public key compiled in** (trust-on-install,
like a software-update signing key). It is the single pinned anchor:

- verifies the **signed bootstrap** (relay URL, gateway key-config, issuer key-id), and
- verifies the **host snapshot** (already registry-signed) — now against the pinned key instead
  of a pasted one.

Everything else is fetched over the (untrusted) relay and verified against the pinned key, so a
malicious relay cannot forge or substitute anything. The registry pubkey is removed from Settings.

If no anchor is compiled in (a plain `cargo build` with no `LLUMA_REGISTRY_PK_B64`), auto-connect
is disabled and the app falls back to manual entry (Advanced). This keeps the repo buildable
without secrets and is the honest dev-build behavior.

## 3. Components

### 3.1 `lluma-crypto`
- `const BOOTSTRAP_DOMAIN: &[u8] = b"lluma-bootstrap-v1";` (distinct from snapshot/receipt domains).
- `bootstrap_sign(registry_sk, doc_bytes) -> ReceiptSignature` and
  `bootstrap_verify(registry_pk, doc_bytes, sig) -> Result<()>` — Ed25519 over
  `BOOTSTRAP_DOMAIN ‖ doc_bytes`, mirroring `snapshot_sign/verify` exactly.

### 3.2 `lluma-core`
- `wire::BootstrapDoc { version: u8, relay_url: String, gateway_kc: Vec<u8>, issuer_key_id: [u8;32], issued_at_s: u64 }` (postcard-serializable).
- `proto::v1::SignedBootstrap { doc: Vec<u8> /* postcard(BootstrapDoc) */, sig: Vec<u8> }`
  (JSON, base64 fields — matches `SnapshotResponse` style). Sign/verify over the **exact** `doc`
  bytes, then decode — no canonicalization ambiguity (same pattern as the snapshot).

### 3.3 `lluma-client`
- `verify_bootstrap(registry_pk, &SignedBootstrap) -> Result<BootstrapDoc, ClientError>` (pure,
  fail-closed).
- `Client::bootstrap(relay_url, registry_pk) -> Result<BootstrapDoc, ClientError>` — plain-HTTPS
  GET `{relay_url}/v1/bootstrap`, verify, decode. Pre-connection, so NOT over OHTTP; safe because
  it is signature-verified against the pinned key. (Static ctor / free fn — no account needed.)

### 3.4 `lluma-relay`
- Load `bootstrap_blob` from `LLUMA_BOOTSTRAP_FILE` (path) at startup; `None` if unset. Serve
  verbatim at `GET /v1/bootstrap` (already implemented — relay mirrors, never authors/signs).
  Backward-compatible.

### 3.5 `lluma-gateway`
- Load the OHTTP secret key from `LLUMA_GATEWAY_KC_SK_FILE` if set (persistent), else generate
  ephemerally as today. Persistence keeps the signed bootstrap valid across restarts.

### 3.6 Operator tooling (`lluma-keygen` + new `lluma-bootstrap` bin)
- `lluma-keygen` also emits a **persistent gateway OHTTP keypair** (`gateway_kc.sk` +
  prints `gateway_kc` base64 for the bootstrap doc).
- `lluma-bootstrap` (small CLI): inputs `registry_sk`, `relay_url`, `gateway_kc` (b64),
  `issuer_key_id` (hex), `issued_at_s` → writes the signed `SignedBootstrap` blob file to place
  on the relay.

### 3.7 `apps/lluma-desktop`
- Pin the anchor: `option_env!("LLUMA_REGISTRY_PK_B64")` → `Option<AccountPublicKey>`.
- New command `auto_connect()`:
  1. if no anchor → return "manual" state (Advanced flow unchanged);
  2. else `Client::bootstrap(relay_url, anchor)` → populate in-memory + persisted settings
     (gateway_kc, issuer_key_id; registry_pk := the pinned anchor); then `network_status`.
- `snapshot`/chat use the pinned anchor as `registry_pk` when present.
- On launch: run `auto_connect()` automatically; Settings shows "Connected ✓" and hides the
  endpoint fields when pinned+connected. Remove the unsafe "Fetch from relay (unverified)" button.
- Manual/Advanced remains for self-hosters and dev builds.

## 4. Flows

**End user (official build):** install → launch → app fetches + verifies the signed bootstrap →
connects. Nothing to paste.

**Operator (one-time-ish):**
1. `lluma-keygen` → registry keypair (+ gateway key). Bake the printed registry pubkey into the
   release build via `LLUMA_REGISTRY_PK_B64=<b64> cargo build --release`.
2. Deploy the persistent gateway key (`LLUMA_GATEWAY_KC_SK_FILE`).
3. `lluma-bootstrap` → signed blob; scp to the relay; set `LLUMA_BOOTSTRAP_FILE`; restart relay.

**Nearest-relay:** out of scope (single production relay today). The signed `relay_url` field is
the hook for future multi-relay discovery.

## 5. Testing & verification

- **Unit (here):** `bootstrap_sign/verify` round-trip + wrong-key + tamper; `verify_bootstrap`
  accepts genuine / rejects wrong-key / tampered (mirrors the snapshot tests); gateway key
  file load/generate; keygen/lluma-bootstrap output shape.
- **Integration (here):** a **local end-to-end auto-connect test** — sign a bootstrap with a test
  registry key, serve it from a local relay (or feed it to the client), verify against the pinned
  test key, then run the existing in-process anonymous-inference slice. Proves the mechanism
  end-to-end without the live boxes.
- **Build (here):** default `cargo build` (no anchor) and an anchor build
  (`LLUMA_REGISTRY_PK_B64=<test> cargo build`) both succeed; clippy `-D warnings` clean.
- **Review:** `protocol-crypto-architect` reviews the bootstrap protocol, domain separation, the
  pinning/trust flow, and fail-closed behavior before merge.

## 6. Hard stops (operator-only; cannot be done from this environment)
- Baking the **real** production registry pubkey (secret lives on the broker box).
- Persisting the gateway key + reading the current gateway key-config (DO box).
- Signing the production bootstrap (registry secret) + placing it on the relay + restart.
- A **live** verified connect therefore needs the operator deploy; the mechanism is fully tested
  locally with a test-signed bootstrap.

## 7. Non-negotiables carried forward
Privacy invariant (no party holds IP + plaintext — the whole reason for signature verification);
typed errors, no `unwrap`/`expect` in library crates; BLAKE3 addressing; green tests + clippy
before done; GLM 5.2 only for small mechanical files (controller writes the crypto/trust code).
