# Lluma Phase 1 · Sub-project #3 — Anonymous Transport (`lluma-net` + `lluma-relay` + `lluma-gateway`) Design Spec

> The OHTTP relay layer that hides the originator's IP from the broker/issuer/host while carrying only ciphertext.
> A **Bodegga** project.

- **Status:** Proposed (pre-implementation)
- **Date:** 2026-07-19
- **Author:** Bodegga / Lluma (architecture ruled by Fable, operator)
- **Parent:** [`2026-07-14-lluma-design.md`](2026-07-14-lluma-design.md) §5 (request lifecycle)
- **Consumes:** `lluma-crypto` `ohttp` module (RFC 9458); ADR-0001 leak register; [ADR-0002](../../architecture/adr-0002-phase1-hosting-and-ddos.md) (hosting/DDoS — relay stateless, IP-only party, separate from broker+issuer).
- **Builds on:** `lluma-issuer` (#2), reused as the origin behind the gateway in the marquee test.

---

## 1. Summary & role

Sub-project #3 is the **anonymous transport**: the RFC 9458 Oblivious HTTP relay/gateway split that lets a client reach the issuer (and later the broker/host) **without any single party holding both its IP and the content**. It ships three crates and proves, end-to-end over a real HTTP wire, that the **relay sees IP + ciphertext but never content**, and the **gateway/origin see content but never the originator IP** — closing ADR-0002 §2's promise that the issuer becomes IP-blind.

## 2. Threat model (scope of #3)

Invariant: no single party holds both originator IP and content (tokens, blinded requests, receipts, inner HTTP). Parties, honest-but-curious:
- **Relay** — sees originator IP + opaque OHTTP ciphertext; holds no secrets; forwards to a configured gateway.
- **Gateway** — holds the `GatewaySecretKey`; decapsulates to inner plaintext; never sees originator IP (only the relay's IP).
- **Origin** (the issuer for #3) — sees accounts/tokens; never the originator IP.

RFC 9458 guarantees a TLS-terminating relay sees only IP + HPKE ciphertext (the inner layer is sealed to the gateway key it never holds). So residual risk is **engineering**: relay-added forwarding headers, per-client upstream connections, non-uniform relay errors, single-source key-config acceptance, and — fatal — relay+gateway colocated in one process. L7 flooders hit the relay edge (ADR-0002). Streaming-response timing (L4) is an accepted MVP gap.

## 3. Decisions (Fable rulings, operator)

- **R1 — plain HTTPS (axum server / reqwest client), no libp2p.** RFC 9458 *is* HTTP POST; libp2p adds a wire fingerprint + dep weight + zero invariant value now. libp2p/QUIC deferred to Phase 3.
- **R2 — three crates; the gateway is real, not a stub, and separate from the relay.**
  - `lluma-net` (client lib): bootstrap verification, inner-request BHTTP framing, encapsulate → POST relay → open response.
  - `lluma-relay` (bin + lib router): stateless forwarder; sees IP + capsule; config = gateway URL; **holds no gateway key**; per-IP limits + size caps live here and only here.
  - `lluma-gateway` (bin + lib router): holds `GatewaySecretKey`; decapsulates; SSRF-guarded forward to an allowlisted origin; seals the response. #4 mounts this router inside the broker.
  - **Relay and gateway are separate binaries/crates with no shared process — ever** (colocating puts IP + HPKE secret in one address space and guts L1 even in dev).
- **R3 — marquee proof = token redemption (and issuance) routed client → relay → gateway → issuer**, reusing `lluma_issuer::service::router` as the origin. Direct-to-issuer redemption remains only as an issuer-crate unit test.
- **R4 — inner framing = Binary HTTP (RFC 9292) via the `bhttp` crate** (same family as `ohttp`). Known-length encoding, single message. Never invent a custom inner encoding.
- **R5 — relay forwarding hygiene is a tested property:** relay copies exactly `body` + `content-type`, strips every inbound header, adds none (no `X-Forwarded-For`/`Via`/`Forwarded`/request-ids); relay→gateway uses **one shared `reqwest::Client`** (mixing clients at the gateway; per-client upstream connections would let the gateway partition traffic); uniform detail-free error bodies; no logs ever (L8).
- **R6 — per-IP token bucket + exact size caps, typed errors.** Hand-rolled `HashMap<IpAddr, Bucket>` + periodic sweep (no `governor` dep). Body cap (start 64 KiB) → 413; bucket exhausted → 429 + uniform `Retry-After`. Duress-PoW: config knob reserved (`pow_difficulty`, 0 = off, only value implemented); L12 (one global difficulty) noted.
- **R7 — bootstrap = one signed artifact + N-source consistency check; relay may mirror but never author it.** `Bootstrap { relay_urls, key_config, key_id, epoch, not_after }` Ed25519-signed by an offline publishing key pinned in the client; `verify_bootstrap(sources, vk)` requires ≥2 byte-identical signed sources, fails closed on mismatch (RFC 9576 / Privacy Pass key-consistency; ADR-0002 §3.4). Relay serves `GET /v1/bootstrap` returning the configured signed blob verbatim as one channel.
- **R8 — keep single-chunk OHTTP responses** (`last = true` always); streaming is broker/host work.
- **R9 — defer (YAGNI):** multi-chunk/streaming; libp2p/QUIC; relay fleet + sticky selection/jittered failover (list is plural but client uses index 0); DHT; Vivaldi/network coordinates; PoW puzzle impl; CDN-labeled second relay; gateway key rotation automation; response padding/timing (L4 — accepted MVP gap); making the issuer's reqwest clients generic over a transport trait (do in #4).

## 4. Crate & module layout

```
crates/lluma-net/        # client lib (deps: lluma-crypto, lluma-core, bhttp, reqwest, ed25519-dalek, thiserror)
  src/{lib.rs, bootstrap.rs (verify_bootstrap), bhttp.rs (InnerRequest/Response <-> RFC 9292), agent.rs (OhttpAgent), error.rs (NetError)}
crates/lluma-relay/      # bin + lib (deps: axum, reqwest, thiserror; NO lluma-crypto key types)
  src/{lib.rs, router.rs (POST /ohttp, GET /v1/bootstrap), ratelimit.rs (token bucket), config.rs, error.rs (RelayError), main.rs}
crates/lluma-gateway/    # bin + lib (deps: lluma-crypto, lluma-core, bhttp, axum, reqwest, thiserror)
  src/{lib.rs, router.rs (POST /), config.rs, error.rs (GatewayError), main.rs}
```

## 5. Protocol

### 5.1 APIs (normative)
```rust
// lluma-net
pub struct Bootstrap { pub relay_urls: Vec<String>, pub key_config: OhttpKeyConfig,
                       pub key_id: u8, pub epoch: u64, pub not_after: u64 }
pub fn verify_bootstrap(sources: &[&[u8]], vk: &ed25519_dalek::VerifyingKey, now_unix_s: u64) -> Result<Bootstrap, NetError>; // rejects now > not_after

pub struct InnerRequest  { pub method: String, pub path: String,
                           pub content_type: Option<String>, pub body: Vec<u8> }  // -> BHTTP (RFC 9292)
pub struct InnerResponse { pub status: u16, pub body: Vec<u8> }                    // <- BHTTP, finality-verified

pub struct OhttpAgent { /* relay_url: String, key_config: OhttpKeyConfig, http: reqwest::Client */ }
impl OhttpAgent {
    pub fn new(relay_url: impl Into<String>, key_config: OhttpKeyConfig) -> Self;
    /// encapsulate(inner as BHTTP) -> POST message/ohttp-req to relay -> open (is_final MUST be true) -> BHTTP-decode
    pub async fn round_trip(&self, req: InnerRequest) -> Result<InnerResponse, NetError>;
}

// lluma-relay
pub struct RateLimitConfig { pub capacity: u32, pub refill_per_sec: u32 }
pub struct RelayConfig { pub gateway_url: String, pub max_body_bytes: usize,
                         pub per_ip: RateLimitConfig, pub pow_difficulty: u8, /* reserved; 0 only */
                         pub bootstrap_blob: Option<Vec<u8>> }
pub fn router(cfg: RelayConfig) -> axum::Router;   // POST /ohttp ; GET /v1/bootstrap

// lluma-gateway
pub struct GatewayConfig { pub secret: GatewaySecretKey, pub origin_url: String,
                           pub allowed_path_prefixes: Vec<String> }
pub fn router(cfg: GatewayConfig) -> axum::Router;  // POST /  (message/ohttp-req in, message/ohttp-res out)
```

### 5.2 Request path
1. Client builds `InnerRequest { method, path, content_type, body }` → BHTTP known-length encode.
2. `ohttp_encapsulate(&mut OsRng, &key_config, &bhttp_bytes)` → `(EncapsulatedRequest, ClientResponseContext)`.
3. POST capsule bytes to `{relay}/ohttp` with `content-type: message/ohttp-req`.
4. **Relay:** enforce per-IP bucket + `max_body_bytes` (before full buffering → 413), then POST the body **verbatim** to `{gateway_url}` with only `content-type` (strip all else, add nothing), one shared `reqwest::Client`.
5. **Gateway:** `ohttp_decapsulate(&secret, &capsule)` → `(bhttp_bytes, ServerResponseContext)`; BHTTP-decode inner request; **SSRF guard:** method ∈ {GET, POST}, path prefix ∈ `allowed_path_prefixes`, **authority always overwritten with `origin_url`** (client-controlled URLs must never steer the gateway); `reqwest` to `{origin_url}{path}`.

### 5.3 Response path
1. Gateway BHTTP-encodes the origin response `{status, body}` → `ohttp_seal_chunk(&mut ctx, bytes, /*last=*/true)` → returns as `message/ohttp-res`.
2. Relay returns the body verbatim.
3. Client `ohttp_open_chunk(&mut client_ctx, bytes)` → `(plaintext, is_final)`; **treat as valid only if `is_final == true`** (fail-closed on truncation → `NetError::NotFinal`); BHTTP-decode → `InnerResponse`.
- `ClientResponseContext` never leaves `OhttpAgent::round_trip`'s stack; `ServerResponseContext` never leaves the gateway handler frame. Neither is serialized.

### 5.4 Errors (typed, uniform, L8)
- `NetError`: `Bootstrap{reason}`, `Encapsulation`, `Relay{status}`, `NotFinal`, `Bhttp`, `Http`.
- `RelayError`: `PayloadTooLarge`(413), `RateLimited`(429 + `Retry-After`), `BadContentType`(415), `UpstreamUnavailable`(502). Bodies are uniform and detail-free — a distinctive error echo is a tagging channel (R5).
- `GatewayError`: decapsulation/allowlist/upstream failures → a single uniform status to the relay; no gateway-error bytes propagate to the client.
- No `unwrap`/`expect` in library code.

## 6. Marquee test — `relay_invariant_harness` (integration test in `lluma-net`)

All in-process: issuer `Router` (from #2, in-memory state, one account granted) ← gateway `Router` (fresh `ohttp_keygen`, origin = issuer, prefixes `["/v1/"]`) ← relay `Router` (gateway URL, tight size cap) ← client (`OhttpAgent`). Each router wrapped in recording middleware capturing every inbound/outbound byte into a per-party `RecordedView` (same discipline as `lluma-crypto/tests/invariant_harness.rs`).

Canaries: `CLIENT_MARKER` (unique header the client sends **only on the outer request to the relay** — stand-in for originator IP on loopback); raw token bytes; receipt/spend_id bytes; the literal strings `/v1/issue`, `/v1/redeem`.

Flow: client issues a token batch via `round_trip(POST /v1/issue)`, redeems one via `round_trip(POST /v1/redeem)`; asserts a valid response and `is_final`.

Per-party byte-scan assertions:
1. **Relay** view contains `CLIENT_MARKER` + capsules; contains **none of** token bytes, spend_id, account pubkey, `/v1/issue`, `/v1/redeem`.
2. **Gateway** view contains token bytes (its designed view) and **no** `CLIENT_MARKER`; headers it received from the relay are exactly `{content-type, content-length}` — proves R5 stripping (no XFF-class leak).
3. **Issuer** view contains account/token material and **no** `CLIENT_MARKER` — the ADR-0002 §2 closure (issuer IP-blind on issue *and* redeem).
4. Negatives: oversize capsule → 413; bucket exhaustion → 429; bit-flipped capsule → gateway fails closed, relay returns the uniform error with no gateway-error detail bytes; disallowed inner path (`/v1/admin/grant`) → gateway rejects **before any origin contact** (SSRF/allowlist proof).

That harness + R5's header test is the "no party sees both" proof for the transport layer.

## 7. Non-negotiables & compliance
- Privacy invariant (§2); relay/gateway separate processes (R2); relay never logs (L8).
- Typed errors (`thiserror`); no `unwrap`/`expect` in libs; BLAKE3 where content-addressing applies.
- RNG: `ohttp_keygen`/`ohttp_encapsulate` take rand_core 0.6 `OsRng` (the hpke/ohttp path) — not `DefaultRng`.
- `cargo test` + `cargo clippy --all-targets -- -D warnings` green before any task is done.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## 8. Leak-register carry-forwards (to #4)
- Durable spent-set (from #2, still the deployment blocker).
- Key-config served through the relay too (L2) so the issuer can't target key-configs by IP.
- Relay fleet + sticky-per-session selection + jittered failover (L11); response padding/timing (L4).
- Idempotency-cache TTL eviction (#2 carry-forward).

## 9. Non-goals / YAGNI
See R9. Also: no persistence anywhere in #3 (relay/gateway are stateless but for the in-memory rate-limit buckets); no TLS in crate code (deployment concern); no multi-relay client logic (index 0 only).
