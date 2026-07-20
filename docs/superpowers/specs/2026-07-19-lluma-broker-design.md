# Lluma Phase 1 · Sub-project #4 — Broker (matchmaking + accounting), `lluma-broker` Design Spec

> The centralized-in-MVP coordinator: host registry + signed snapshots, durable credit accounting, and the double-spend arbiter.
> A **Bodegga** project.

- **Status:** Proposed (pre-implementation)
- **Date:** 2026-07-19
- **Author:** Bodegga / Lluma (architecture ruled by Fable, operator)
- **Parent:** [`2026-07-14-lluma-design.md`](2026-07-14-lluma-design.md) §5, §6, §8, §10
- **Consumes:** `lluma-crypto` (tokens, receipts, OHTTP), `lluma-issuer` (#2 — trait seams), `lluma-gateway` (#3 — mounted with a registry-backed origin resolver).
- **Normative:** [ADR-0002](../../architecture/adr-0002-phase1-hosting-and-ddos.md).

---

## 1. Summary & role

`lluma-broker` is the coordinator (centralized in the MVP, decentralized in Phase 3). It owns: the **host registry** + a **signed registry snapshot** (matchmaking is client-side selection over that snapshot — never live queries); **durable credit accounting** (a SQLite ledger fed by signed usage receipts) and the **durable per-epoch spent-set** (the double-spend arbiter — closing the restart-respend hole demonstrated in #2); it **mounts the #3 gateway** with a registry-backed origin resolver so all client traffic rides relay→gateway; and it runs the **trial-grant anti-Sybil** policy. It is trusted for **credit integrity and double-spend arbitration, not anonymity**: it sees ciphertext + routing metadata (model-id, chosen host, spend_id), never the originator IP (relay-only ingress) or prompt plaintext (E2E-sealed to the host).

## 2. Threat model

Broker/gateway (ADR-0002 VPS-B) may see: relay IPs, decapsulated routing metadata, inner E2E ciphertext, spent-set, receipts, host registry. Must never see: originator IP, prompt plaintext, or the account↔token issuance link (that lives issuer-side; RFC 9474 blinding unlinks it). Adversaries: L7 flooders (handled at relay/registration PoW), a malicious host (fabricated receipts — bounded by "receipt requires a burned spend_id + price cap"), and the broker operator itself (sees no consumer identity by construction; earn names only `host_account`).

## 3. Decisions (Fable rulings R1–R12, operator)

- **R1 — broker = registry + snapshot-signer + token-arbiter + forwarder; selection is client-side.** No "pick me a host" queries. Client filters the signed snapshot by model/freshness, weighted-random by inverse-load bucket. Broker runtime path: `token_verify → SpentSet::insert(spend_id) → resolve host → forward inner ciphertext`.
- **R2 — token verified at the broker inside the gateway-decapsulated envelope.** Inner envelope `{key_id, token, host_account, model_id, e2e_ciphertext}`. **Never persist raw token bytes — only `spend_id`.** The #1 AAD contract (client binds spend_id into the E2E seal; host checks) prevents detach/replay.
- **R3 — reuse #3 gateway with a registry-backed origin resolver.** `host_account → registered ingress addr` replaces the static `origin_url`; SSRF guard tightens to "exact registered, admission-checked addresses only." Issuer paths stay allowlisted so issuance also rides relay→gateway.
- **R4 — pure-Rust `redb` embedded ACID store (CONTROLLER DEVIATION from Fable's rusqlite).** Rationale: this build environment has **no C compiler** (confirmed 2026-07-19 — `cc`/`gcc`/`cl`/`clang` all absent), so rusqlite's `bundled` SQLite (compiled from C) would fail to build like `lluma-runtime`. `redb` is 100% safe Rust, ACID, single-file, single-writer — meeting R4's durability + atomicity intent without the toolchain. Atomicity via redb write transactions: spent-set insert = write-txn get-or-insert + commit → `Inserted`/`AlreadySpent`; debit = write-txn read-check-write (`balance >= n`) + commit → `InsufficientCredits`; receipt = one write-txn insert-if-absent (host idempotency on spend_id). Values postcard-encoded. `spawn_blocking` still wraps the sync store from async handlers. (Deployment backup: redb file snapshot instead of Litestream WAL — record for ops. Revisit rusqlite if/when a C toolchain is provisioned.)
- **R5 — keep the `CreditLedger`/`SpentSet`/`IssueIdempotencyCache` traits in `lluma-issuer`; make them fallible.** `lluma-broker` ships `SqliteLedger`/`SqliteSpentSet`/`SqliteIdemCache`. One interface break: methods return `Result<_, IssuerError>` (add `IssuerError::Storage` → opaque 500). Idem cache gains `expires_at` + delete-on-insert TTL (closes carry-forward).
- **R6 — co-locate issuer+broker on one DB for MVP (ADR-0002 §7 fallback), behind a `settle(receipt)` seam** so the later VPS-C split is "replace `settle` with a signed broker→issuer batch RPC," not a rewrite. Records new leak **L14** (co-located debit/redeem timing correlation; mitigated by client fixed-batch randomized pre-fetch; eliminated by the split).
- **R7 — earn/spend unlinkability holds:** earn names only `host_account`; spend names nobody. Broker per-request view = `{spend_id, host, model, tier, units, timestamp_h}` — no consumer identity, no IP. Receipt acceptance: `receipt_verify` against the **registered** host pubkey; `spend_id` must already be in the spent-set (no receipt without burned work); `units` capped by a per-model/tier price table; `timestamp_h` hour-coarse.
- **R8 — trial anti-Sybil bounds the aggregate, not the identity.** One trial grant (~20 requests) per new account at issuer-side `/v1/register` (relay-routed, no IP), gated by (a) BLAKE3 hashcash PoW over `account_pk ‖ nonce ‖ epoch_salt` with one **global** difficulty knob (L12), and (b) a **global daily trial-credit budget** (the real boundary — Sybil loss capped/day regardless of N). Trial volume tagged in counters for the `redeemed ≤ issued` audit. `/admin/grant` remains operator-only ops tooling. Deferred: memory-hard PoW, invite graphs, graduation curve, any identity verification (never — it links identity by construction).
- **R9 — registration + heartbeats.** Register: signed body (`lluma-host-register-v1`) `{host_account, hpke_pk, ingress_addr, models}` + PoW + **slow admission** (`pending→active` after M heartbeats; only active hosts enter the snapshot). Heartbeat: signed (`lluma-heartbeat-v1`), monotonic counter (replay-proof), `{load_bucket, models}`; **pre-verify key-id HashSet filter** before Ed25519 (unknown-key flood costs a hash); evict after 3 missed intervals. **Split ingress: heartbeats/receipts on a second independently-bound axum listener** so a flood can't starve redeem.
- **R10 — snapshot mechanics.** Fixed 60 s cadence, postcard-encoded, **padded to a fixed size bucket** (L4), signed with a dedicated broker **registry Ed25519 key** (`lluma-registry-snapshot-v1`, distinct from host-facing keys). Per host `{host_account, hpke_pk, models, tier_flags, load_bucket, freshness_bucket}` + header `{epoch, issued_at_h, current issuer key_id}` (embedded key_id = second L2 consistency channel). Served as a static GET through relay/gateway; reserve a `coords` field (Vivaldi deferred).
- **R11 — monitoring is code.** `counters` table tracks per-epoch `issued`/`redeemed`; operator-only endpoint returns invariant status; broker **refuses redeem + alarm-logs** the moment `redeemed > issued` (key-compromise tripwire). Epoch hygiene: spent-set rows carry `epoch`; accept k and k−1; purge `< k−1` at rotation.
- **R12 — defer (YAGNI):** Vivaldi coords; reputation beyond liveness/uptime; ratio-throttle curve (seam only); DHT/gossip; TEE tier; broker→issuer settlement RPC; warm standby + Litestream (deployment); host NAT traversal (#5 — tests use localhost stub hosts); memory-hard PoW; key rotation automation; token→session-key exchange (#5 host handshake).

## 4. Crate & module layout

```
crates/lluma-broker/
  src/
    lib.rs        # wiring + re-exports
    error.rs      # BrokerError (thiserror), L8-safe
    store.rs      # rusqlite open/migrate, single-writer handle, WAL+FULL pragmas
    ledger.rs     # SqliteLedger  : lluma_issuer::CreditLedger (fallible)
    spent.rs      # SqliteSpentSet: lluma_issuer::SpentSet (INSERT OR IGNORE)
    idem.rs       # SqliteIdemCache + TTL eviction
    registry.rs   # hosts table; register (PoW + slow admission); heartbeat; eviction
    snapshot.rs   # build/pad/sign on cadence; verify fn for clients
    receipts.rs   # ingest: verify -> spend_id-exists -> price-cap -> settle() TX
    redeem.rs     # inner-envelope: token_verify -> spent-set -> resolve -> forward
    service.rs    # two routers: core (redeem, snapshot GET) + ingress (register, heartbeat, receipts)
    main.rs       # binary: broker core + mounted gateway (resolver origin) + co-located issuer
  tests/broker_e2e.rs

crates/lluma-issuer/src/{ledger,spent_set,idem}.rs   # MODIFY: trait methods -> Result<_, IssuerError>; add IssuerError::Storage
crates/lluma-core/src/{wire.rs, proto.rs}            # ADD: register/heartbeat/snapshot bodies + envelope DTO
crates/lluma-crypto/src/account.rs                   # ADD: host_register_sign/verify, heartbeat_sign/verify, snapshot_sign/verify (mirror receipt_sign, distinct domains)
```

## 5. Storage schema (rusqlite, WAL, `WITHOUT ROWID` where keyed)

```sql
spent_set (spend_id BLOB PRIMARY KEY, epoch INTEGER) WITHOUT ROWID;
ledger    (account BLOB PRIMARY KEY, balance INTEGER CHECK(balance>=0),
           earned_total INTEGER, spent_total INTEGER) WITHOUT ROWID;
receipts  (spend_id BLOB PRIMARY KEY, host_account BLOB, model_id BLOB, tier INTEGER,
           units INTEGER, epoch INTEGER, timestamp_h INTEGER, sig BLOB) WITHOUT ROWID;
hosts     (host_account BLOB PRIMARY KEY, hpke_pk BLOB, ingress_addr TEXT, models TEXT,
           status INTEGER, hb_counter INTEGER, last_hb INTEGER, load_bucket INTEGER, uptime_ok INTEGER) WITHOUT ROWID;
idem_cache(account BLOB, request_id BLOB, batch_hash BLOB, response BLOB, expires_at INTEGER,
           PRIMARY KEY(account, request_id)) WITHOUT ROWID;
counters  (epoch INTEGER PRIMARY KEY, issued INTEGER, redeemed INTEGER, trial_granted INTEGER);
```

## 6. Key APIs (shapes)
`Store::open(path)`; `registry::register(signed, pow) -> Pending`; `registry::heartbeat(signed)`; `snapshot::publish() -> SignedSnapshot` / `snapshot::verify(pk, bytes)`; `receipts::ingest(receipt, sig) -> Credited | AlreadyCredited`; `redeem::handle(envelope) -> forwarded response`; the three Sqlite trait impls. All fallible → `BrokerError`/`IssuerError`; no `unwrap`/`expect` in libs.

## 7. Marquee test (`tests/broker_e2e.rs`, in-process: issuer + broker + 2 stub hosts + client)
1. **Durable-respend inverse (closes #2's hole):** issue → redeem T1 via broker → drop broker/Store without graceful close → reopen same SQLite file → replay T1 ⇒ 409 `DoubleSpend`; a pre-restart unspent T2 still redeems (durability didn't over-reject).
2. **Earn/spend unlinkability sweep (extends #2 across two services):** full transcripts at issuer `/issue` and broker redeem+receipt; no shared ≥8-byte substring outside whitelisted publics; no consumer-account bytes in any broker record/receipt row.
3. **Matchmaking + accounting loop:** register 2 stub hosts (PoW + admission) → heartbeats → snapshot verifies, is the fixed padded size, byte-identical across clients → client picks a host, request forwards to the live host, spend_id lands in the spent-set → host submits a receipt twice ⇒ credited exactly once → stop host B heartbeats ⇒ next snapshot drops it.
4. **Invariant tripwire:** `redeemed ≤ issued` holds; a synthetic extra redeem trips the alarm path.
Proptests: ledger never negative under concurrent debits on real SQLite; `SpentSet::insert` returns `AlreadySpent` exactly once per id across threads.

## 8. Non-negotiables & leak addenda
- Privacy invariant; typed errors (thiserror), no `unwrap`/`expect` in libs; BLAKE3 content addressing; `cargo test` + `cargo clippy --all-targets -- -D warnings` green before done. Commit trailer as usual.
- Record **L14** (co-located issuer+broker debit/redeem timing) in ADR-0001/0002; forcing function for the VPS-C split.

## 9. Non-goals / YAGNI
See R12. No decentralization, no reputation sophistication, no TEE tier, no streaming, no host NAT traversal in #4 (stub hosts on localhost).
