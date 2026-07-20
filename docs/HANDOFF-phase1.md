# Lluma Phase 1 — Session Handoff

**Written:** 2026-07-16 · **For:** the next session continuing Phase 1.
**Read alongside:** your auto-loaded memory (`MEMORY.md`), especially
`delegate-impl-to-glm-opencode.md` and `lluma-build-env.md`.

---

## TL;DR

Phase 1 (the anonymity layer) is decomposed into **5 sub-projects**. **#1 (`lluma-crypto`) is
DONE and merged to `main`.** Next is **#2: the token issuance loop.** The working model:
**Fable/Claude designs (brainstorm→spec→plan + review); GLM 5.2 via opencode implements.**

## Repo / git state

- Branch: `main`. Local `main` is **~13 commits ahead of `origin/main`** (all the crypto crate
  + design docs) and is **NOT pushed** — the user chose "merge locally." Ask before pushing
  (outward action). The live website deploys ONLY from `apps/lluma-web` on `origin/main`, so the
  unpushed crypto code doesn't affect it.
- Website: `lluma.bodegga.net` (+ `/whitepaper.html`) live, deployed via DigitalOcean app
  `c8effc7b-a326-4768-b9fa-c37cbb6e1ee7`. Deploys are MANUAL:
  `doctl apps create-deployment c8effc7b-a326-4768-b9fa-c37cbb6e1ee7` (production deploy — needs
  explicit user OK each time). Source branch = `main`, `source_dir apps/lluma-web`.
- Feature-branch workflow: branch off `main` (`feat/phase1-<name>`), merge `--no-ff` back when
  reviewed. Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## The build/test facts that matter

- `lluma-core`, `lluma-crypto`, `lluma-registry` are **pure Rust** — `cargo test -p <crate>` and
  `cargo clippy -p <crate> --all-targets -- -D warnings` work in a plain shell. `cargo` is at
  `/c/Users/A/.cargo/bin` (prepend to PATH in fresh shells).
- Only `lluma-runtime` (llama.cpp) needs the MSVC dev env (`vcvars64` + `ninja`) — see
  `lluma-build-env.md`. Phase-1 services won't touch it.
- **rand_core split (inherited, important):** `blind-rsa-signatures` 0.17 uses `rsa::rand_core`
  0.10; `hpke`/`ed25519-dalek`/`account` use `rand_core` 0.6. Token code uses the blind-rsa RNG
  (`blind_rsa_signatures::DefaultRng`); everything else uses 0.6 `OsRng`. Don't assume one shared
  RNG. Documented in root `Cargo.toml` + ADR-0001.

## How to run GLM (the implementer)

```
opencode run --auto -m opencode-go/glm-5.2 --dir "C:\Projects\Bodegga\Lluma" "<task>"
```
`--auto` is required (auto-approves edits + cargo). GLM has NO context — always hand it a
self-contained delegation `.md` (requirements + exact APIs + invariants + discipline + the commit
command) plus the task brief, run it in the background, and **re-verify its output yourself**
(`cargo test` + `clippy -D warnings`, spot-check security params). It's been reliable and even
fixed a real bug in a brief's test — but the controller owns verification.

## `lluma-crypto` — what sub-project #2+ consume

Public API (all pure functions over `lluma_core::wire` byte-newtypes; `CryptoError`):
- **tokens:** `issuer_keygen`, `token_blind`, `token_issue`, `token_unblind`, `token_verify`,
  `token_spend_id` (=BLAKE3(token); the double-spend key).
- **ohttp:** `ohttp_keygen`, `ohttp_encapsulate`, `ohttp_decapsulate`, `ohttp_seal_chunk`,
  `ohttp_open_chunk` (single-chunk MVP; finality flag authenticated).
- **e2e:** `host_keygen`, `session_keygen`, `e2e_seal`, `e2e_open`, `response_setup_host`,
  `response_setup_client`, `response_seal_chunk`, `response_open_chunk`. **AAD contract:** callers
  MUST bind the request's token `spend_id` into the e2e `aad` (so a token can't be detached/replayed).
- **account:** `account_mnemonic_new`, `derive_keypair_from_seed`, `account_fingerprint`,
  `receipt_sign`, `receipt_verify`, `seal_keystore`, `open_keystore`.

## The 5 sub-projects (dependency order)

1. **`lluma-crypto`** — ✅ DONE, merged. (blind tokens, OHTTP+HPKE, accounts, keystore, invariant harness)
2. **Token issuance loop** — ⬅ NEXT. `lluma-issuer` (HTTP service that blind-signs redemption
   requests, debiting a credit balance) + client-side redemption. Goal: prove unlinkable
   issuance↔redemption end-to-end over a real wire. First networking sub-project — scope the
   transport (axum/reqwest?) in the spec.
3. **Anonymous transport** — `lluma-net` (relay client + OHTTP framing) + `lluma-relay`. Proves
   relay-never-sees-plaintext. Enforce the **L1 constraint**: relay MUST be operationally separate
   from broker+issuer (separate host/logs).
4. **Matchmaking + accounting** — `lluma-broker` (host registry, latency/reputation match,
   signed-receipt credit ledger, per-epoch spent-set keyed by `spend_id`). This is where the
   **trial-grant anti-Sybil** decision lives (deferred from crypto; see design spec §6).
5. **End-to-end slice** — `lluma-host` + `lluma-client` + desktop wiring → one real anonymous
   request reaching a model. The shippable Phase-1 MVP.

For #2, follow: `superpowers:brainstorming` → `writing-plans` → then delegate task-by-task to GLM
(subagent-driven flow, but GLM is the implementer; controller reviews diffs; Fable for whole-branch).

## Carry-forward tickets from Fable's crypto review (not blocking, do opportunistically)

- Memory-hygiene pass: `e2e`/`tokens`/`account`/`ohttp` copy key material through non-zeroized
  intermediate `Vec`s before the zeroizing newtype wraps them (defense-in-depth; outside current
  threat model).
- `response_open_chunk` maps all failures to `ChunkOrder` — split tamper vs. reorder.
- Add in-crate RFC 9474/9180/9458 known-answer-test vectors (currently rely on upstream crates').
- Keystore passphrase proptest (empty/Unicode) — ADR §8 test 13.
- Wiring notes for services: callers must require `is_final==true` before treating a stream as
  complete; host should idempotency-key work on `spend_id` (SealedRequest is replayable);
  one OHTTP gateway `key_id` per epoch (avoid config partitioning).

## Key docs

- Design spec: `docs/superpowers/specs/2026-07-14-lluma-design.md`
- Crypto ADR + leak register (L1–L8): `docs/architecture/adr-0001-lluma-crypto-primitives.md`
- Crypto sub-project spec: `docs/superpowers/specs/2026-07-15-lluma-crypto-design.md`
- Whitepaper (public, on the site): `docs/whitepaper/lluma-technical-whitepaper.md`
- SDD scratch (ledger, briefs, reports; gitignored): `.superpowers/sdd/`

## Suggested opening move for the next session

> "Read docs/HANDOFF-phase1.md. Start Phase 1 sub-project #2 (token issuance loop): brainstorm
> then spec `lluma-issuer` + client redemption, then let GLM 5.2 implement it task-by-task."
