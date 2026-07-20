# ADR-0003: Minimal end-to-end anonymous-inference slice — static registry, broker as sole redeemer, echo upstream

- **Status:** Proposed (slice/MVP scope decision; ruled by Fable, operator, 2026-07-19)
- **Context:** #1 crypto, #2 issuer, #3 transport are merged; #4's durable redb accounting core (spent-set + ledger) is built. The goal of this slice is the honest minimal statement: **one anonymous request reaches a "model" and returns, with no single party holding both originator IP and prompt plaintext — proven by test.** Optimize for that over spec completeness.

## Decision

Build the leanest path to a tested end-to-end slice, deferring availability/abuse machinery (which does not affect the *linkage* invariant):

1. **Static host registry.** A config `StaticHostDirectory { host_account, ingress_url, host_pk }`; **defer** PoW registration, slow admission, signed snapshots, heartbeats, matchmaking. Rationale: the registry decides *who serves*, not *what links*. A statically-listed host receives only `{spend_id, ciphertext}` and never a client connection — identical linkage exposure to the full machinery; a malicious host sees plaintext either way and never sees IP either way. Availability/Sybil is explicitly out of scope tonight.
2. **Broker is the sole redeemer.** The broker's durable `RedbSpentSet` is THE spend authority for exec (`/v1/exec`: `token_verify` → `spent_set.insert` before forwarding). **Drop `/v1/redeem` from the slice's gateway allowlist** — two live spent-sets would reopen a respend hole between them. (`lluma-issuer` keeps `/v1/redeem` for its own tests.)
3. **API-donor host with echo upstream.** The host opens the E2E seal (aad = spend_id), calls `Upstream::complete(prompt)` behind a one-method trait, re-seals to the session key. `EchoUpstream` (returns a sentinel ‖ prompt) is acceptable for the marquee test; a real OpenAI-compatible adapter is a ~20-line swap. No local GGUF (no C toolchain here anyway).
4. **Client is composition.** `lluma-client` reuses `OhttpAgent`: acquire tokens (issue over OHTTP) → `e2e_seal(prompt, aad=spend_id)` → `/v1/exec` via the relay → `response_open_chunk` (require `is_final`).

## Deferred (record as caveats)
PoW registration / slow admission / signed snapshots / heartbeats; matchmaking (latency/reputation); receipt ingest + host crediting/payout; real payment rails; streaming (single final chunk only); real upstream LLM adapter; host-side spend_id idempotency; key rotation/multi-epoch; **relay operational separation (L1)** — the in-process test colocates parties, so IP separation is *modeled* by connection-graph + recorded-view assertions, not demonstrated across real infrastructure; TLS; desktop/Tauri wiring; multi-origin gateway routing.

## Honest caveats
(a) A localhost test cannot show real network unlinkability or timing-side-channel resistance. (b) The echo stub means "reaches a model" is architecturally true, not commercially true. (c) A single static host leaks nothing *because there is no selection* — matchmaking MUST be re-reviewed for linkage when built (#4 full).

## Consequences
The slice proves the privacy invariant end-to-end and gives a working skeleton to harden. The full #4 (registry/snapshots/receipts/anti-Sybil) and #5 (desktop, real inference) remain, tracked against their specs. This ADR is the forcing function that those deferrals are revisited, not forgotten.
