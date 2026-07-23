# ADR-0004 — GUI tunnel hosting: published registration params + separate host identity

- **Status:** Accepted (2026-07-23)
- **Context:** The reverse tunnel (spec 2026-07-21 §Track 1) lets NAT-bound hosts
  serve without a public IP. To let a *desktop GUI* user contribute, the app must
  register as a host with the broker — which is PoW-gated and needs the epoch salt
  + difficulty, values previously operator-provided out-of-band. This ADR records
  the three decisions (crypto-architect review, 2026-07-23) that make GUI hosting
  work without weakening the privacy invariant.

## Decision 1 — Publish `epoch_salt` + `pow_difficulty` in the registry-signed bootstrap

The `BootstrapDoc` gains optional `pow_difficulty: u32` and `epoch_salt: [u8;32]`
(appended last, same one-way postcard-compat as `tunnel_url`). The desktop reads
them from the pinned-key-verified bootstrap and solves the host-registration PoW.

Rationale: the salt's security property is *unpredictability before the epoch*
(anti-precompute), not secrecy during it — every registering host already holds
it, so it is effectively public. Difficulty is public policy. Publishing them
just makes host registration self-service (the intended open-participation model).
**Signing matters:** served unauthenticated, a malicious relay could hand a wrong
salt (registration DoS) or an absurd difficulty (wedge a client grinding PoW).
The broker remains the authority — the doc cannot weaken *verification*.

Must-haves (implemented): client refuses to solve difficulty > 30 bits (a
mis-signed doc can't spin forever); the same one-way-compat + blob-first deploy
discipline as `tunnel_url`. Note: the salt also gates the *trial* PoW domain, so
publishing makes trial PoW self-service too — safe, because the real Sybil bound
is the global daily trial budget (see ADR-0002 / `trial.rs`), designed for a
public salt. **Rotation coupling (runbook):** rotating the epoch salt now requires
re-signing + republishing the bootstrap; the broker's accept-current-or-previous
window (`epoch_salt_prev`) must outlast bootstrap propagation before `prev` is
dropped, or GUI hosts on a stale doc get `BadPow`. A host *running* across a
rotation past the `prev` window strands too (its captured salt goes dead); today
that surfaces as a "reconnecting" status (heartbeat failures update the UI), and
re-fetching the bootstrap for a fresh salt on repeated failures is a roadmap item.

Residual (roadmap): self-service registration widens the Sybil-host
prompt-harvest surface (hosts see plaintext by design); mitigated today by PoW +
slow admission (time-gated M heartbeats). Host reputation / canary probing and a
per-IP register rate limit at ingress remain future work.

## Decision 2 — The desktop hosts under a SEPARATE identity, never the spending account

**This is the load-bearing privacy decision.** Registering/heartbeating/tunnelling
happen over direct connections from the user's home IP, signed by the host
account key — so the broker learns `host_account ↔ IP`. If `host_account` were the
user's *spending* account, the broker would hold `spend_account ↔ IP`: the exact
linkage `trial.rs` routes `/v1/register` through the relay to avoid (leak L16).

Composition attack this prevents: spend tokens are blind, but the broker sees
per-account issuance timing; with `spend_account ↔ IP` known AND self-service host
registration (Decision 1), a malicious broker can run its own host, route that
account's job to it, and decrypt — one colluding party then holds originator IP
**and** prompt plaintext, breaking the invariant. Contributors would be the
worst-protected users on the network.

Implementation: the desktop uses a **device-local host account keypair**
(`host_account.bin`, sealed under the passphrase; `host::load_or_create_host_account`)
that is independent of the spending account. Its pubkey is unlinkable to the spend
account at the broker. The per-device HPKE key (response sealing) stays as-is.
Earnings accrue to the host pseudonym's ledger row.

Known limitation (roadmap): the device-local host key is not mnemonic-recoverable,
and the GUI does not yet present a unified "one balance" (spend account + host
earnings). The recommended evolution is a domain-separated host key *derived from
the same mnemonic* plus a client-side summed balance that spends from either
pseudonym over the anonymous relay→gateway path — deferred, and it composes with
this decision without a broker change (the ledger is already keyed by host
account fingerprint).

## Decision 3 — Derive the register/heartbeat origin from the signed `tunnel_url`

The desktop POSTs `/v1/host/register` and `/v1/heartbeat` to the origin derived
from the registry-signed `tunnel_url`: strictly `wss://host[:port]/…` →
`https://host[:port]` (`host::ingress_from_tunnel_url`), never `ws→http`. This
inherits the signed URL's authenticity with no extra bootstrap field. The
register/heartbeat client uses redirect-none (mirrors the broker's exec
forwarder) so a proxy misconfig can't bounce a signed registration elsewhere.

Contract (ops): the `tunnel_url` origin MUST serve `/v1/host/register` and
`/v1/heartbeat` (today Caddy on the broker box reverse-proxies all paths on
`tunnel.n.lluma.bodegga.net` to the broker ingress). If WS termination is ever
split from HTTP ingress, add an optional signed `ingress_url` via the same append
pattern — do not pre-add it.
