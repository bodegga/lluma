# Lluma Phase 1 — Deployment (PREPARED, NOT EXECUTED)

> ⚠️ **GATED.** Nothing in this directory has been run. Deployment is outward-facing
> and irreversible (public infrastructure, real IPs, cost, exposure). It requires
> the operator's explicit go-ahead. These are templates + a checklist to follow by
> hand once you decide to deploy. Per ADR-0002, the topology is **≥ 2 distinct
> providers/ASNs**, with a hard rule: **no single vendor fronts both the relay edge
> and the broker/gateway edge** (leak L10).

## Topology (ADR-0002)

```
            (distinct provider A)              (distinct provider B)
client ──TLS──▶ VPS-A: lluma-relay ──▶ VPS-B: lluma-gateway ─▶ co-located origin
   │              (sees IP + OHTTP        (decapsulates OHTTP,   (lluma-broker bin:
   │               ciphertext only)        allowlists paths)      issuer + broker,
   │                                                              one redb store)
   └── never contacts VPS-B or hosts directly                     │
                                                    broker ──▶ serving hosts (elsewhere)
```

- **VPS-A — relay** (`lluma-relay`): the ONLY party that sees originator IPs. Holds
  no secrets. May sit behind a TLS-terminating CDN as a *separate labeled* endpoint
  (L9) — never give the CDN the gateway HPKE key.
- **VPS-B — gateway + co-located origin** (`lluma-gateway` + `lluma-broker`): the
  gateway decapsulates OHTTP and forwards allowlisted paths to the origin; the
  `lluma-broker` binary is the co-located issuer+broker origin (spec R6). **No CDN,
  no public DNS** on this side (L10). Bind the origin to loopback; only the gateway
  reaches it.
- **Serving hosts**: register with the broker (PoW + slow admission), receive only
  `{spend_id, ciphertext}` from the broker, never a client connection or an IP.

The privacy invariant holds by construction: the relay sees IP but only OHTTP
ciphertext; the gateway/broker/origin see ciphertext + routing metadata but never
the originator IP; the host sees prompt plaintext but never IP or identity.

## Prerequisites

- Rust toolchain on the build host (these 9 crates are pure-Rust; no C toolchain
  needed — `lluma-runtime`/llama.cpp is NOT part of this deployment).
- Two VPS on distinct providers/ASNs. TLS certificates (e.g. Caddy/nginx or a CDN
  in front of the relay only).
- Build release binaries: `cargo build --release -p lluma-relay -p lluma-gateway -p lluma-broker`.

## Key material (generate on VPS-B, keep offline backups)

Run `./gen-material.sh <dir>` to create the random 32-byte **registry key** and
**epoch salt** the broker needs. The **issuer RSA-BSSA key pair** (DER) is produced
by the issuer key-generation path — see `docs/superpowers/specs/2026-07-15-lluma-crypto-design.md`;
export the DER files and reference them from the broker env. **Never** ship an
all-zero epoch salt — the broker refuses to start on one (guard in `main.rs`).

## Steps (perform manually, in order — this is a checklist, not a script)

1. Provision VPS-A and VPS-B on distinct providers. Lock down firewalls: VPS-B's
   origin listeners bind to loopback; only the gateway port is reachable from VPS-A.
2. Copy release binaries + `systemd/*.service` + env files to each host.
3. On VPS-B: generate key material; fill `broker.env` + `gateway.env`; start
   `lluma-broker` then `lluma-gateway` (systemd). Confirm the origin refuses to
   start on a zero salt.
4. On VPS-A: fill `relay.env` (point `LLUMA_RELAY_GATEWAY` at VPS-B's gateway URL);
   start `lluma-relay`. Front with TLS.
5. Register serving hosts against the broker ingress listener (PoW + heartbeats to
   admission). Publish the client bootstrap (relay URL + pinned gateway OHTTP key).
6. Verify end-to-end with a real client request; confirm the relay logs show only
   IP+ciphertext and the origin never logs prompt/response plaintext.

## Backups / ops

- redb is a single file: snapshot `LLUMA_DB_PATH` for backup (no WAL shipping).
  Take backups from a paused/consistent point or copy-on-write snapshot.
- Rotate the epoch salt per epoch; keep `epoch_salt_prev` available for the k−1
  acceptance window (a `main.rs` follow-up once rotation automation lands).
- Monitor `GET /admin/invariant` (ingress, admin-secret): `redeemed ≤ issued` must
  hold; a trip is a key-compromise alarm — the broker already refuses redeem on trip.

## Not covered here (follow-ups)

- Gateway OHTTP key persistence across restarts (clients pin it — regenerating
  breaks pinning; persist the gateway key like the broker keys before real traffic).
- Warm standby + automated failover; multi-epoch key rotation; the VPS-C issuer/
  broker split (settle() seam) that eliminates L14.
