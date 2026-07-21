# ADR-0002: Phase-1 hosting & DDoS resistance — relay/broker/issuer topology

- **Status:** Proposed (DRAFT — recommendation memo for human sign-off)
- **Date:** 2026-07-19
- **Deciders:** Bodegga / Lluma (architecture ruled by Fable; pending human approval)
- **Scope:** hosting, network-layer and application-layer DoS hardening, redundancy, and
  key/state protection for the three Phase-1 coordination services (relay, broker/tracker,
  issuer). Architecture-level only — no code or configs. **Drives sub-project #3 (relay)
  and #4 (broker) design and the deployment plan.**
- **Inputs:** ADR-0001 (`docs/architecture/adr-0001-lluma-crypto-primitives.md`, esp. §0
  threat model and §6 leak register); design spec §3, §5, §8
  (`docs/superpowers/specs/2026-07-14-lluma-design.md`); issuer design spec
  (`docs/superpowers/specs/2026-07-16-lluma-issuer-design.md`).

---

## 0. Threat model and trust assumptions (restated)

**Invariant (spec §3, ADR-0001 §0):** no single party ever holds both the originator's IP
and the prompt plaintext.

Adversaries added by this ADR on top of ADR-0001's honest-but-curious parties:

1. **L3/L4 volumetric flooders** — saturate links/conntrack with junk packets.
2. **L7 application attackers** — target Lluma-specific CPU and state: RSA blind-sign
   (~1 ms/token), token_verify on redeem, spent-set growth, matchmaking queries,
   host-registry spam / fake heartbeats.
3. **Privacy adversary = any infrastructure party** — including any DDoS-mitigation
   vendor we introduce. **Every mitigation layer becomes a party and must be classified
   into an existing trust domain; that classification is the whole analysis.**

Trust-domain views (extends ADR-0001 §0 table to infrastructure):

| Party | May see | Must never see |
|---|---|---|
| Relay host + anything fronting the relay edge | originator IP, outer TLS metadata, OHTTP **ciphertext** | plaintext, chosen host, account identity, gateway HPKE secret |
| Broker/gateway host + anything fronting it | relay IPs, decapsulated routing metadata, inner ciphertext, spent-set, receipts | originator IP, plaintext |
| Issuer host | account pubkeys, credit ledger, **blinded** requests, epoch secret | originator IP, plaintext, spendable tokens |
| Static mirrors (GitHub/CDN object storage) | signed public artifacts, fetcher IPs ("is a Lluma user") | anything secret or linking |

Key deployment assumptions: solo/small operator, DigitalOcean-class VPS budget, hosts
(GPU supply) and clients are user-run, clients pre-fetch token batches (ADR-0001 §3),
issuer keys rotate per epoch (ADR-0001 §1, leak L2).

---

## 1. Central reframe: a CDN in front of the relay *joins the relay trust domain*

RFC 9458 was designed precisely so that TLS-terminating infrastructure on the relay side
sees only **client IP + HPKE ciphertext** — which is exactly the relay's own view. The
inner HPKE layer (encapsulated to the gateway key, ADR-0001 §2) is not terminable by any
CDN because no CDN ever holds the gateway secret. Deployed OHTTP systems embody this:
Apple Private Relay and Firefox's OHTTP relay *are* Fastly/Cloudflare/Akamai.

**Consequences of the reframe:**

- Fronting the **relay** with a TLS-terminating CDN does **not** create a new observer
  class and does **not** break L1 — it adds a second member to the "sees IP + ciphertext"
  domain. What it *does* add: a subpoenable third-party IP log (new leak **L9**) and a
  large-vantage timing observer (leak L4).
- The hard rule that replaces "no CDN": **one vendor must never front both the relay edge
  and the broker/gateway edge** — a single vantage point on both sides enables
  ciphertext-matching and timing correlation across the hop (new leak **L10**). Same
  reasoning forbids sharing DNS/registrar for both sides with that vendor.
- The gateway HPKE private key is never given to any fronting layer, anywhere, ever.
- Fronting the **issuer** with a CDN is L1-safe (issuance carries account + *blinded*
  material, never plaintext — ADR-0001 §4.2) but is mooted by §2 below: the issuer should
  have no public edge at all.

---

## 2. Decision: collapse the public attack surface to the relay

Route **all** client traffic — inference, redeem, matchmaking reads, issuance, key-config
fetch — through the relay via OHTTP. Broker+gateway and issuer accept inbound only from
relay IPs plus one segregated host-heartbeat listener; they get no DNS names and their
IPs are unpublished (known only to relays and the operator).

- The only publicly discoverable service is the **stateless, secret-free, disposable**
  component — exactly the one that is cheap to replicate and rebuild.
- Strengthens L1: broker and issuer become fully IP-blind (today the issuer would
  otherwise see account↔IP).
- Strengthens L2: the issuer cannot serve per-IP targeted key-configs because it never
  sees an IP; combined with §3.4 consistency checking, per-client key-config attacks
  require defeating multiple independent channels.
- Issuance stays authenticated *inside* the OHTTP payload (Ed25519 account signature,
  ADR-0001 §4.2), so per-account rate limiting survives IP-blindness.

### Alternatives considered

- **2-alt-A: issuer/broker with public endpoints + CDN.** Works, L1-safe (§1), but
  exposes two more origins to attack and leaks account↔IP to the CDN at the issuer edge.
  Rejected: strictly worse than IP-allowlisting behind the relay.
- **2-alt-B: hosts also routed through relays.** Unnecessary — hosts are identified
  parties (they see plaintext by design; L1 concerns the *originator's* IP). Heartbeats
  stay direct to a segregated listener (§4.4). Revisit only if host anonymity becomes a
  Phase-3+ goal.

---

## 3. Decision: L7 DoS — the token economy is the rate limiter (where it applies)

### 3.1 Issuance (blind-sign, ~1 ms RSA each)

Authenticated by account and debits credits → economically self-limiting: nobody can
demand more signatures than credits they bought. Enforce **cheap-first ordering**:
Ed25519 account-sig verify (~50 µs) → balance check (µs) → only then RSA blind-sign. Cap
batch size and per-account concurrency. No identity-free surface here.

### 3.2 Redeem / token_verify

Identity-free **by design** (ADR-0001 §4.3 — no parameter can carry an account on the
spend path), so it cannot be rate-limited by account, and must not be. Two separate
resources:

- **State:** spent-set inserts happen only for *valid* tokens, so spent-set growth is
  bounded by tokens actually purchased in the epoch, and the set is dropped at epoch end
  (ADR-0001 §1). The economy fully bounds state. An attacker who "floods" the spent-set
  is a paying customer.
- **CPU:** garbage tokens cost one RSA-PSS public verify (tens of µs) and are dropped
  before any state write. The economy does *not* bound this; the relay does (§3.5).

### 3.3 Matchmaking reads and host registry

Do not serve queries. The broker emits a **signed registry/latency snapshot** on a fixed
cadence with padded/uniform size (leak L4 discipline); clients fetch it as static,
cacheable content via relay and mirrors. Reads become effectively un-DoS-able; only
writes hit the origin. Host **registration** requires a small burned-credit fee or
proof-of-work plus slow admission; **heartbeats** from unknown key IDs are dropped by a
hash-set lookup *before* Ed25519 verification, so unknown-key floods cost a hash, not a
signature verify.

### 3.4 Key-config: publish, don't serve (leak L2)

Issuer key-config and the relay list are signed artifacts published to ≥ 2 independent
static mirrors (GitHub Releases/raw + Cloudflare R2/Pages, optionally IPFS), with the
current-epoch hash also fetchable through the relay. Clients cross-check all channels and
fail closed on mismatch. This is the Privacy Pass key-consistency problem (RFC 9576
security considerations; draft-ietf-privacypass-consistency) — adopt its framing rather
than inventing one. Mirror fetches reveal "is a Lluma user" to the mirror operator —
accepted; no content linkage.

### 3.5 Per-IP limiting and duress proof-of-work live at the relay — and only there

The relay is the one party *permitted* to see IPs, so per-IP token buckets, exact
request-size bounds (OHTTP capsules have predictable sizes), and an optional client
puzzle under load leak nothing new. Broker/issuer never rate-limit by anything
IP-derived (they never have it) — only by account (issuance) or by token validity
(redeem). **PoW difficulty is one global knob**: per-client-tuned difficulty is a tagging
vector, same class as a targeted key-config (new leak **L12**).

### Alternatives considered

- **3-alt-A: CAPTCHA / account login on redeem.** Breaks the anonymous-bearer design
  (would re-link account↔spend). Rejected outright.
- **3-alt-B: global PoW on every request.** Punishes honest clients constantly for a
  sometimes-attack; keep PoW as a duress mode toggled by load, uniform difficulty.
- **3-alt-C: broker answers matchmaking queries with per-query rate limits.** No identity
  to key limits on (queries arrive via relay); snapshot publication dominates. Rejected.

---

## 4. Decision: redundancy and failover without creating correlation

### 4.1 Relay: fleet of cattle, not a fortress

2–3 stateless relays across distinct providers/ASNs, shipped in the client as a signed
list, updatable via the §3.4 mirrors. Clients select a relay **randomly and stick per
session/epoch** — per-request hopping gives a broker + multi-relay observer intersection
material, and synchronized mass failover is itself a correlatable event (new leak
**L11**); failover uses client-side jittered retry. Relays hold no secrets; rebuild from
one machine definition in minutes.

### 4.2 Issuer: single instance + client token inventory (chosen) vs. issuer HA (rejected)

- **Chosen:** clients pre-fetch token batches (ADR-0001 §3) giving a runway of days; the
  issuer can be down for hours with zero inference impact. One active issuer, epoch key
  loaded at epoch start, cold-restore from encrypted backup onto a fresh VPS if it dies.
- **Rejected — hot-replicated issuer:** every replica holding the epoch secret is another
  key-theft surface, and issuance is low-QPS and not latency-critical. Availability
  engineering here buys risk, not resilience.
- L4 caveat: pre-fetch on a client-side randomized schedule at fixed batch sizes so
  issuance timing doesn't correlate with usage bursts (ADR-0001 leak L4 mitigation).

### 4.3 Broker: durability + warm standby (chosen) vs. synchronous HA (rejected)

- **Chosen:** SQLite + continuous WAL streaming (Litestream-class) to off-site object
  storage (Backblaze B2), fsync on spent-set insert; a second small VPS continuously
  restores the stream and is promoted manually; relays know both broker addresses.
  Async replication ⇒ a seconds-scale respend window on failover — accepted: loss is
  bounded, monetary-only, epoch-scoped, and auditable via signed receipts (ADR-0001 §4.1).
- **Rejected — synchronous multi-node consensus (Postgres sync replication, rqlite/raft):**
  operational weight a solo operator will misconfigure; the failure it prevents (bounded
  respend) is cheaper than the failures it introduces. Standby inherits the broker's
  no-logging discipline (leak L8).

### 4.4 Heartbeat ingress split

Host heartbeats terminate on a separate hostname/IP from the broker core (may sit behind
a CDN — it sees *host* IPs, never originator IPs; L1 holds). A heartbeat flood cannot
starve redeem/matchmaking.

---

## 5. Decision: key and state protection (what a compromise actually costs)

### 5.1 Issuer epoch secret key

**Compromise = unlimited token minting until rotation — never IP/plaintext linkage.**
Blast radius is bounded by epoch length; balance ADR-0001 L2 (long epochs widen the
anonymity set) against minting exposure — start at ~30 days per ADR-0001 and shorten only
on evidence of key-theft risk.

- Generate epoch keys **offline**, ahead of schedule; load into the issuer at epoch start
  via operator passphrase (key encrypted at rest); Shamir-split encrypted backups
  (`age` + SSS-class tooling) held off-site.
- **Detection invariant, monitored continuously:** per-epoch
  `tokens_redeemed ≤ tokens_issued`. Breach ⇒ key compromised ⇒ emergency rotation +
  new key-config through all §3.4 consistency channels.

**Alternatives considered for custody:**

- **Cloud KMS (AWS/GCP/Azure): rejected.** RFC 9474 blind signing requires a *raw* RSA
  private-key operation on the blinded message (s = m′^d mod n), not a standard
  PKCS#1/PSS signing API; cloud KMS services do not expose the raw primitive.
- **PKCS#11 HSM with raw RSA (`CKM_RSA_X_509`), e.g. Nitrokey HSM 2: viable, P2.** Pairs
  with the home-box pattern: issuer front on a dumb VPS, outbound WireGuard/Tailscale
  tunnel to a home/colo machine holding the token — the key never sits on rentable disk.
- **Passphrase-at-boot on a dedicated minimal VPS: chosen for P0** — weakest custody, but
  bounded by the epoch + detection invariant; upgrade path is the HSM.

### 5.2 Broker state (spent-set + ledger/receipts)

- **Wiped/rolled-back spent-set = respend**, bounded to tokens outstanding for the epoch
  remainder — monetary loss only, no privacy loss. Mitigation: §4.3 durability; alert on
  replication lag.
- Ledger and receipts are append-only and signed (ADR-0001 §4.1) → rebuildable/auditable
  from backup; encrypted off-site backups (restic/borg to B2 or rsync.net).
- **Broker compromise cost:** metadata (host registry, timing), spent-set manipulation
  (enable respends, or DoS by marking tokens spent), forging broker-signed receipts. No
  IPs, no plaintext, no issuer key — provided the issuer is a separate host (§7).

### 5.3 Relay compromise cost

The IP/timing view it already has by design, nothing more: no secrets, no logs (journald
volatile/tmpfs, no access logs, no analytics — leak L8), one-command rebuild.

---

## 6. Prioritized recommendations

### P0 — before public launch

| # | Recommendation | Rationale | Privacy caveat |
|---|---|---|---|
| P0-1 | Collapse public surface to the relay; broker+issuer IP-allowlisted, no DNS, unpublished IPs (§2) | Only the stateless disposable component is findable | None — strengthens L1, L2 |
| P0-2 | Relay on a provider with included L3/4 filtering (Hetzner free / OVH VAC / BuyVM+Path.net); no TLS-terminating third party at first | Hosting provider already sees the packets — zero new observers | None new |
| P0-3 | Optional second, clearly-labeled Cloudflare-proxied relay hostname (§1) | Near-free volumetric absorption; CDN sees only IP+ciphertext (OHTTP design point) | **L9** CDN IP log; **L10** same vendor must not front broker edge/DNS; client chooses & pins relay flavor |
| P0-4 | Key-config + relay list published to ≥2 independent signed mirrors; clients cross-check, fail closed (§3.4) | Static signed blobs are effectively un-DoS-able and untargetable | L2 addressed; mirrors learn "is a user" only |
| P0-5 | Cheap-first ordering on issuance; batch + per-account concurrency caps (§3.1) | Can't be made to sign more than credits sold | None |
| P0-6 | Redeem: verify-before-state-write; rely on economy for state bounds, relay for CPU bounds (§3.2, §3.5) | Spent-set growth requires purchased tokens | Never rate-limit redeem by anything identity-like |
| P0-7 | Matchmaking = signed snapshot publication, not queries (§3.3) | Reads become static/cacheable; only writes hit origin | Fixed cadence + padded size (L4) |
| P0-8 | Per-IP limits, size caps, duress-PoW knob at the relay only (§3.5) | Relay is the one party allowed to see IPs | **L12**: one global PoW difficulty, never per-client |
| P0-9 | Issuer key: offline generation, passphrase-at-boot, Shamir off-site backup, `redeemed ≤ issued` alarm (§5.1) | Bounds compromise to one epoch; makes theft detectable | None |
| P0-10 | Broker: fsync + continuous WAL streaming off-site (§5.2) | Durability is cheaper and safer than HA | Backups encrypted; no linking data in them (L8) |

### P1 — before meaningful traffic

| # | Recommendation | Rationale | Privacy caveat |
|---|---|---|---|
| P1-1 | 2–3 relay fleet across distinct providers/ASNs; signed client list + mirror updates (§4.1) | Attack buys hours of degradation, not data | **L11**: sticky-per-session selection, jittered failover |
| P1-2 | Lean on client token inventories instead of issuer HA (§4.2) | Issuer downtime ≠ inference downtime; fewer key copies | L4: randomized pre-fetch schedule, fixed batch sizes |
| P1-3 | Broker warm standby restoring the WAL stream; manual promote (§4.3) | Bounded respend window beats consensus complexity | Standby inherits no-log discipline (L8) |
| P1-4 | Split heartbeat ingress from broker core; CDN-frontable (§4.4) | Heartbeat floods can't starve redeem/matchmaking | CDN sees host IPs only — L1 unaffected |
| P1-5 | Registration fee/PoW + pre-verify key-ID filter on heartbeats (§3.3) | Unknown-key floods cost a hash lookup | None |
| P1-6 | Relay hygiene: no logs, volatile journal, minimal image, one-command rebuild (§5.3) | Compromise cost = its designed view, nothing more | Directly serves L1, L8 |
| P1-7 | Independent monitoring (healthchecks.io / Uptime Kuma outside all three providers); alert on the §5.1 invariant and replication lag | Detection is the compensating control for cheap custody | Monitor must not receive linking data |

### P2 — when funded

| # | Recommendation | Rationale | Privacy caveat |
|---|---|---|---|
| P2-1 | Issuer key into a PKCS#11 raw-RSA HSM (Nitrokey HSM 2) on a home/colo box behind an outbound tunnel (§5.1) | Key never on rentable disk | None |
| P2-2 | Own ASN + /24, BGP anycast for the relay fleet (Vultr BGP / Path.net) | Real volumetric resilience with no TLS-terminating third party | None; ~$1–2k/yr + skill |
| P2-3 | User-run relay pool and/or Tor-reachable relay as an additional client-selectable trust profile | Long-term answer to "the relay operator is still one party" (spec Phase 3/4) | New relay operators join the IP-seeing domain — vetting/no-log policy |
| P2-4 | Transparency log for key-configs (Sigstore Rekor or hash-chained log) replacing "two mirrors" | Verifiable append-only key history (L2) | None |

### Alternatives considered for the relay edge (summary)

| Option | Volumetric protection | What it leaks / cost | Verdict |
|---|---|---|---|
| Provider-included L3/4 filtering (Hetzner/OVH/Path.net) | Good (tens–hundreds of Gbps at provider scale) | Nothing new — provider already carries the traffic | **P0 default** |
| GRE/tunnel scrubbing (Path.net, X4B, Voxility) | Good | Scrubber sees IP + TLS ciphertext (no HTTP metadata) | Acceptable fallback |
| TLS-terminating CDN (Cloudflare/Fastly/bunny) | Best, ~free | IP + OHTTP ciphertext + HTTP metadata = relay's own view; L9/L10 | **P0 as second labeled endpoint** |
| Self-hosted scrubbing (own filtering boxes) | Poor at solo scale — you cannot buy enough upstream | Nothing | Rejected: economics |
| Anycast/BGP own ASN | Very good | Nothing; cost + expertise | **P2** |
| Tor / mixnet in front | N/A for volumetric; strong anonymity | Latency kills interactive inference (ADR-0001 §2, option 2C) | Phase-4 "paranoid mode", not a DDoS tool |
| Over-provisioning alone | Weak | Nothing | Insufficient alone; implicit in fleet sizing |

---

## 7. Minimal viable hardened topology (solo operator, 2–3 VPS, ~$25–40/mo)

- **VPS-A — Relay** (Hetzner; free always-on L3/4 filtering): stateless OHTTP relay, no
  logs, per-IP limits, exact size caps, duress-PoW knob. Optional parallel
  Cloudflare-proxied hostname as the second labeled relay. **Public.**
- **VPS-B — Broker + OHTTP gateway** (OVH, different ASN; VAC filtering): gateway HPKE
  key; spent-set + ledger in SQLite with continuous WAL streaming → Backblaze B2; signed
  registry snapshots pushed out as static content; separate heartbeat listener.
  **Firewalled to relay IPs; no DNS; IP unpublished.**
- **VPS-C — Issuer** (third provider, cheapest tier): epoch key passphrase-loaded at
  epoch start; Shamir-split offline backup; reachable only via relay-forwarded OHTTP;
  issuance authenticated per account. *Budget fallback:* may temporarily co-locate with
  VPS-B — L1 permits it (neither sees IPs; ADR-0001 §0 already assumes one broker+issuer
  operator in MVP) — but it concentrates the epoch secret next to the spent-set; split
  as soon as possible.
- **$0 static tier:** GitHub Releases/raw + Cloudflare Pages/R2 (optionally IPFS) for
  signed key-configs, relay lists, registry snapshots, client updates — the genuinely
  un-DoS-able part of the system.
- **Monitoring:** healthchecks.io / Uptime Kuma on a box outside all three providers;
  alerts on the `redeemed ≤ issued` invariant and WAL replication lag.

**Trust-domain summary:** {originator IP} lives only at VPS-A (+ Cloudflare iff the
proxied hostname is used); {content-side metadata, spent-set, receipts} only at VPS-B;
{epoch secret, account↔credit ledger} only at VPS-C; plaintext only at hosts and clients.
No party's view crosses sets. Distinct providers ⇒ no shared hypervisor, billing, or
logging plane — satisfying L1's operational-separation requirement, not just its
letter.

---

## 8. Leak-register additions (extends ADR-0001 §6)

Cross-references above use ADR-0001's L1/L2/L4/L8 as defined there. New entries:

| # | Leak | Mitigation |
|---|---|---|
| L9 | CDN fronting the relay holds a third-party, subpoenable IP log of the user base (jurisdiction exposure) | CDN-proxied relay is a *separate, labeled* endpoint clients opt into and pin; bare-provider relay always offered; never give any fronting layer the gateway HPKE key |
| L10 | One vendor fronting both relay edge and broker/gateway edge (or their DNS) gains a two-sided vantage for ciphertext-matching / timing correlation | Hard rule: distinct vendors per side; broker/issuer have no CDN and no public DNS at all (§2) |
| L11 | Relay selection & failover pattern as a client fingerprint; synchronized mass failover is a correlatable event | Random sticky-per-session/epoch relay choice; client-side jittered retry; no per-request hopping |
| L12 | Per-client-tuned PoW difficulty (or any per-client duress parameter) tags individual users — same class as a targeted key-config (L2) | Single global difficulty knob, published/observable; uniform application at the relay |
| L13 | Payment rail links real-world identity to credit purchases; purchase-timing can correlate with issuance bursts | Out of crypto's reach by design — blinding already unlinks purchase from spend (ADR-0001 §4.2); decouple issuance timing from purchase (client-side scheduling, fixed batches per L4); keep payment processor blind to usage data; deplatforming risk noted in §9 |
| L14 | Co-located issuer+broker (MVP, R6) sees the account at `/issue` and the token at `/exec` over one operator; debit/redeem timing could be correlated | Client fixed-batch randomized pre-fetch + randomized spend delay (#5); eliminated by the VPS-C issuer/broker split behind the `settle()` seam |
| L15 | Usage-receipt `units` is a host-attested response-size channel per `spend_id` that survives future response padding | Coarse buckets (`units ≤ 4`) + hour-coarse `timestamp_h`; credit is 1/receipt regardless of `units`; revisit if finer metering is ever added |
| L16 | Trial registration (`/v1/register`) binds `account_pk` → issue → spend for a brand-new account at its most identifiable moment, extending the issue→spend temporal correlation earlier | Trial register MUST ride the relay/gateway path (never the direct host-ingress listener); #5 pre-fetch pools + randomized spend delay |
| L17 | A direct (non-relay) snapshot GET reveals the client IP as a Lluma user plus fetch-timing that precedes an exec | Fetch the signed snapshot over the relay path on a fixed cadence (client, #5); snapshot is a static signed blob so any cache/CDN in front sees only ciphertext-equivalent bytes |

---

## 9. Consequences and honest limits

**What this buys.** The stateful, secret-holding services become unreachable except
through the relay; the L7 paths that matter are bounded by the token economy (state) and
the relay (CPU); every compromise has a stated, bounded, monetary-only cost with a
detection invariant; and every mitigation layer has been placed in an explicit trust
domain, so hardening never silently widens who can link identity to content.

**What cannot be made un-DDoS-able — set expectations accordingly:**

- A $10 VPS relay will always be knock-off-able by a sufficiently large volumetric
  attack. The honest posture is a fleet of cheap, stateless, log-free relays across
  providers with client-side failover: an attack buys the adversary hours of
  degradation, never data. Design for cheap recovery, not invulnerability.
- What *is* effectively un-DoS-able: the static tier (signed key-configs, relay lists,
  snapshots) and — economically — the stateful L7 paths.
- A **global passive observer**, or a single vendor fronting every edge (L10), can do
  timing correlation regardless of topology. Mitigations at this layer are only L4
  discipline (fixed batches, jitter, padded snapshots, coarse timestamps); the real
  answer is user-run relays/mixnets (P2-3, spec Phase 3/4).
- **Solo-operator key custody is the weakest single link.** Compensating controls are
  epoch-bounded blast radius, the `redeemed ≤ issued` alarm, and the P2 HSM path — not
  wishful hardening.
- The **broker is the true availability SPOF** (matchmaking + double-spend arbiter). It
  gets durability plus a warm standby, and we accept a bounded respend window on
  failover rather than pretending consensus-grade HA is operable solo.
- **Payment rails** (Stripe et al.) are DoS-able and deplatformable outside our control
  (L13). Issuance is decoupled from payment settlement so a payment outage never touches
  inference availability; client token inventories decouple inference from issuance in
  turn.

---

## References

- ADR-0001 — `lluma-crypto` primitives (threat model §0, tokens §1, OHTTP §2, leak
  register §6)
- RFC 9458 — Oblivious HTTP (relay/gateway split; the reason TLS-terminating relay-side
  infrastructure sees only ciphertext)
- RFC 9474 — RSA Blind Signatures (raw private-key op ⇒ cloud KMS unusable, §5.1)
- RFC 9576 — Privacy Pass architecture (key-consistency security considerations);
  [draft-ietf-privacypass-consistency](https://datatracker.ietf.org/doc/draft-ietf-privacypass-key-consistency/)
  — key-config consistency framing adopted in §3.4
- Deployed OHTTP-relay precedent: Apple iCloud Private Relay (Cloudflare/Fastly/Akamai
  as relays), Mozilla Firefox OHTTP relay (Fastly)
- Tooling named (current as of 2026-07): Hetzner DDoS protection, OVH VAC, Path.net /
  BuyVM, Cloudflare (proxy, Pages, R2), Backblaze B2, Litestream, restic/borg,
  rsync.net, healthchecks.io, Uptime Kuma, Nitrokey HSM 2 (PKCS#11 `CKM_RSA_X_509`),
  Tailscale/WireGuard, Sigstore Rekor, `age` + Shamir secret sharing
