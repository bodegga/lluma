# Lluma — Design Specification (v1)

> Anonymous, contribution-based, peer-to-peer LLM inference.
> A **Bodegga** project. *Lluma* — a double-**L** nod to **LL**M and a play on Peta**luma**.

- **Status:** Approved architecture, pre-implementation
- **Date:** 2026-07-14
- **Author:** Bodegga / Lluma
- **Supersedes:** none

---

## 1. Summary

Lluma is a network that lets anyone get **anonymous LLM inference** — where no single participant can tie *who you are* to *what you asked* — while the compute is supplied by a **contribution-based, torrent-style peer-to-peer fabric** of volunteer hosts, plus donated commercial API keys.

The design fuses three ideas:

1. **Unlinkable inference** (as pioneered by the Open Anonymity Project / OpenPCC): blind-signed tokens + Oblivious-HTTP-style relaying so identity and content are never held by the same party.
2. **BitTorrent-style distribution**: model *weights* are content-addressed and seeded peer-to-peer; peers/seeds/trackers with self-healing and latency-aware routing.
3. **A contribution economy**: you must put resources in before you take inference out, with the contribution tiered to whatever your device can actually give.

Everything is delivered through a **point-and-click desktop app** (Rust core + Tauri UI) that auto-detects hardware and makes hosting a model a one-click action, expanding the pool of people who understand and run local LLMs.

### Non-goals (v1)

- Cross-WAN sharded/pipeline inference of a single model across many peers (too slow/fragile — see §4).
- FHE or MPC inference (orders of magnitude too slow for interactive LLMs today — see §7).
- A blockchain/crypto token (accounting is off-chain — see §8).
- Mobile and browser clients (Phase 4+).
- A public OpenAI-compatible gateway (Phase 4).

---

## 2. Goals & success criteria

**Primary goal:** a user can install one app, contribute compute in one click, and — anonymously — get useful LLM output, with no party able to deanonymize the request originator.

**Success criteria (MVP / Phase 1):**

- A consumer request completes end-to-end with **no single party holding both the originator's IP and the prompt plaintext**.
- Requests from the same user are **unlinkable** to each other and to the user's identity (fresh ephemeral key per session; blind-token entitlement).
- A newcomer can go from install → contributing → first inference in **under 5 minutes** on capable hardware.
- Hosting a model is a **one-click** action after an automatic hardware benchmark + model recommendation.
- The network sustains supply: leeching is impossible long-term (contribution economy), and Sybil attacks cost real resources.

---

## 3. Core privacy principle

**No single participant ever holds both "who you are" and "what you asked."**

Three concerns are split across three parties; none is trusted with the whole picture:

| Party | Sees | Never sees |
|---|---|---|
| **Relay** (Oblivious HTTP) | Originator IP, an encrypted blob | The prompt plaintext; which host serves it |
| **Broker / Tracker** | Ciphertext + routing metadata (model-id, coords), the relay's IP | The originator's real IP; the prompt plaintext |
| **Host** (serving node) | The prompt plaintext (Open tier) *or* nothing (Confidential/TEE tier) | The originator's IP; the originator's identity; the originator's other requests |

Reinforced by:

- **Blind-signed entitlement tokens** — a user proves "I hold credits" without revealing *who*, and token **issuance cannot be linked to redemption**. This is the same primitive OpenAnonymity uses.
- **Ephemeral session keys** — a fresh key per session means requests are unlinkable to the user and to one another. An observer cannot tell whether 100 requests came from 100 people or 1 person.

### 3.1 Honesty about the guarantee (Open tier)

For **volunteer, non-TEE hosts** (the "Open tier"), the guarantee is:

> The serving host **cannot link the prompt to your identity or IP**, and your requests are spread across many hosts so no host sees your history.

It is **not**:

> "The host cannot read the prompt."

Content-blindness against the serving operator requires the **Confidential (ZK) tier** (§7). We document this plainly and never market the Open tier as "zero-knowledge."

### 3.2 The path is already zero-knowledge

Everything *along the path* — relay, broker, and the seeds that distribute weights — never sees plaintext. The relay sees ciphertext + IP; the broker sees ciphertext + routing metadata; seeds move only encrypted **weight files**, never prompts. The only party that ever sees a prompt is the final serving node, and only that node is addressed by the tiered-trust model in §7.

---

## 4. Roles — the torrent analogy made precise

**Lluma torrents the model *weights*, but runs each inference whole-model on a single host.** Cross-WAN layer/tensor sharding is explicitly out of scope: WAN latency makes token-by-token cross-peer inference slow and fragile.

- **Seed** — a host that holds a model's weights and both (a) serves inference and (b) seeds the weight files to others.
- **Peer** — a node fetching weights (content-addressed, verified on arrival) and/or a lightweight consumer.
- **Tracker** — the **Broker**: announces which hosts serve which models, tracks health/latency/reputation, and matchmakes requests to hosts. **Centralized in the MVP**, decentralized (DHT + gossip) in Phase 3.
- **Latency beacon** — overlay **network coordinates** (Vivaldi-style synthetic coordinates computed over the relay layer, *not* raw-IP geolocation). Lets the broker/client select the nearest fast host without anyone learning real IPs.

**Self-healing:** hosts send signed heartbeats; the tracker (and later, gossip) evicts dead/unhealthy hosts and re-routes in-flight demand. Requests that fail mid-flight are retried against the next-best host transparently.

---

## 5. Request lifecycle (MVP)

```
Consumer app                 Relay (OHTTP)         Broker / Tracker          Host (seed)
  │  (out of band) blind-token  →  ephemeral session key  [from Issuer]
  │  encrypt(prompt) to the chosen Host's published key
  ├──── OHTTP-encapsulated ───►│
  │                            ├─ ciphertext + model-id + net-coords ─►│
  │                            │        match by latency + load + reputation + tier
  │                            │◄──────────── chosen host route ────────┤
  │                            ├──────────── forward ciphertext ───────────────────►│
  │                            │                                           decrypt + infer
  │◄──── streamed response (reverse path, E2E encrypted to consumer) ─────────────────┤
  │                                              signed usage receipt ───►│ (credit accounting)
```

Notes:

- **Issuer / Station** blind-signs entitlement tokens out of band; the client redeems a token for an **ephemeral session key**. Issuance↔redemption are unlinkable.
- The prompt is **end-to-end encrypted to the serving host's published key**, so the broker only ever matchmakes and relays ciphertext.
- The relay hides the originator's IP from both broker and host.
- The response streams back along the reverse path, E2E-encrypted to the consumer.
- The host emits a **signed usage receipt** used for credit accounting (§8); the receipt is redeemed through blind tokens so it never links contribution/spend to identity.

### 5.1 Error handling & resilience

- **Host failure mid-request:** relay/broker detect timeout or dropped heartbeat → transparent retry against next-best host; consumer sees at most a brief reconnect.
- **No host for a model:** broker returns a typed "no capacity" error; client offers to (a) wait/queue, (b) pick an available model, or (c) fetch+host it locally if capable.
- **Token/credit exhaustion:** typed "insufficient credits" error → client routes user to the Contribute tab.
- **Weight fetch corruption:** BLAKE3 hash mismatch → chunk re-fetched from another seed; never loaded.
- **Relay unreachable:** client fails over to an alternate relay from its bootstrap list.

---

## 6. Contribution economy (anti-leech + anti-Sybil)

**Principle:** you must contribute resources before you sustainably consume. Contribution is **tiered to your device**, auto-detected on install:

| Device capability | Contribution ("skin in the game") | Reward |
|---|---|---|
| Capable GPU / ample RAM | **Host a model** (hero path — educational, best rewards, the celebrated default) | ★★★ |
| Weak / always-on machine (Pi, phone, NAS) | **Seed weights + run a relay** (bandwidth/storage) | ★★ |
| No spare compute | **Donate an API key** (real inference contributed, see §9) | ★★ |
| Truly can't contribute | Small community-sponsored trial, then locked until contributing | ★ |

Rules:

- **Hosting is best-rewarded but not required.** Capable machines are strongly nudged toward hosting (education flywheel), but no one is walled out by hardware.
- **Trial grant:** a newcomer gets a small, community-sponsored grant (a handful of calls) to *feel* the product; sustained consumer access then **locks until a contribution is set up**.
- **Ratio maintenance:** keep contributing to keep spending. A sustained negative ratio throttles the account (private-tracker mechanic = the "no leeching" rule, graduated rather than binary).
- **Anonymous accounting:** contribution and spend are tracked via **signed receipts redeemed through blind tokens**, so the economy never deanonymizes anyone (§8).

**Security benefit:** because every identity must burn real resources to participate, Sybil/abuse attacks (mass fake consumers) cost money — the contribution gate doubles as a rate-limiter.

---

## 7. Trust tiers & zero-knowledge

To run a model on a plaintext prompt, some silicon must hold that prompt in the clear — *unless* one of three techniques is used:

| Technique | Serving host sees prompt? | LLM-speed today? | Verdict |
|---|---|---|---|
| **Plaintext** (normal) | Yes | ✅ Fast, any consumer GPU | Open tier |
| **TEE / confidential computing** | **No** — only a sealed, attested enclave does | ✅ Near-native | **Confidential (ZK) tier** — the practical ZK path |
| **FHE** | No — never decrypted | ❌ ~10³–10⁶× too slow | Future research only |
| **MPC** | No single party | ❌ Huge bandwidth, needs non-colluding peers | Future research only |

**Definition:** in Lluma, "**zero-knowledge inference**" means **TEE-attested, operator-blind** — the prompt is plaintext only inside a hardware enclave the operator cannot inspect, with attestation cryptographically proving the enclave runs approved, non-logging code. It does **not** mean "never decrypted anywhere" (that would be FHE).

**Two tiers, chosen per request by the requester:**

- **Open tier** — any consumer GPU. Host sees the prompt but cannot link it to the originator. Hardened by:
  - **Signed, open-source, no-log node software** (MVP), and
  - **Random canary audits** — planted requests that detect a node that logs or leaks (Phase 3).
  This is *verifiable good behavior*, not cryptographic blindness — but it materially raises community trust for the fast tier.
- **Confidential (ZK) tier** — TEE-attested hosts only (NVIDIA confidential GPU, Intel TDX, AMD SEV-SNP). Operator is provably blind. A consumer can flag a request **"confidential only"**, and it will route only to attested nodes. Scarcer/costlier hardware ⇒ earns more credits. Ships in **Phase 4**; grows over time and can eventually become the default.

**Trade-off documented:** requiring the ZK tier universally would shrink the volunteer pool to confidential-computing hardware and contradict the grassroots home-GPU vision. Hence tiers coexist and the requester decides.

---

## 8. Credit & accounting model

- Credits are an **off-chain**, anonymous unit. Contributing compute/bandwidth/keys **earns** credits; consuming inference **spends** them.
- Every served request produces a **signed usage receipt** from the host. Receipts are aggregated by the accounting service into credit balances.
- Balances are spent by presenting **blind tokens**, so "who earned" and "who spent" cannot be correlated to an identity.
- **Bootstrap:** new accounts get a small community-sponsored grant (funded by contribution surplus + API-key donors).
- **Pricing:** credit cost per request scales with model size/compute and tier (Confidential > Open). Exact schedule is a tunable config, not hard-coded.
- **No token trading / no fiat** in v1 — credits are non-transferable and redeemable only for your own inference. (Keeps it out of regulatory/scope trouble.)

---

## 9. API-key donation bridge

A host mode for people with no spare GPU:

- The user pastes a commercial API key (OpenAI / Anthropic / etc.). Their node becomes a **gateway host**.
- It receives network requests like any host, **translates** them to the upstream provider's API, spends the donated quota, and earns credits.
- **Keys are encrypted at rest locally and never leave the machine** or reach the broker.
- Gateway hosts are matched like any other host (by model capability, latency, reputation), and are subject to the same signed-receipt accounting.
- Donors can set caps (spend/day, models allowed) to bound their exposure.

---

## 10. Host app (UX)

A single **Tauri (Rust core + web UI)** desktop app with two faces:

- **Contribute tab** — one large toggle. On first run it **benchmarks hardware** (RAM, VRAM, CPU, disk, bandwidth), pulls a **demand signal** from the broker (which models are under-supplied), and recommends *one* model + quant that both fits the machine and serves network need — e.g. *"Recommended: Llama-3.1-8B Q4 — fits your 16 GB, network needs it. [Start contributing]"*. Advanced users can override. Runs as a low-footprint background daemon / tray icon.
- **Chat tab** — the consumer client: type prompts, pick a model or "Auto", choose trust tier (Open / Confidential-only), get anonymous inference.

Model runtime: a **bundled llama.cpp / GGUF runner**. Weights are fetched via the registry/torrent layer (§11) and verified by hash before loading.

---

## 11. Model distribution (torrent layer)

- Model **weights** are **content-addressed** (BLAKE3) and chunked. A **model registry** maps `model-id → manifest` (chunk hashes, quant variants, metadata, recommended hardware, credit cost).
- Hosts fetch weights from **seeds** (other hosts) over the P2P fabric and verify each chunk by hash; corrupt chunks are re-fetched from another seed.
- This weight-distribution path is **separate** from the inference path and never carries prompts.
- Ships in **Phase 2** (MVP fetches weights from a simple registry/CDN; P2P seeding is the Phase-2 upgrade).

---

## 12. Component architecture (Rust workspace + Tauri)

Small, focused, independently testable crates:

```
lluma/
├─ crates/
│  ├─ lluma-core       # shared types, protocol messages, errors
│  ├─ lluma-crypto     # blind signatures, OHTTP encapsulation, token issuance/redemption
│  ├─ lluma-net        # libp2p transport, relay client, network coordinates / latency beacon
│  ├─ lluma-runtime    # model-runner trait + llama.cpp binding, hardware detection, auto-select
│  ├─ lluma-registry   # model manifests + content-addressed weight distribution (BLAKE3)
│  ├─ lluma-host       # host daemon: serve, seed, earn, API-key bridge
│  ├─ lluma-broker     # tracker / matchmaker + credit accounting (centralized in MVP)
│  ├─ lluma-relay      # Oblivious-HTTP relay
│  ├─ lluma-issuer     # blind-token station
│  └─ lluma-client     # consumer inference client library
├─ apps/
│  └─ lluma-desktop    # Tauri app (src-tauri + web frontend): Contribute + Chat tabs
├─ docs/               # architecture, ADRs, specs
├─ .claude/agents/     # specialized subagents (see §15)
├─ AGENTS.md · CLAUDE.md · README.md
```

**Boundary contracts (what/how/depends-on):**

- `lluma-crypto` — *what:* all cryptographic primitives (blind signatures, OHTTP encapsulate/decapsulate, token flows). *How:* pure functions over byte types from `lluma-core`. *Depends on:* audited crypto libraries only. No network, no I/O.
- `lluma-net` — *what:* anonymous transport (relay client, libp2p, network coordinates). *How:* send/receive encrypted frames; expose a latency-beacon API. *Depends on:* `lluma-core`, `lluma-crypto`.
- `lluma-runtime` — *what:* run a GGUF model + detect hardware + recommend a model. *How:* a `ModelRunner` trait with a llama.cpp implementation. *Depends on:* `lluma-core`.
- `lluma-broker` — *what:* matchmaking + accounting. *How:* HTTP/RPC service; pluggable so it can decentralize later. *Depends on:* `lluma-core`, `lluma-crypto`.
- `lluma-host`, `lluma-relay`, `lluma-issuer`, `lluma-client` — thin orchestrators composing the above.

---

## 13. Build phases (progressive decentralization)

- **Phase 0 — Dogfood:** host app + local llama.cpp runner + local OpenAI-compatible loopback. No network. Proves the app + runtime.
- **Phase 1 — MVP:** centralized broker + relay + blind-token issuer + credits ⇒ **end-to-end anonymous inference** across volunteer hosts *and* API-key donors. Open-tier hardening = signed no-log binaries + unlinkability. ← *the shippable slice*.
- **Phase 2 — Torrent layer:** P2P content-addressed weight distribution + model registry + seeding.
- **Phase 3 — Decentralize:** DHT tracker, multiple relays, gossip health, network-coordinate beaconing, self-healing, canary audits.
- **Phase 4 — Hardening & reach:** Confidential (TEE) tier + attestation; optional I2P/Tor "paranoid" mode; public OpenAI-compatible gateway; web/mobile clients.

---

## 14. Testing strategy

- **Unit tests** per crate; `lluma-crypto` gets property-based tests for blind-signature unlinkability and OHTTP round-trips, plus known-answer vectors.
- **Integration tests:** spin up issuer + relay + broker + host + client in-process and assert the full lifecycle, including the invariant *no party holds both IP and plaintext* (verified by inspecting what each mock party received).
- **Privacy invariants as tests:** issuance↔redemption unlinkability; fresh-key-per-session; relay-never-sees-plaintext; broker-never-sees-plaintext/IP.
- **Resilience tests:** kill a host mid-request → transparent retry; corrupt a weight chunk → re-fetch; relay down → failover.
- **Hardware-detection tests:** golden fixtures for representative machine profiles → expected model recommendation.
- TDD per the project's standard workflow; privacy invariants are written as failing tests first.

---

## 15. How we build it (agent strategy)

- **Fable (`claude-fable-5`)** for high-reasoning work: protocol/crypto design, ADRs, threat modeling, architecture review.
- **Smaller models via subagents** (Sonnet / Haiku) for implementation grunt work: crate boilerplate, tests, glue, docs.
- Purpose-built agent definitions live in `.claude/agents/`: `protocol-crypto-architect` (Fable), `rust-net-engineer`, `model-runtime-engineer`, `tauri-frontend`, `test-writer`, `docs-writer`.

---

## 16. Open questions / future work

- Exact credit pricing schedule and ratio-throttle curve (tunable config; needs live data).
- Attestation verifier design and reference-measurement management for the Phase-4 Confidential tier.
- Governance of the model registry (who can publish a model manifest; abuse/malware review of shared weights).
- Abuse handling for generated content (the network serves inference; content-policy posture per tier is a Phase-3/4 policy question).
- I2P/Tor "paranoid" mode integration details (Phase 4).
```
