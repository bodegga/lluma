# Lluma Phase 0 (Dogfood) + Scaffold — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a point-and-click Lluma desktop app that auto-detects hardware, recommends and downloads a GGUF model, and runs a local streaming chat — plus the full repo scaffold, agent definitions, and README. No network/privacy layer yet (that is Phase 1).

**Architecture:** A Rust cargo workspace. Pure logic crates (`lluma-core`, `lluma-runtime`, `lluma-registry`) are unit-testable with no I/O in their core functions; the llama.cpp binding lives behind a `ModelRunner` trait so consumers test against a `MockRunner`. A Tauri v2 desktop app (`lluma-desktop`) exposes Rust commands to a minimal web UI with **Contribute** and **Chat** tabs and streams generated tokens to the frontend via Tauri events.

**Tech Stack:** Rust (edition 2021), Tauri v2, `llama-cpp-2` (GGUF inference), `sysinfo` (hardware detection), `nvml-wrapper` (best-effort NVIDIA VRAM), `blake3` (content addressing), `reqwest` (model download), `serde`/`serde_json`, `thiserror`, `tokio`.

## Global Constraints

- Language: **Rust edition 2021**; workspace resolver `"2"`.
- Desktop framework: **Tauri v2** (`tauri = "2"`, `tauri-build = "2"`).
- Inference binding: **`llama-cpp-2`** (crate imports as `llama_cpp_2`).
- Content addressing hash: **BLAKE3** everywhere (never MD5/SHA1).
- Brand strings: product **"Lluma"**, umbrella **"Bodegga"**. Never lowercase "lluma" in user-facing copy.
- All errors are typed with `thiserror`; no `unwrap()`/`expect()` in library crates except in tests.
- TDD: write the failing test first; commit after every green step.
- Commit message co-author trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Primary dev OS is Windows; keep code cross-platform (no hard-coded path separators — use `std::path`).

---

### Task 1: Repo scaffold, workspace, and project meta

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `.gitignore`
- Create: `rust-toolchain.toml`
- Create: `README.md`
- Create: `AGENTS.md`
- Create: `CLAUDE.md`
- Create: `.claude/agents/protocol-crypto-architect.md`
- Create: `.claude/agents/rust-net-engineer.md`
- Create: `.claude/agents/model-runtime-engineer.md`
- Create: `.claude/agents/tauri-frontend.md`
- Create: `.claude/agents/test-writer.md`
- Create: `.claude/agents/docs-writer.md`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: a buildable empty workspace; crate members added in later tasks.

- [ ] **Step 1: Create the workspace `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = [
    "crates/lluma-core",
    "crates/lluma-runtime",
    "crates/lluma-registry",
]

[workspace.package]
edition = "2021"
license = "Apache-2.0"
authors = ["Bodegga / Lluma"]
repository = "https://github.com/bodegga/lluma"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
blake3 = "1"
sysinfo = "0.33"
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["stream"] }
```

- [ ] **Step 2: Create `.gitignore`**

```gitignore
/target
**/*.rs.bk
Cargo.lock
node_modules
dist
.DS_Store
# downloaded model weights
/models
*.gguf
# Tauri build output
apps/lluma-desktop/src-tauri/target
apps/lluma-desktop/dist
```

- [ ] **Step 3: Create `rust-toolchain.toml`**

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 4: Create `README.md`**

````markdown
# Lluma

> Anonymous, contribution-based, peer-to-peer LLM inference. A **Bodegga** project.
> *Lluma* — a double-**L** nod to **LL**M and a play on Peta**luma**.

Lluma lets anyone get **anonymous LLM inference** — where no single participant can tie
*who you are* to *what you asked* — with compute supplied by a **contribution-based,
torrent-style peer-to-peer fabric** of volunteer hosts plus donated commercial API keys.

See the full design in [`docs/superpowers/specs/2026-07-14-lluma-design.md`](docs/superpowers/specs/2026-07-14-lluma-design.md).

## Core principle

**No single participant ever holds both "who you are" and "what you asked."**
Identity and content are split across a relay, a broker, and a serving host; blind-signed
tokens make request entitlement unlinkable to identity.

## Status

Phase 0 (Dogfood): a point-and-click desktop app that auto-detects your hardware,
recommends and downloads a GGUF model, and runs a local streaming chat.
The anonymous network (relay + broker + credits) arrives in Phase 1.

## Roadmap

- **Phase 0 — Dogfood:** local host app + GGUF runtime + local chat. ← *current*
- **Phase 1 — MVP:** relay + broker + blind-token issuer + credits → anonymous inference.
- **Phase 2 — Torrent layer:** P2P content-addressed weight distribution.
- **Phase 3 — Decentralize:** DHT tracker, gossip health, latency beaconing, canary audits.
- **Phase 4 — Hardening:** TEE-attested confidential tier, paranoid mode, wider clients.

## Build

```bash
cargo build
cargo test
# run the desktop app (after Task 7):
cd apps/lluma-desktop && cargo tauri dev
```

## Repository layout

```
crates/lluma-core       shared types, errors
crates/lluma-runtime    hardware detection, model recommendation, GGUF runner
crates/lluma-registry   model catalog + content-addressed download/verify
apps/lluma-desktop      Tauri app (Contribute + Chat tabs)
docs/                   specs, plans, architecture
.claude/agents/         specialized subagents for building Lluma
```

## License

Apache-2.0.
````

- [ ] **Step 5: Create `AGENTS.md`**

````markdown
# Lluma — Agent & Contributor Guide

This file orients any agent or engineer working in this repo.

## What Lluma is

Anonymous, contribution-based, peer-to-peer LLM inference. Read
`docs/superpowers/specs/2026-07-14-lluma-design.md` before making architectural changes.

## Golden rules

- **Privacy invariant:** never write code where a single party holds both the originator's
  IP and the prompt plaintext. If a change could violate this, stop and flag it.
- **Typed errors:** every crate defines its errors with `thiserror`. No `unwrap()`/`expect()`
  in library code outside tests.
- **TDD:** failing test first, then implementation, then commit. Small commits.
- **Content addressing:** BLAKE3 only.
- **Brand:** "Lluma" and "Bodegga" are always capitalized in user-facing copy.

## How we build (model strategy)

- **Fable (`claude-fable-5`)** does the high-reasoning work: protocol/crypto design, ADRs,
  threat modeling, architecture review. Use the `protocol-crypto-architect` agent.
- **Smaller models (Sonnet/Haiku) via subagents** do implementation grunt work: crate
  boilerplate, tests, glue, docs. Use `rust-net-engineer`, `model-runtime-engineer`,
  `tauri-frontend`, `test-writer`, `docs-writer`.

## Build & test

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

## Layout

See `README.md` → Repository layout.
````

- [ ] **Step 6: Create `CLAUDE.md`**

```markdown
# CLAUDE.md

Project-specific instructions for Claude Code in the Lluma repo.

## Read first
- Design spec: `docs/superpowers/specs/2026-07-14-lluma-design.md`
- Contributor guide: `AGENTS.md`

## Non-negotiables
- Privacy invariant: no single party ever holds both originator IP and prompt plaintext.
- Typed errors via `thiserror`; no `unwrap()`/`expect()` in library crates (tests excepted).
- BLAKE3 for all content addressing.
- TDD with frequent commits; run `cargo test` and `cargo clippy --all-targets -- -D warnings`
  before claiming a task is done.

## Model strategy
- Use Fable (`claude-fable-5`) for architecture/crypto/protocol reasoning.
- Use smaller models via subagents for implementation.

## Commit trailer
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
```

- [ ] **Step 7: Create `.claude/agents/protocol-crypto-architect.md`**

```markdown
---
name: protocol-crypto-architect
description: Use for high-reasoning design work on Lluma — the privacy protocol (OHTTP relaying, blind-signed tokens, unlinkability), threat modeling, cryptographic primitive selection, ADRs, and architecture review. Invoke before implementing any crypto or protocol change.
tools: Read, Grep, Glob, WebFetch, WebSearch, Write, Edit
model: fable
---

You are Lluma's protocol and cryptography architect. You reason carefully about the
privacy invariant: **no single party ever holds both the originator's IP and the prompt
plaintext.**

When given a task:
- Restate the threat model and trust assumptions explicitly.
- Prefer well-reviewed primitives (blind signatures, Oblivious HTTP, HPKE) over novel crypto.
- Produce ADRs in `docs/architecture/` with alternatives considered and the decision rationale.
- Call out any place a design could leak linkage between identity and content.
- Do not write production crypto without citing the primitive and library you rely on.
```

- [ ] **Step 8: Create `.claude/agents/rust-net-engineer.md`**

```markdown
---
name: rust-net-engineer
description: Use to implement Lluma's Rust networking and systems crates (lluma-net, lluma-relay, lluma-broker, lluma-issuer, lluma-host). Implements libp2p transport, relay client, network coordinates, and services. Follows TDD.
tools: Read, Grep, Glob, Edit, Write, Bash
model: sonnet
---

You implement Lluma's Rust networking and service crates. Follow the plan task exactly.
Write the failing test first, run it, implement minimally, run tests, commit.
Use typed errors (`thiserror`). No `unwrap()`/`expect()` outside tests.
Never break the privacy invariant. When a task's interface block names a type or function,
use those exact names and signatures.
```

- [ ] **Step 9: Create `.claude/agents/model-runtime-engineer.md`**

```markdown
---
name: model-runtime-engineer
description: Use to implement Lluma's model runtime — hardware detection, model recommendation, GGUF loading and streaming generation via llama-cpp-2 (lluma-runtime, lluma-registry). Follows TDD.
tools: Read, Grep, Glob, Edit, Write, Bash
model: sonnet
---

You implement Lluma's model runtime crates. Keep pure logic (hardware profiling,
recommendation, hashing) free of I/O so it is unit-testable. Put llama.cpp behind the
`ModelRunner` trait so consumers can use `MockRunner` in tests. Follow TDD and commit often.
Use typed errors. Verify llama-cpp-2 API details against current docs before coding.
```

- [ ] **Step 10: Create `.claude/agents/tauri-frontend.md`**

```markdown
---
name: tauri-frontend
description: Use to build and wire the Lluma Tauri v2 desktop app (apps/lluma-desktop) — Rust commands, managed state, streaming events, and the Contribute + Chat tab web UI.
tools: Read, Grep, Glob, Edit, Write, Bash
model: sonnet
---

You build Lluma's Tauri v2 desktop app. Expose Rust logic through `#[tauri::command]`
functions registered with `tauri::generate_handler!`. Manage shared state with
`tauri::State<Mutex<...>>`. Stream tokens to the frontend with `app.emit`. Keep the UI
minimal, accessible, and clearly branded "Lluma". Do not put business logic in the UI —
call into the Rust crates.
```

- [ ] **Step 11: Create `.claude/agents/test-writer.md`**

```markdown
---
name: test-writer
description: Use to write focused unit and integration tests for Lluma crates, including property-based tests for crypto and privacy-invariant assertions. Does not write production code.
tools: Read, Grep, Glob, Edit, Write, Bash
model: sonnet
---

You write tests only. Prefer behavior-focused tests with clear arrange/act/assert structure.
For crypto, add property-based tests (unlinkability, round-trips) and known-answer vectors.
For the network layer, assert the privacy invariant by inspecting what each mock party
received. Never weaken a test just to make it pass.
```

- [ ] **Step 12: Create `.claude/agents/docs-writer.md`**

```markdown
---
name: docs-writer
description: Use to write and maintain Lluma documentation — README, module docs, ADR formatting, and user-facing help copy. Keeps brand voice consistent.
tools: Read, Grep, Glob, Edit, Write
model: haiku
---

You write clear, concise Lluma documentation. Keep "Lluma" and "Bodegga" capitalized.
Explain the privacy model honestly — never over-claim "zero-knowledge" for the Open tier.
Match the existing tone in README.md.
```

- [ ] **Step 13: Verify the workspace builds and commit**

Run: `cargo build`
Expected: `Finished` with no errors (workspace has no members yet that fail; if cargo errors that members don't exist, that is expected until Task 2 — in that case skip build here and build after Task 2). Then:

```bash
git add -A
git commit -m "chore: scaffold Lluma workspace, agents, README, and project meta

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `lluma-core` — shared types & errors

**Files:**
- Create: `crates/lluma-core/Cargo.toml`
- Create: `crates/lluma-core/src/lib.rs`
- Create: `crates/lluma-core/src/model.rs`
- Create: `crates/lluma-core/src/hardware.rs`
- Create: `crates/lluma-core/src/error.rs`

**Interfaces:**
- Consumes: workspace deps `serde`, `thiserror`.
- Produces:
  - `enum Quant { Q4KM, Q5KM, Q8, F16 }` with `Display`.
  - `struct ModelId(pub String)`.
  - `struct HardwareProfile { pub ram_bytes: u64, pub vram_bytes: Option<u64>, pub cpu_cores: usize, pub disk_free_bytes: u64 }`.
  - `struct ModelSpec { pub id: ModelId, pub display_name: String, pub quant: Quant, pub params_billions: f32, pub download_bytes: u64, pub min_ram_bytes: u64, pub blake3_hex: String, pub url: String }`.
  - `struct ModelRecommendation { pub spec: ModelSpec, pub reason: String }`.
  - `enum LlumaError { ... }` (see below), `type Result<T> = std::result::Result<T, LlumaError>`.

- [ ] **Step 1: Create `crates/lluma-core/Cargo.toml`**

```toml
[package]
name = "lluma-core"
version = "0.0.0"
edition.workspace = true
license.workspace = true

[dependencies]
serde = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
serde_json = { workspace = true }
```

- [ ] **Step 2: Write the failing test for serde round-trip and Quant display**

Create `crates/lluma-core/src/model.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Quant {
    Q4KM,
    Q5KM,
    Q8,
    F16,
}

impl std::fmt::Display for Quant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Quant::Q4KM => "Q4_K_M",
            Quant::Q5KM => "Q5_K_M",
            Quant::Q8 => "Q8_0",
            Quant::F16 => "F16",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelId(pub String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelSpec {
    pub id: ModelId,
    pub display_name: String,
    pub quant: Quant,
    pub params_billions: f32,
    pub download_bytes: u64,
    pub min_ram_bytes: u64,
    pub blake3_hex: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelRecommendation {
    pub spec: ModelSpec,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quant_display_matches_gguf_naming() {
        assert_eq!(Quant::Q4KM.to_string(), "Q4_K_M");
        assert_eq!(Quant::F16.to_string(), "F16");
    }

    #[test]
    fn model_spec_round_trips_through_json() {
        let spec = ModelSpec {
            id: ModelId("llama-3.1-8b".into()),
            display_name: "Llama 3.1 8B".into(),
            quant: Quant::Q4KM,
            params_billions: 8.0,
            download_bytes: 4_920_000_000,
            min_ram_bytes: 6_000_000_000,
            blake3_hex: "abc123".into(),
            url: "https://example.com/model.gguf".into(),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: ModelSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }
}
```

- [ ] **Step 3: Create `crates/lluma-core/src/hardware.rs`**

```rust
use serde::{Deserialize, Serialize};

/// A snapshot of the machine's resources, used to recommend a model to host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub ram_bytes: u64,
    pub vram_bytes: Option<u64>,
    pub cpu_cores: usize,
    pub disk_free_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_round_trips_through_json() {
        let p = HardwareProfile {
            ram_bytes: 16_000_000_000,
            vram_bytes: Some(8_000_000_000),
            cpu_cores: 8,
            disk_free_bytes: 200_000_000_000,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: HardwareProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
```

- [ ] **Step 4: Create `crates/lluma-core/src/error.rs`**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LlumaError {
    #[error("no model fits this hardware (ram: {ram_bytes} bytes)")]
    NoFittingModel { ram_bytes: u64 },

    #[error("model not found in catalog: {0}")]
    ModelNotFound(String),

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("download failed: {0}")]
    Download(String),

    #[error("inference backend error: {0}")]
    Backend(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, LlumaError>;
```

- [ ] **Step 5: Create `crates/lluma-core/src/lib.rs`**

```rust
//! Shared types and errors for Lluma.
pub mod error;
pub mod hardware;
pub mod model;

pub use error::{LlumaError, Result};
pub use hardware::HardwareProfile;
pub use model::{ModelId, ModelRecommendation, ModelSpec, Quant};
```

- [ ] **Step 6: Run the tests**

Run: `cargo test -p lluma-core`
Expected: PASS (3 tests: `quant_display_matches_gguf_naming`, `model_spec_round_trips_through_json`, `profile_round_trips_through_json`).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(core): shared types (ModelSpec, HardwareProfile, Quant) and errors

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `lluma-runtime` — hardware detection

**Files:**
- Create: `crates/lluma-runtime/Cargo.toml`
- Create: `crates/lluma-runtime/src/lib.rs`
- Create: `crates/lluma-runtime/src/hardware.rs`

**Interfaces:**
- Consumes: `lluma_core::HardwareProfile`.
- Produces: `pub fn detect_hardware() -> HardwareProfile`.

- [ ] **Step 1: Create `crates/lluma-runtime/Cargo.toml`**

```toml
[package]
name = "lluma-runtime"
version = "0.0.0"
edition.workspace = true
license.workspace = true

[dependencies]
lluma-core = { path = "../lluma-core" }
serde = { workspace = true }
thiserror = { workspace = true }
sysinfo = { workspace = true }

[target.'cfg(any(target_os = "windows", target_os = "linux"))'.dependencies]
nvml-wrapper = "0.10"
```

- [ ] **Step 2: Write the failing test**

Create `crates/lluma-runtime/src/hardware.rs`:

```rust
use lluma_core::HardwareProfile;

/// Detect the machine's resources. VRAM is best-effort (NVIDIA via NVML);
/// `None` when it cannot be determined.
pub fn detect_hardware() -> HardwareProfile {
    use sysinfo::{Disks, System};

    let mut sys = System::new_all();
    sys.refresh_memory();

    let ram_bytes = sys.total_memory();
    let cpu_cores = sys.cpus().len().max(1);

    let disks = Disks::new_with_refreshed_list();
    let disk_free_bytes = disks
        .list()
        .iter()
        .map(|d| d.available_space())
        .max()
        .unwrap_or(0);

    let vram_bytes = detect_vram();

    HardwareProfile {
        ram_bytes,
        vram_bytes,
        cpu_cores,
        disk_free_bytes,
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn detect_vram() -> Option<u64> {
    let nvml = nvml_wrapper::Nvml::init().ok()?;
    let device = nvml.device_by_index(0).ok()?;
    let mem = device.memory_info().ok()?;
    Some(mem.total)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn detect_vram() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_plausible_values() {
        let p = detect_hardware();
        assert!(p.ram_bytes > 0, "RAM should be detected");
        assert!(p.cpu_cores >= 1, "at least one core");
    }
}
```

- [ ] **Step 3: Create `crates/lluma-runtime/src/lib.rs`**

```rust
//! Lluma model runtime: hardware detection, recommendation, and GGUF inference.
pub mod hardware;

pub use hardware::detect_hardware;
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p lluma-runtime hardware`
Expected: PASS (`detect_returns_plausible_values`). If NVML is not installed the VRAM path returns `None` — that is fine.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(runtime): hardware detection (RAM/CPU/disk + best-effort NVIDIA VRAM)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: `lluma-runtime` — model recommendation logic

**Files:**
- Create: `crates/lluma-runtime/src/recommend.rs`
- Modify: `crates/lluma-runtime/src/lib.rs` (add `pub mod recommend;`)

**Interfaces:**
- Consumes: `lluma_core::{HardwareProfile, ModelSpec, ModelRecommendation, LlumaError, Result}`.
- Produces:
  - `pub struct DemandSignal { pub undersupplied: Vec<String> }` (model-id strings the network needs).
  - `pub fn recommend(profile: &HardwareProfile, catalog: &[ModelSpec], demand: &DemandSignal) -> Result<ModelRecommendation>`.

**Rule:** a model "fits" when `usable_bytes >= spec.min_ram_bytes`, where `usable_bytes = vram_bytes.unwrap_or(ram_bytes)`. Among fitting models, prefer one whose id is in `demand.undersupplied`; break ties by the largest `params_billions` that still fits (better contribution). If none fit, return `NoFittingModel`.

- [ ] **Step 1: Write the failing test**

Create `crates/lluma-runtime/src/recommend.rs`:

```rust
use lluma_core::{HardwareProfile, LlumaError, ModelRecommendation, ModelSpec, Result};

/// Which models the network currently needs more of.
#[derive(Debug, Clone, Default)]
pub struct DemandSignal {
    pub undersupplied: Vec<String>,
}

/// Recommend the best single model for this machine to host.
pub fn recommend(
    profile: &HardwareProfile,
    catalog: &[ModelSpec],
    demand: &DemandSignal,
) -> Result<ModelRecommendation> {
    let usable = profile.vram_bytes.unwrap_or(profile.ram_bytes);

    let mut fitting: Vec<&ModelSpec> = catalog
        .iter()
        .filter(|s| usable >= s.min_ram_bytes)
        .collect();

    if fitting.is_empty() {
        return Err(LlumaError::NoFittingModel {
            ram_bytes: profile.ram_bytes,
        });
    }

    // Prefer undersupplied models; then the largest that still fits.
    fitting.sort_by(|a, b| {
        let a_needed = demand.undersupplied.contains(&a.id.0);
        let b_needed = demand.undersupplied.contains(&b.id.0);
        b_needed
            .cmp(&a_needed)
            .then(b.params_billions.total_cmp(&a.params_billions))
    });

    let best = fitting[0].clone();
    let needed = demand.undersupplied.contains(&best.id.0);
    let reason = if needed {
        format!(
            "Fits your hardware and the network needs {} right now.",
            best.display_name
        )
    } else {
        format!("Best fit for your hardware ({}).", best.display_name)
    };

    Ok(ModelRecommendation { spec: best, reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lluma_core::{ModelId, Quant};

    fn spec(id: &str, params: f32, min_ram: u64) -> ModelSpec {
        ModelSpec {
            id: ModelId(id.into()),
            display_name: id.into(),
            quant: Quant::Q4KM,
            params_billions: params,
            download_bytes: 1,
            min_ram_bytes: min_ram,
            blake3_hex: "x".into(),
            url: "u".into(),
        }
    }

    fn profile(ram: u64, vram: Option<u64>) -> HardwareProfile {
        HardwareProfile { ram_bytes: ram, vram_bytes: vram, cpu_cores: 8, disk_free_bytes: 1 << 40 }
    }

    #[test]
    fn errors_when_nothing_fits() {
        let cat = vec![spec("big", 70.0, 48_000_000_000)];
        let err = recommend(&profile(8_000_000_000, None), &cat, &DemandSignal::default());
        assert!(matches!(err, Err(LlumaError::NoFittingModel { .. })));
    }

    #[test]
    fn picks_largest_fitting_when_no_demand() {
        let cat = vec![
            spec("small", 3.0, 3_000_000_000),
            spec("mid", 8.0, 6_000_000_000),
        ];
        let rec = recommend(&profile(16_000_000_000, None), &cat, &DemandSignal::default()).unwrap();
        assert_eq!(rec.spec.id.0, "mid");
    }

    #[test]
    fn prefers_undersupplied_model_even_if_smaller() {
        let cat = vec![
            spec("small", 3.0, 3_000_000_000),
            spec("mid", 8.0, 6_000_000_000),
        ];
        let demand = DemandSignal { undersupplied: vec!["small".into()] };
        let rec = recommend(&profile(16_000_000_000, None), &cat, &demand).unwrap();
        assert_eq!(rec.spec.id.0, "small");
        assert!(rec.reason.contains("network needs"));
    }

    #[test]
    fn uses_vram_when_present() {
        // 32GB RAM but only 4GB VRAM => only the small model fits.
        let cat = vec![
            spec("small", 3.0, 3_000_000_000),
            spec("mid", 8.0, 6_000_000_000),
        ];
        let rec = recommend(&profile(32_000_000_000, Some(4_000_000_000)), &cat, &DemandSignal::default()).unwrap();
        assert_eq!(rec.spec.id.0, "small");
    }
}
```

- [ ] **Step 2: Register the module in `lib.rs`**

Modify `crates/lluma-runtime/src/lib.rs` to:

```rust
//! Lluma model runtime: hardware detection, recommendation, and GGUF inference.
pub mod hardware;
pub mod recommend;

pub use hardware::detect_hardware;
pub use recommend::{recommend, DemandSignal};
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p lluma-runtime recommend`
Expected: PASS (4 tests).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(runtime): model recommendation (fit + demand-aware selection)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `lluma-registry` — model catalog + verified download

**Files:**
- Create: `crates/lluma-registry/Cargo.toml`
- Create: `crates/lluma-registry/src/lib.rs`
- Create: `crates/lluma-registry/src/catalog.rs`
- Create: `crates/lluma-registry/src/download.rs`

**Interfaces:**
- Consumes: `lluma_core::{ModelSpec, ModelId, Quant, LlumaError, Result}`; workspace deps `blake3`, `reqwest`, `tokio`.
- Produces:
  - `pub fn builtin_catalog() -> Vec<ModelSpec>`.
  - `pub fn find(catalog: &[ModelSpec], id: &ModelId) -> Result<ModelSpec>`.
  - `pub fn verify_blake3(bytes: &[u8], expected_hex: &str) -> Result<()>`.
  - `pub async fn download_verified(spec: &ModelSpec, dest_dir: &std::path::Path) -> Result<std::path::PathBuf>`.

- [ ] **Step 1: Create `crates/lluma-registry/Cargo.toml`**

```toml
[package]
name = "lluma-registry"
version = "0.0.0"
edition.workspace = true
license.workspace = true

[dependencies]
lluma-core = { path = "../lluma-core" }
blake3 = { workspace = true }
reqwest = { workspace = true }
tokio = { workspace = true }
futures-util = "0.3"

[dev-dependencies]
tokio = { workspace = true }
tempfile = "3"
```

- [ ] **Step 2: Write the failing test for hashing**

Create `crates/lluma-registry/src/download.rs`:

```rust
use futures_util::StreamExt;
use lluma_core::{LlumaError, ModelSpec, Result};
use std::path::{Path, PathBuf};

/// Verify a byte buffer against an expected BLAKE3 hex digest.
pub fn verify_blake3(bytes: &[u8], expected_hex: &str) -> Result<()> {
    let actual = blake3::hash(bytes).to_hex().to_string();
    if actual == expected_hex {
        Ok(())
    } else {
        Err(LlumaError::HashMismatch {
            expected: expected_hex.to_string(),
            actual,
        })
    }
}

/// Download a model to `dest_dir`, verify its BLAKE3 hash, and return the path.
/// The file is only written to its final name after verification passes.
pub async fn download_verified(spec: &ModelSpec, dest_dir: &Path) -> Result<PathBuf> {
    tokio::fs::create_dir_all(dest_dir).await?;
    let final_path = dest_dir.join(format!("{}-{}.gguf", spec.id.0, spec.quant));

    let resp = reqwest::get(&spec.url)
        .await
        .map_err(|e| LlumaError::Download(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(LlumaError::Download(format!("http status {}", resp.status())));
    }

    let mut hasher = blake3::Hasher::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| LlumaError::Download(e.to_string()))?;
        hasher.update(&chunk);
        buf.extend_from_slice(&chunk);
    }

    let actual = hasher.finalize().to_hex().to_string();
    if actual != spec.blake3_hex {
        return Err(LlumaError::HashMismatch {
            expected: spec.blake3_hex.clone(),
            actual,
        });
    }

    tokio::fs::write(&final_path, &buf).await?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_correct_hash() {
        let data = b"hello lluma";
        let hex = blake3::hash(data).to_hex().to_string();
        assert!(verify_blake3(data, &hex).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_hash() {
        let err = verify_blake3(b"hello lluma", "deadbeef");
        assert!(matches!(err, Err(LlumaError::HashMismatch { .. })));
    }
}
```

- [ ] **Step 3: Create `crates/lluma-registry/src/catalog.rs`**

```rust
use lluma_core::{LlumaError, ModelId, ModelSpec, Quant, Result};

/// A small built-in catalog of models to host. In later phases this is fetched
/// from the network registry; for Phase 0 it is a static list.
///
/// NOTE: `blake3_hex` and `url` must be filled with real values before shipping.
/// The values here are placeholders that will fail verification by design until
/// a maintainer pins a real GGUF (see docs/architecture/model-catalog.md, Phase 2).
pub fn builtin_catalog() -> Vec<ModelSpec> {
    vec![
        ModelSpec {
            id: ModelId("qwen2.5-0.5b-instruct".into()),
            display_name: "Qwen2.5 0.5B Instruct".into(),
            quant: Quant::Q4KM,
            params_billions: 0.5,
            download_bytes: 400_000_000,
            min_ram_bytes: 1_500_000_000,
            blake3_hex: String::new(),
            url: String::new(),
        },
        ModelSpec {
            id: ModelId("llama-3.1-8b-instruct".into()),
            display_name: "Llama 3.1 8B Instruct".into(),
            quant: Quant::Q4KM,
            params_billions: 8.0,
            download_bytes: 4_920_000_000,
            min_ram_bytes: 6_500_000_000,
            blake3_hex: String::new(),
            url: String::new(),
        },
    ]
}

/// Find a model in a catalog by id.
pub fn find(catalog: &[ModelSpec], id: &ModelId) -> Result<ModelSpec> {
    catalog
        .iter()
        .find(|s| &s.id == id)
        .cloned()
        .ok_or_else(|| LlumaError::ModelNotFound(id.0.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_is_nonempty_and_findable() {
        let cat = builtin_catalog();
        assert!(!cat.is_empty());
        let id = cat[0].id.clone();
        assert_eq!(find(&cat, &id).unwrap().id, id);
    }

    #[test]
    fn find_missing_errors() {
        let cat = builtin_catalog();
        let err = find(&cat, &ModelId("nope".into()));
        assert!(matches!(err, Err(LlumaError::ModelNotFound(_))));
    }
}
```

- [ ] **Step 4: Create `crates/lluma-registry/src/lib.rs`**

```rust
//! Lluma model registry: catalog lookup and content-addressed verified download.
pub mod catalog;
pub mod download;

pub use catalog::{builtin_catalog, find};
pub use download::{download_verified, verify_blake3};
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p lluma-registry`
Expected: PASS (4 tests: two hashing, two catalog).

- [ ] **Step 6: Add `lluma-registry` to workspace members**

Confirm `crates/lluma-registry` is already listed in the root `Cargo.toml` members (it was added in Task 1). If not, add it and re-run `cargo test -p lluma-registry`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(registry): built-in catalog + BLAKE3-verified model download

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `lluma-runtime` — `ModelRunner` trait, llama.cpp backend, and mock

**Files:**
- Modify: `crates/lluma-runtime/Cargo.toml` (add `llama-cpp-2`, `encoding_rs`)
- Create: `crates/lluma-runtime/src/runner.rs`
- Modify: `crates/lluma-runtime/src/lib.rs` (add `pub mod runner;`)

**Interfaces:**
- Consumes: `lluma_core::{LlumaError, Result}`.
- Produces:
  - `pub struct GenerateRequest { pub prompt: String, pub max_tokens: usize }`.
  - `pub trait ModelRunner { fn generate(&mut self, req: &GenerateRequest, on_token: &mut dyn FnMut(&str)) -> Result<String>; }` — calls `on_token` for each decoded piece and returns the full output.
  - `pub struct MockRunner { pub script: Vec<String> }` implementing `ModelRunner` (emits scripted pieces; for tests/consumers).
  - `pub struct LlamaRunner` with `pub fn load(model_path: &std::path::Path, n_ctx: u32) -> Result<Self>` implementing `ModelRunner`.

- [ ] **Step 1: Add dependencies to `crates/lluma-runtime/Cargo.toml`**

Add to `[dependencies]`:

```toml
llama-cpp-2 = "0.1"
encoding_rs = "0.8"
```

- [ ] **Step 2: Write the failing test using `MockRunner`**

Create `crates/lluma-runtime/src/runner.rs`:

```rust
use lluma_core::{LlumaError, Result};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct GenerateRequest {
    pub prompt: String,
    pub max_tokens: usize,
}

/// A model that can stream a completion. `on_token` is invoked with each decoded
/// text piece as it is produced; the full concatenated output is also returned.
pub trait ModelRunner {
    fn generate(&mut self, req: &GenerateRequest, on_token: &mut dyn FnMut(&str)) -> Result<String>;
}

/// A deterministic runner for tests and for wiring consumers before a real model
/// is available. Emits each string in `script` as one "token".
pub struct MockRunner {
    pub script: Vec<String>,
}

impl ModelRunner for MockRunner {
    fn generate(&mut self, req: &GenerateRequest, on_token: &mut dyn FnMut(&str)) -> Result<String> {
        let mut out = String::new();
        for piece in self.script.iter().take(req.max_tokens.max(1)) {
            on_token(piece);
            out.push_str(piece);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_runner_streams_and_returns_full_output() {
        let mut runner = MockRunner {
            script: vec!["Hel".into(), "lo".into(), "!".into()],
        };
        let mut streamed = String::new();
        let full = runner
            .generate(
                &GenerateRequest { prompt: "hi".into(), max_tokens: 10 },
                &mut |t| streamed.push_str(t),
            )
            .unwrap();
        assert_eq!(full, "Hello!");
        assert_eq!(streamed, "Hello!");
    }

    #[test]
    fn mock_runner_respects_max_tokens() {
        let mut runner = MockRunner { script: vec!["a".into(), "b".into(), "c".into()] };
        let full = runner
            .generate(&GenerateRequest { prompt: "x".into(), max_tokens: 2 }, &mut |_| {})
            .unwrap();
        assert_eq!(full, "ab");
    }
}
```

- [ ] **Step 3: Run the mock tests (they should pass without the llama backend yet)**

Run: `cargo test -p lluma-runtime runner`
Expected: PASS (2 mock tests).

- [ ] **Step 4: Add the `LlamaRunner` real backend**

Append to `crates/lluma-runtime/src/runner.rs` (above the `#[cfg(test)]` module):

```rust
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;
use std::num::NonZeroU32;
use std::sync::Arc;

/// A real llama.cpp-backed runner loaded from a GGUF file.
pub struct LlamaRunner {
    backend: Arc<LlamaBackend>,
    model: LlamaModel,
    n_ctx: u32,
}

impl LlamaRunner {
    /// Load a GGUF model. `n_ctx` is the context window (e.g. 4096).
    pub fn load(model_path: &Path, n_ctx: u32) -> Result<Self> {
        let backend =
            LlamaBackend::init().map_err(|e| LlumaError::Backend(format!("backend init: {e}")))?;
        let model = LlamaModel::load_from_file(&backend, model_path, &LlamaModelParams::default())
            .map_err(|e| LlumaError::Backend(format!("load model: {e}")))?;
        Ok(Self { backend: Arc::new(backend), model, n_ctx })
    }
}

impl ModelRunner for LlamaRunner {
    fn generate(&mut self, req: &GenerateRequest, on_token: &mut dyn FnMut(&str)) -> Result<String> {
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(self.n_ctx));
        let mut ctx = self
            .model
            .new_context(&self.backend, ctx_params)
            .map_err(|e| LlumaError::Backend(format!("new context: {e}")))?;

        let tokens = self
            .model
            .str_to_token(&req.prompt, AddBos::Always)
            .map_err(|e| LlumaError::Backend(format!("tokenize: {e}")))?;

        let mut batch = LlamaBatch::new(512, 1);
        let last = tokens.len().saturating_sub(1);
        for (i, tok) in tokens.iter().enumerate() {
            batch
                .add(*tok, i as i32, &[0], i == last)
                .map_err(|e| LlumaError::Backend(format!("batch add: {e}")))?;
        }
        ctx.decode(&mut batch)
            .map_err(|e| LlumaError::Backend(format!("decode: {e}")))?;

        let mut sampler = LlamaSampler::chain_simple([
            LlamaSampler::top_p(0.9, 1),
            LlamaSampler::temp(0.7),
            LlamaSampler::dist(1234),
        ]);

        let mut out = String::new();
        let mut n_cur = tokens.len() as i32;
        let mut decoder = encoding_rs::UTF_8.new_decoder();

        for _ in 0..req.max_tokens {
            let next = sampler.sample(&ctx, batch.n_tokens() - 1);
            sampler.accept(next);
            if next == self.model.token_eos() {
                break;
            }
            let piece = self
                .model
                .token_to_piece(next, &mut decoder, false)
                .map_err(|e| LlumaError::Backend(format!("detokenize: {e}")))?;
            on_token(&piece);
            out.push_str(&piece);

            batch.clear();
            batch
                .add(next, n_cur, &[0], true)
                .map_err(|e| LlumaError::Backend(format!("batch add: {e}")))?;
            n_cur += 1;
            ctx.decode(&mut batch)
                .map_err(|e| LlumaError::Backend(format!("decode: {e}")))?;
        }

        Ok(out)
    }
}
```

> **Implementer note:** `llama-cpp-2` occasionally revises method signatures (`with_n_ctx`, `token_to_piece`, `LlamaSampler` constructors). Before running, confirm the exact signatures for the pinned `0.1.x` version via Context7 (`/utilityai/llama-cpp-rs`) or `cargo doc -p llama-cpp-2 --open`, and adjust the three call sites (`with_n_ctx`, sampler chain, `token_to_piece`) if the compiler flags a mismatch. The control flow (tokenize → prime batch → decode → sample loop → detokenize) is correct and version-stable.

- [ ] **Step 5: Register the module in `lib.rs`**

Modify `crates/lluma-runtime/src/lib.rs` to:

```rust
//! Lluma model runtime: hardware detection, recommendation, and GGUF inference.
pub mod hardware;
pub mod recommend;
pub mod runner;

pub use hardware::detect_hardware;
pub use recommend::{recommend, DemandSignal};
pub use runner::{GenerateRequest, LlamaRunner, MockRunner, ModelRunner};
```

- [ ] **Step 6: Add a gated integration test for the real backend**

Create `crates/lluma-runtime/tests/llama_integration.rs`:

```rust
//! Runs only when LLUMA_TEST_GGUF points to a real small GGUF file.
//! Example (PowerShell): $env:LLUMA_TEST_GGUF="C:\models\qwen0.5b.gguf"; cargo test -p lluma-runtime --test llama_integration -- --nocapture
use lluma_runtime::{GenerateRequest, LlamaRunner, ModelRunner};

#[test]
fn generates_tokens_from_a_real_model() {
    let Ok(path) = std::env::var("LLUMA_TEST_GGUF") else {
        eprintln!("skipping: set LLUMA_TEST_GGUF to a GGUF path to run this test");
        return;
    };
    let mut runner = LlamaRunner::load(std::path::Path::new(&path), 2048)
        .expect("load model");
    let mut streamed = String::new();
    let out = runner
        .generate(
            &GenerateRequest { prompt: "The capital of France is".into(), max_tokens: 16 },
            &mut |t| streamed.push_str(t),
        )
        .expect("generate");
    assert!(!out.is_empty(), "model should produce output");
    assert_eq!(out, streamed, "streamed and returned output must match");
}
```

- [ ] **Step 7: Build and run the non-gated tests**

Run: `cargo test -p lluma-runtime`
Expected: PASS. The mock/recommend/hardware tests pass; the integration test prints "skipping" and passes unless `LLUMA_TEST_GGUF` is set. Fix any compile errors in `LlamaRunner` per the implementer note before proceeding.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(runtime): ModelRunner trait, MockRunner, and llama.cpp GGUF backend

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: `lluma-desktop` — Tauri app (Contribute + Chat, streaming)

**Files:**
- Create: `apps/lluma-desktop/src-tauri/Cargo.toml`
- Create: `apps/lluma-desktop/src-tauri/tauri.conf.json`
- Create: `apps/lluma-desktop/src-tauri/build.rs`
- Create: `apps/lluma-desktop/src-tauri/src/main.rs`
- Create: `apps/lluma-desktop/src-tauri/src/lib.rs`
- Create: `apps/lluma-desktop/dist/index.html`
- Create: `apps/lluma-desktop/dist/main.js`
- Create: `apps/lluma-desktop/dist/styles.css`
- Modify: root `Cargo.toml` (do **not** add the Tauri app to the workspace; it has its own target dir — see Step 1 note)

**Interfaces:**
- Consumes: `lluma_core`, `lluma_runtime`, `lluma_registry` as path dependencies.
- Produces: a runnable desktop app with commands `detect_hardware`, `recommend_model`, `start_generate`; and a `token`/`done`/`error` event stream.

> **Workspace note:** Tauri apps are kept out of the root workspace to avoid feature-unification and build-dir conflicts. Add `apps/lluma-desktop/src-tauri` as its own crate with `[workspace]` empty table at the bottom of its `Cargo.toml` so cargo treats it as standalone.

- [ ] **Step 1: Create `apps/lluma-desktop/src-tauri/Cargo.toml`**

```toml
[package]
name = "lluma-desktop"
version = "0.0.0"
edition = "2021"
license = "Apache-2.0"

[lib]
name = "lluma_desktop_lib"
crate-type = ["staticlib", "cdylib", "rlib"]

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
tauri = { version = "2", features = [] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
lluma-core = { path = "../../../crates/lluma-core" }
lluma-runtime = { path = "../../../crates/lluma-runtime" }
lluma-registry = { path = "../../../crates/lluma-registry" }

# Standalone: not part of the root workspace.
[workspace]
```

- [ ] **Step 2: Create `apps/lluma-desktop/src-tauri/build.rs`**

```rust
fn main() {
    tauri_build::build()
}
```

- [ ] **Step 3: Create `apps/lluma-desktop/src-tauri/tauri.conf.json`**

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "Lluma",
  "version": "0.0.0",
  "identifier": "ai.bodegga.lluma",
  "build": {
    "frontendDist": "../dist"
  },
  "app": {
    "windows": [
      {
        "title": "Lluma",
        "width": 980,
        "height": 720,
        "resizable": true
      }
    ],
    "security": {
      "csp": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
    }
  },
  "bundle": {
    "active": true,
    "targets": "all",
    "icon": ["icons/icon.png"]
  }
}
```

> Provide a placeholder `icons/icon.png` (any 512×512 PNG). `cargo tauri icon path/to/logo.png` can generate the full set later.

- [ ] **Step 4: Create the Rust command layer `apps/lluma-desktop/src-tauri/src/lib.rs`**

```rust
use lluma_core::{HardwareProfile, ModelRecommendation};
use lluma_registry::builtin_catalog;
use lluma_runtime::{
    detect_hardware, recommend, DemandSignal, GenerateRequest, MockRunner, ModelRunner,
};
use serde::Serialize;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager};

/// App-wide state. In Phase 0 we keep it minimal; a loaded LlamaRunner will live
/// here in a later step once model download is wired end-to-end.
#[derive(Default)]
struct AppState {
    last_profile: Mutex<Option<HardwareProfile>>,
}

#[derive(Serialize)]
struct TokenEvent {
    text: String,
}

#[tauri::command]
fn detect_hardware_cmd(state: tauri::State<AppState>) -> HardwareProfile {
    let profile = detect_hardware();
    *state.last_profile.lock().unwrap() = Some(profile);
    profile
}

#[tauri::command]
fn recommend_model_cmd() -> std::result::Result<ModelRecommendation, String> {
    let profile = detect_hardware();
    let catalog = builtin_catalog();
    recommend(&profile, &catalog, &DemandSignal::default()).map_err(|e| e.to_string())
}

/// Start generation and stream tokens to the frontend via events.
/// Phase 0 uses MockRunner so the full UI loop is testable before a model is
/// downloaded; swapping in `LlamaRunner::load(...)` is a one-line change once a
/// verified GGUF exists on disk.
#[tauri::command]
fn start_generate(app: AppHandle, prompt: String) {
    std::thread::spawn(move || {
        let mut runner = MockRunner {
            script: vec![
                "Lluma ".into(),
                "is ".into(),
                "running ".into(),
                "locally. ".into(),
                "(prompt: ".into(),
                prompt.clone(),
                ")".into(),
            ],
        };
        let req = GenerateRequest { prompt, max_tokens: 256 };
        let result = runner.generate(&req, &mut |piece| {
            let _ = app.emit("token", TokenEvent { text: piece.to_string() });
        });
        match result {
            Ok(_) => {
                let _ = app.emit("done", ());
            }
            Err(e) => {
                let _ = app.emit("error", e.to_string());
            }
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            detect_hardware_cmd,
            recommend_model_cmd,
            start_generate
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lluma");
}
```

- [ ] **Step 5: Create `apps/lluma-desktop/src-tauri/src/main.rs`**

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    lluma_desktop_lib::run()
}
```

- [ ] **Step 6: Create the frontend `apps/lluma-desktop/dist/index.html`**

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Lluma</title>
    <link rel="stylesheet" href="styles.css" />
  </head>
  <body>
    <header>
      <h1>Lluma</h1>
      <nav>
        <button id="tab-contribute" class="tab active">Contribute</button>
        <button id="tab-chat" class="tab">Chat</button>
      </nav>
    </header>

    <main>
      <section id="panel-contribute" class="panel">
        <h2>Contribute compute</h2>
        <p id="hw"></p>
        <p id="rec"></p>
        <button id="btn-detect">Detect my hardware</button>
        <button id="btn-recommend">Recommend a model</button>
      </section>

      <section id="panel-chat" class="panel hidden">
        <h2>Chat</h2>
        <div id="output" aria-live="polite"></div>
        <form id="chat-form">
          <input id="prompt" type="text" placeholder="Ask anything…" autocomplete="off" />
          <button type="submit">Send</button>
        </form>
      </section>
    </main>

    <script type="module" src="main.js"></script>
  </body>
</html>
```

- [ ] **Step 7: Create the frontend logic `apps/lluma-desktop/dist/main.js`**

```javascript
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

function showTab(name) {
  document.getElementById("panel-contribute").classList.toggle("hidden", name !== "contribute");
  document.getElementById("panel-chat").classList.toggle("hidden", name !== "chat");
  document.getElementById("tab-contribute").classList.toggle("active", name === "contribute");
  document.getElementById("tab-chat").classList.toggle("active", name === "chat");
}
document.getElementById("tab-contribute").onclick = () => showTab("contribute");
document.getElementById("tab-chat").onclick = () => showTab("chat");

function fmtGB(bytes) {
  return (bytes / 1e9).toFixed(1) + " GB";
}

document.getElementById("btn-detect").onclick = async () => {
  const hw = await invoke("detect_hardware_cmd");
  const vram = hw.vram_bytes ? fmtGB(hw.vram_bytes) : "n/a";
  document.getElementById("hw").textContent =
    `RAM ${fmtGB(hw.ram_bytes)} · VRAM ${vram} · ${hw.cpu_cores} cores · disk free ${fmtGB(hw.disk_free_bytes)}`;
};

document.getElementById("btn-recommend").onclick = async () => {
  try {
    const rec = await invoke("recommend_model_cmd");
    document.getElementById("rec").textContent =
      `Recommended: ${rec.spec.display_name} (${rec.spec.quant}) — ${rec.reason}`;
  } catch (e) {
    document.getElementById("rec").textContent = `No recommendation: ${e}`;
  }
};

const output = document.getElementById("output");
await listen("token", (e) => { output.textContent += e.payload.text; });
await listen("done", () => { output.textContent += "\n"; });
await listen("error", (e) => { output.textContent += `\n[error] ${e.payload}\n`; });

document.getElementById("chat-form").onsubmit = async (ev) => {
  ev.preventDefault();
  const input = document.getElementById("prompt");
  const prompt = input.value.trim();
  if (!prompt) return;
  output.textContent += `\n> ${prompt}\n`;
  input.value = "";
  await invoke("start_generate", { prompt });
};
```

- [ ] **Step 8: Create `apps/lluma-desktop/dist/styles.css`**

```css
:root { font-family: system-ui, sans-serif; color-scheme: light dark; }
body { margin: 0; padding: 0; }
header { padding: 1rem 1.5rem; border-bottom: 1px solid #8883; }
header h1 { margin: 0 0 .5rem; font-size: 1.4rem; letter-spacing: .02em; }
nav .tab { background: none; border: none; padding: .5rem .75rem; cursor: pointer; font-size: 1rem; opacity: .6; }
nav .tab.active { opacity: 1; border-bottom: 2px solid currentColor; }
main { padding: 1.5rem; }
.panel.hidden { display: none; }
#output { white-space: pre-wrap; min-height: 12rem; border: 1px solid #8884; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
#chat-form { display: flex; gap: .5rem; }
#prompt { flex: 1; padding: .6rem; border-radius: 8px; border: 1px solid #8886; }
button[type="submit"], #btn-detect, #btn-recommend { padding: .6rem 1rem; border-radius: 8px; border: 1px solid #8886; cursor: pointer; }
```

- [ ] **Step 9: Verify the app builds**

Run: `cd apps/lluma-desktop/src-tauri && cargo build`
Expected: compiles. (Requires the Tauri CLI and system webview; on Windows, WebView2 is present by default on Win11.)

- [ ] **Step 10: Run the app and manually verify the loop**

Run: `cd apps/lluma-desktop && cargo tauri dev`
Expected:
1. Window titled "Lluma" opens on the Contribute tab.
2. "Detect my hardware" shows RAM/VRAM/cores/disk.
3. "Recommend a model" shows a recommendation from the catalog (or a clear "No recommendation" message if nothing fits).
4. On the Chat tab, typing a prompt and pressing Send streams the mock tokens into the output area, then a newline on `done`.

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "feat(desktop): Tauri app with Contribute + Chat tabs and streaming generation

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage (Phase 0 scope):**
- Point-and-click app → Task 7. ✓
- Auto hardware detection → Task 3 + Task 7 command. ✓
- Auto model recommendation (fit + demand) → Task 4 + Task 7 command. ✓
- Bundled GGUF runtime via llama.cpp → Task 6. ✓
- Content-addressed (BLAKE3) verified model download → Task 5. ✓
- Repo scaffold + agents files + README + AGENTS.md + CLAUDE.md → Task 1. ✓
- Fable-for-reasoning / small-models-for-work strategy → encoded in Task 1 agent files. ✓
- Deferred to later phases (correctly absent here): relay, broker, issuer, blind tokens, credits, P2P seeding, TEE tier. These belong to the Phase 1+ plans.

**2. Placeholder scan:** The only intentional empty values are `blake3_hex`/`url` in `builtin_catalog()` (Task 5), which are documented as maintainer-pinned before shipping and fail safely (hash mismatch) until then. No "TODO/implement later" in code steps. The `LlamaRunner` implementer note points to a verification action, not a placeholder — full code is present.

**3. Type consistency:** `HardwareProfile`, `ModelSpec`, `ModelRecommendation`, `Quant`, `ModelId`, `LlumaError` defined in Task 2 are used with identical field names/signatures in Tasks 3–7. `ModelRunner::generate(&mut self, &GenerateRequest, &mut dyn FnMut(&str)) -> Result<String>` is defined in Task 6 and consumed identically in Task 7. `detect_hardware`, `recommend`, `DemandSignal`, `builtin_catalog` names match across producing and consuming tasks.

**Note carried to execution:** Task 6 Step 4 depends on the exact `llama-cpp-2 0.1.x` API; the implementer note directs verifying `with_n_ctx`, the `LlamaSampler` chain, and `token_to_piece` signatures via Context7 before the build step. This is the one place the code may need a small signature adjustment.
