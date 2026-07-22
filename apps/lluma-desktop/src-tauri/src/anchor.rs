//! Compiled-in trust anchor. The official release build bakes the network's
//! registry public key via `LLUMA_REGISTRY_PK_B64` at build time; that pinned
//! key verifies both the signed bootstrap and the host snapshot, so the app can
//! self-configure over an untrusted relay without anyone being able to
//! substitute the gateway key. A plain `cargo build` (no env var) ships no
//! anchor → auto-connect is disabled and the manual (Advanced) flow is used.

use base64::Engine;
use lluma_core::wire::AccountPublicKey;

/// The base64 registry public key baked in at build time, if any.
const PINNED_REGISTRY_PK_B64: Option<&str> = option_env!("LLUMA_REGISTRY_PK_B64");

/// The pinned registry public key, or `None` for a dev/self-host build.
pub fn pinned_registry_pk() -> Option<AccountPublicKey> {
    let b64 = PINNED_REGISTRY_PK_B64?.trim();
    if b64.is_empty() {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(AccountPublicKey(bytes))
}

/// Whether this build has a pinned anchor (auto-connect available).
pub fn has_anchor() -> bool {
    pinned_registry_pk().is_some()
}
