//! `lluma-net` — the client side of Lluma's anonymous transport (Phase 1 #3).
//!
//! Verifies a signed bootstrap (relay URLs + gateway OHTTP key-config), frames
//! an inner HTTP request as RFC 9292 BHTTP, OHTTP-encapsulates it to the gateway
//! key, and round-trips it through a relay — so the relay learns the client's IP
//! but never the content, and the gateway learns the content but never the IP.

mod agent;
mod bootstrap;
mod error;
mod framing;

pub use agent::OhttpAgent;
pub use bootstrap::{sign_bootstrap, verify_bootstrap, Bootstrap};
pub use error::NetError;
pub use framing::{InnerRequest, InnerResponse};
