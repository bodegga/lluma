//! Lluma's cryptographic trust foundation: blind entitlement tokens, Oblivious
//! HTTP + HPKE encapsulation, ephemeral sessions, account identity, signed
//! usage receipts, and self-custodial key backup. Pure functions only — no I/O,
//! no network, no global state. See docs/architecture/adr-0001-lluma-crypto-primitives.md.
pub mod error;

pub use error::{CryptoError, Result};
