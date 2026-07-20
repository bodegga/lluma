//! `lluma-issuer` — the token-issuance loop service crate.
//!
//! This crate (Phase 1 #2) builds the axum HTTP service that blind-signs
//! entitlement tokens while debiting a credit balance, and redeems tokens with
//! double-spend protection. Tasks 2–6 here build the crate scaffold + in-memory
//! state layer; HTTP handlers land in Task 7+.

pub mod error;
pub mod idem;
pub mod keys;
pub mod ledger;
pub mod service;
pub mod spent_set;

#[cfg(feature = "client")]
pub mod client;

pub use error::IssuerError;