//! `lluma-issuer` — the token-issuance loop service crate.
//!
//! This crate (Phase 1 #2) builds the axum HTTP service that blind-signs
//! entitlement tokens while debiting a credit balance, and redeems tokens with
//! double-spend protection. Tasks 2–6 here build the crate scaffold + in-memory
//! state layer; HTTP handlers land in Task 7+.

pub mod error;
pub mod ledger;
pub mod spent_set;

pub use error::IssuerError;