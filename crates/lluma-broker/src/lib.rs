//! `lluma-broker` — Phase 1 #4: matchmaking + accounting.
//!
//! This crate currently ships the **durable accounting core**: a pure-Rust redb
//! store backing `RedbLedger` and `RedbSpentSet`, which implement the #2
//! `CreditLedger`/`SpentSet` trait seams with durability that closes the
//! restart-respend hole demonstrated by #2's in-memory spent-set. Registry,
//! signed snapshots, receipt ingest, and the redeem-forward service are the
//! remaining #4 work (see the design spec).

pub mod error;
pub mod ledger;
pub mod spent;
pub mod store;

pub use error::BrokerError;
pub use ledger::RedbLedger;
pub use spent::RedbSpentSet;
pub use store::Store;
