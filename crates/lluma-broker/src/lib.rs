//! `lluma-broker` — Phase 1 #4: matchmaking + accounting.
//!
//! This crate currently ships the **durable accounting core**: a pure-Rust redb
//! store backing `RedbLedger` and `RedbSpentSet`, which implement the #2
//! `CreditLedger`/`SpentSet` trait seams with durability that closes the
//! restart-respend hole demonstrated by #2's in-memory spent-set. Registry,
//! signed snapshots, receipt ingest, and the redeem-forward service are the
//! remaining #4 work (see the design spec).

pub mod config;
pub mod counters;
pub mod error;
pub mod hosts;
pub mod ledger;
pub mod receipts;
pub mod registry;
pub mod service;
pub mod snapshot;
pub mod spent;
pub mod store;
pub mod trial;

pub use config::BrokerConfig;
pub use error::BrokerError;
pub use hosts::{HostEntry, StaticHostDirectory};
pub use ledger::RedbLedger;
pub use receipts::{ingest, IngestOutcome};
pub use registry::{heartbeat, register, HeartbeatOutcome, RegisterOutcome};
pub use spent::RedbSpentSet;
pub use service::{router, BrokerState};
pub use snapshot::{publish as publish_snapshot, verify as verify_snapshot, SNAPSHOT_BUCKET};
pub use store::Store;
pub use trial::{grant_trial, TrialOutcome};
