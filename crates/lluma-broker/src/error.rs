//! Broker errors. L8-safe: `Storage` is opaque — it never carries a redb/IO
//! `Display` (which could name paths) to a caller or the wire.

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("storage error")]
    Storage,
}
