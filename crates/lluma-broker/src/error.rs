//! Broker errors. L8-safe: variants are opaque — they never carry a redb/IO
//! `Display` (which could name paths) or wire bytes to a caller or the wire.

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("storage error")]
    Storage,
    /// A snapshot's encoded size exceeds the fixed bucket — fail closed + alarm
    /// (never silently grow the bucket, which would leak host count, L4).
    #[error("snapshot too large")]
    SnapshotTooLarge,
    /// A snapshot failed signature/length/decoding checks on the client side.
    #[error("snapshot invalid")]
    SnapshotInvalid,
}
