//! Typed transport errors. No variant embeds capsule/token/plaintext bytes or
//! an inner crypto/reqwest `Display` (leak L8) — static messages only.

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("bootstrap verification failed")]
    Bootstrap,
    #[error("OHTTP encapsulation failed")]
    Encapsulation,
    #[error("relay returned status {0}")]
    Relay(u16),
    #[error("response not final (truncated)")]
    NotFinal,
    #[error("BHTTP encode/decode failed")]
    Bhttp,
    #[error("http transport failed")]
    Http,
    #[error("crypto error")]
    Crypto,
}

impl From<lluma_crypto::CryptoError> for NetError {
    fn from(_: lluma_crypto::CryptoError) -> Self {
        NetError::Crypto
    }
}
