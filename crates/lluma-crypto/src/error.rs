use thiserror::Error;

/// Errors from `lluma-crypto`. No variant embeds plaintext or secret bytes.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("token verification failed")]
    TokenInvalid,
    #[error("blind-signature operation failed: {0}")]
    Blind(String),
    #[error("OHTTP encapsulation error: {0}")]
    Ohttp(String),
    #[error("HPKE seal/open error: {0}")]
    Hpke(String),
    #[error("stream truncated: final chunk missing")]
    Truncated,
    #[error("stream chunk out of order or replayed")]
    ChunkOrder,
    #[error("AEAD authentication failed (wrong key, tamper, or wrong passphrase)")]
    AuthFailed,
    #[error("signature verification failed")]
    BadSignature,
    #[error("key derivation failed: {0}")]
    Derivation(String),
    #[error("encoding error: {0}")]
    Encoding(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
