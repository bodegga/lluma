use thiserror::Error;

#[derive(Debug, Error)]
pub enum LlumaError {
    #[error("no model fits this hardware (ram: {ram_bytes} bytes)")]
    NoFittingModel { ram_bytes: u64 },

    #[error("model not found in catalog: {0}")]
    ModelNotFound(String),

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("download failed: {0}")]
    Download(String),

    #[error("inference backend error: {0}")]
    Backend(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, LlumaError>;
