//! Shared types and errors for Lluma.
pub mod error;
pub mod hardware;
pub mod model;

pub use error::{LlumaError, Result};
pub use hardware::HardwareProfile;
pub use model::{ModelId, ModelRecommendation, ModelSpec, Quant};
