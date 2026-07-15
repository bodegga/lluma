//! Lluma model runtime: hardware detection, recommendation, and GGUF inference.
pub mod hardware;

pub use hardware::detect_hardware;
