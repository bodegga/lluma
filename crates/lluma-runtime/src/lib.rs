//! Lluma model runtime: hardware detection, recommendation, and GGUF inference.
pub mod hardware;
pub mod recommend;

pub use hardware::detect_hardware;
pub use recommend::{recommend, DemandSignal};
