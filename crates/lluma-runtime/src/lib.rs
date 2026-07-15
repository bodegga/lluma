#![allow(linker_messages, unused_attributes)]
//! Lluma model runtime: hardware detection, recommendation, and GGUF inference.
pub mod hardware;
pub mod recommend;
pub mod runner;

pub use hardware::detect_hardware;
pub use recommend::{recommend, DemandSignal};
pub use runner::{GenerateRequest, LlamaRunner, MockRunner, ModelRunner};
