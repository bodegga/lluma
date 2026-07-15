//! Lluma model registry: catalog lookup and content-addressed verified download.
pub mod catalog;
pub mod download;

pub use catalog::{builtin_catalog, find};
pub use download::{download_verified, verify_blake3};
