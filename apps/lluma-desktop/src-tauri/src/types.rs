//! Serde DTOs shared across the command layer and the frontend.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamKind {
    #[default]
    OpenAi,
    Echo,
    Local,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostConfig {
    pub upstream: UpstreamKind,
    /// Public address the broker forwards sealed prompts to, e.g.
    /// `http://203.0.113.9:9000`. Must be reachable from the internet.
    pub ingress_addr: String,
    pub openai_base: String,
    pub openai_model: String,
    pub openai_api_key: String,
    /// Broker ingress URL for register/heartbeat (operator-provided; direct,
    /// not via the relay). Empty ⇒ serve-only mode (won't receive broker work).
    pub broker_ingress: String,
    /// Broker epoch salt (base64) needed to solve the registration PoW. Not
    /// yet published; operator-provided today.
    pub epoch_salt_b64: String,
    /// Registration PoW difficulty in leading zero bits (broker policy).
    pub pow_difficulty: u32,
    /// Model label this host advertises in the registry (non-empty required).
    pub model_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub relay_url: String,
    pub gateway_kc_b64: String,
    pub registry_pk_b64: String,
    pub issuer_key_id_hex: String,
    pub host: HostConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkStatus {
    pub reachable: bool,
    pub epoch: u64,
    pub denomination: u64,
    pub latency_ms: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountStatus {
    pub has_account: bool,
    pub unlocked: bool,
    pub account_id_hex: String,
    pub balance: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostStatus {
    pub running: bool,
    pub reachable: bool,
    /// "stopped" | "registering" | "admitting" | "active"
    pub state: String,
    pub credits_earned: u64,
    pub requests_served: u64,
    pub message: String,
}

impl Default for HostStatus {
    fn default() -> Self {
        HostStatus {
            running: false,
            reachable: false,
            state: "stopped".into(),
            credits_earned: 0,
            requests_served: 0,
            message: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatReply {
    pub answer: String,
    pub spent: usize,
    pub balance: usize,
}

/// Returned once, on account creation/import, so the UI can show the recovery
/// phrase for the user to write down. Never persisted in the clear.
#[derive(Debug, Clone, Serialize)]
pub struct NewAccount {
    pub account_id_hex: String,
    pub recovery_phrase: String,
}

/// Endpoint material published by the relay bootstrap (all base64/hex strings).
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapDoc {
    #[serde(default)]
    pub gateway_kc_b64: String,
    #[serde(default)]
    pub registry_pk_b64: String,
    #[serde(default)]
    pub issuer_key_id_hex: String,
}
