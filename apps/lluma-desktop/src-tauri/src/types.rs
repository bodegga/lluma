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
    pub ingress_addr: String,
    pub openai_base: String,
    pub openai_model: String,
    pub openai_api_key: String,
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
