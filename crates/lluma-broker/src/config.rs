//! Broker configuration knobs (Fable-ruled defaults, spec §"Security defaults").
//! Every value here is a policy knob, not a wire constant.

/// Runtime policy for registry admission, anti-Sybil, receipts, and snapshots.
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// Proof-of-work difficulty in leading zero bits (Fable: 20).
    pub pow_difficulty: u32,
    /// Current epoch's global PoW salt (published; one value per epoch).
    pub epoch_salt: [u8; 32],
    /// Previous epoch's PoW salt, accepted alongside the current one to bound
    /// precomputation across a rotation (`None` before the first rotation).
    pub epoch_salt_prev: Option<[u8; 32]>,
    /// Current token epoch (keys COUNTERS + stamps SPENT/RECEIPTS rows).
    pub epoch: u64,
    /// Valid heartbeats required for `pending → active` (Fable: 3).
    pub admission_m: u32,
    /// Heartbeat cadence in seconds (Fable: 30); eviction after 3 missed.
    pub heartbeat_interval_s: u64,
    /// Signed-snapshot rebuild cadence in seconds (Fable: 60).
    pub snapshot_cadence_s: u64,
    /// One-time trial grant per new account, in credits (Fable: 20).
    pub trial_grant: u64,
    /// Global daily trial-credit budget — the real Sybil boundary (Fable: 10_000,
    /// flagged as a product/growth knob, NOT security-reviewed).
    pub daily_trial_budget: u64,
    /// Audit/metering bound on receipt `units` (Fable: 4). NEVER multiplied into
    /// credited amount — a valid receipt credits exactly 1.
    pub units_audit_cap: u32,
    /// Allow loopback/private ingress addresses (TEST ONLY). Prod = `false`,
    /// which denies loopback/link-local/RFC1918 host registrations (SSRF).
    pub allow_loopback_ingress: bool,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            pow_difficulty: 20,
            epoch_salt: [0u8; 32],
            epoch_salt_prev: None,
            epoch: 1,
            admission_m: 3,
            heartbeat_interval_s: 30,
            snapshot_cadence_s: 60,
            trial_grant: 20,
            daily_trial_budget: 10_000,
            units_audit_cap: 4,
            allow_loopback_ingress: false,
        }
    }
}

impl BrokerConfig {
    /// A config suitable for in-process tests: low PoW difficulty (fast solve)
    /// and loopback ingress allowed. Shipped (not `#[cfg(test)]`) so integration
    /// tests in `tests/` — a separate compilation unit — can use it.
    pub fn for_test() -> Self {
        Self {
            pow_difficulty: 8,
            allow_loopback_ingress: true,
            ..Self::default()
        }
    }
}
