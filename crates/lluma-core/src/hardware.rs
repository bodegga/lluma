use serde::{Deserialize, Serialize};

/// A snapshot of the machine's resources, used to recommend a model to host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub ram_bytes: u64,
    pub vram_bytes: Option<u64>,
    pub cpu_cores: usize,
    pub disk_free_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_round_trips_through_json() {
        let p = HardwareProfile {
            ram_bytes: 16_000_000_000,
            vram_bytes: Some(8_000_000_000),
            cpu_cores: 8,
            disk_free_bytes: 200_000_000_000,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: HardwareProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
