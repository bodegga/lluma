//! Persisted, non-secret app settings (endpoints + host config).

use std::path::Path;

use crate::types::Settings;

/// The stable production relay URL (TLS-fronted). Baked in as the default so
/// the app can reach the network out of the box; the ephemeral gateway
/// key-config and registry pubkey are fetched/pasted separately.
pub const DEFAULT_RELAY_URL: &str = "https://relay.n.lluma.bodegga.net";

impl Default for Settings {
    fn default() -> Self {
        Settings {
            relay_url: DEFAULT_RELAY_URL.into(),
            gateway_kc_b64: String::new(),
            registry_pk_b64: String::new(),
            issuer_key_id_hex: String::new(),
            host: Default::default(),
            ollama_install_consent: false,
        }
    }
}

impl Settings {
    /// Load settings from `<dir>/settings.json`. A missing or corrupt file
    /// yields defaults (never an error) so the app always starts.
    pub fn load(dir: &Path) -> Settings {
        let path = dir.join("settings.json");
        std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("settings.json"), bytes).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefills_relay() {
        assert!(Settings::default().relay_url.contains("relay.n.lluma.bodegga.net"));
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("lluma-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Settings {
            gateway_kc_b64: "abc".into(),
            ..Default::default()
        };
        s.save(&dir).unwrap();
        let back = Settings::load(&dir);
        assert_eq!(back.gateway_kc_b64, "abc");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_returns_default() {
        let dir = std::env::temp_dir().join("lluma-settings-does-not-exist-xyz");
        assert!(Settings::load(&dir).relay_url.contains("relay.n"));
    }
}
