//! Local hardware detection + model recommendation for the Contribute tab.
//! Detects an NVIDIA GPU (via `nvidia-smi`) and suggests Ollama models sized to
//! the available VRAM, with an earning-tier hint.
//!
//! Note on earnings: the broker currently credits a flat amount per served
//! request (audit `units` are never multiplied — anti-self-dealing). The `tier`
//! here is a forward-looking label; per-model differential crediting is a
//! broker/economics change (see the ADR backlog), so the UI presents tier as
//! "earns more once tiered crediting ships", not a live multiplier.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct HardwareInfo {
    /// Human-readable accelerator name, or a CPU-only note.
    pub gpu: String,
    /// Detected VRAM in MiB (0 ⇒ no discrete GPU detected; CPU/RAM inference).
    pub vram_mb: u64,
    /// "cuda" | "cpu".
    pub backend: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelOption {
    /// Ollama tag to pull/serve.
    pub tag: String,
    pub label: String,
    pub params: String,
    /// Rough VRAM (MiB) needed to serve comfortably.
    pub min_vram_mb: u64,
    /// Forward-looking earning tier: "starter" | "standard" | "advanced".
    pub tier: String,
    /// Whether it fits the detected hardware.
    pub fits: bool,
}

/// Detect the primary accelerator. Tries `nvidia-smi` first; falls back to a
/// CPU-only descriptor. Never fails (returns a best-effort descriptor).
pub fn detect_hardware() -> HardwareInfo {
    if let Some(hw) = nvidia_smi() {
        return hw;
    }
    HardwareInfo {
        gpu: "No NVIDIA GPU detected — CPU inference (small models only)".into(),
        vram_mb: 0,
        backend: "cpu".into(),
    }
}

fn nvidia_smi() -> Option<HardwareInfo> {
    let mut cmd = std::process::Command::new("nvidia-smi");
    cmd.args(["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().next()?;
    let parts: Vec<&str> = line.split(',').map(|p| p.trim()).collect();
    if parts.len() < 2 {
        return None;
    }
    let vram_mb: u64 = parts[1].parse().ok()?;
    Some(HardwareInfo { gpu: parts[0].to_string(), vram_mb, backend: "cuda".into() })
}

/// Curated Ollama models by size, each flagged for whether it fits `vram_mb`
/// (0 = CPU: only the smallest are practical).
pub fn recommend_models(vram_mb: u64) -> Vec<ModelOption> {
    // (tag, label, params, min_vram_mb, tier)
    const CATALOG: &[(&str, &str, &str, u64, &str)] = &[
        ("qwen2.5:0.5b", "Qwen2.5 0.5B", "0.5B", 1_000, "starter"),
        ("llama3.2:1b", "Llama 3.2 1B", "1B", 2_000, "starter"),
        ("qwen2.5:3b", "Qwen2.5 3B", "3B", 4_000, "standard"),
        ("qwen2.5:7b", "Qwen2.5 7B", "7B", 6_500, "standard"),
        ("llama3.1:8b", "Llama 3.1 8B", "8B", 7_000, "standard"),
        ("qwen2.5:14b", "Qwen2.5 14B", "14B", 11_000, "advanced"),
        ("qwen2.5:32b", "Qwen2.5 32B", "32B", 22_000, "advanced"),
    ];
    CATALOG
        .iter()
        .map(|(tag, label, params, min, tier)| {
            let fits = if vram_mb == 0 { *min <= 2_000 } else { vram_mb >= *min };
            ModelOption {
                tag: (*tag).to_string(),
                label: (*label).to_string(),
                params: (*params).to_string(),
                min_vram_mb: *min,
                tier: (*tier).to_string(),
                fits,
            }
        })
        .collect()
}

/// Combined hardware + model recommendation report for the Contribute tab.
#[derive(Debug, Clone, Serialize)]
pub struct HardwareReport {
    pub hardware: HardwareInfo,
    pub models: Vec<ModelOption>,
    /// Suggested default tag for this hardware.
    pub recommended: String,
}

pub fn report() -> HardwareReport {
    let hardware = detect_hardware();
    let models = recommend_models(hardware.vram_mb);
    let recommended = default_model_for(hardware.vram_mb);
    HardwareReport { hardware, models, recommended }
}

/// The best default tag for detected hardware: the largest model that fits,
/// falling back to the smallest.
pub fn default_model_for(vram_mb: u64) -> String {
    let models = recommend_models(vram_mb);
    // CPU (no VRAM): the smallest model is the safe default. With a GPU: the
    // largest model that fits comfortably.
    let pick = if vram_mb == 0 {
        models.iter().find(|m| m.fits)
    } else {
        models.iter().filter(|m| m.fits).max_by_key(|m| m.min_vram_mb)
    };
    pick.or_else(|| models.first())
        .map(|m| m.tag.clone())
        .unwrap_or_else(|| "qwen2.5:0.5b".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommend_flags_fit_by_vram() {
        let m = recommend_models(12_000); // ~RTX 3060 12GB
        let by = |t: &str| m.iter().find(|x| x.tag == t).unwrap().fits;
        assert!(by("qwen2.5:7b"));
        assert!(by("qwen2.5:14b"));
        assert!(!by("qwen2.5:32b")); // needs ~22GB
        // CPU-only: only the smallest fit.
        let cpu = recommend_models(0);
        assert!(cpu.iter().find(|x| x.tag == "qwen2.5:0.5b").unwrap().fits);
        assert!(!cpu.iter().find(|x| x.tag == "qwen2.5:14b").unwrap().fits);
    }

    #[test]
    fn default_model_picks_largest_fit() {
        assert_eq!(default_model_for(12_000), "qwen2.5:14b");
        assert_eq!(default_model_for(0), "qwen2.5:0.5b");
        assert_eq!(default_model_for(3_000), "llama3.2:1b");
    }
}
