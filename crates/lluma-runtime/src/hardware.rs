use lluma_core::HardwareProfile;

/// Detect the machine's resources. VRAM is best-effort (NVIDIA via NVML);
/// `None` when it cannot be determined.
pub fn detect_hardware() -> HardwareProfile {
    use sysinfo::{Disks, System};

    let mut sys = System::new_all();
    sys.refresh_memory();

    let ram_bytes = sys.total_memory();
    let cpu_cores = sys.cpus().len().max(1);

    let disks = Disks::new_with_refreshed_list();
    let disk_free_bytes = disks
        .list()
        .iter()
        .map(|d| d.available_space())
        .max()
        .unwrap_or(0);

    let vram_bytes = detect_vram();

    HardwareProfile {
        ram_bytes,
        vram_bytes,
        cpu_cores,
        disk_free_bytes,
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn detect_vram() -> Option<u64> {
    let nvml = nvml_wrapper::Nvml::init().ok()?;
    let device = nvml.device_by_index(0).ok()?;
    let mem = device.memory_info().ok()?;
    Some(mem.total)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn detect_vram() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_plausible_values() {
        let p = detect_hardware();
        assert!(p.ram_bytes > 0, "RAM should be detected");
        assert!(p.cpu_cores >= 1, "at least one core");
    }
}
