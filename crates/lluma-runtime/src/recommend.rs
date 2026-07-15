use lluma_core::{HardwareProfile, LlumaError, ModelRecommendation, ModelSpec, Result};

/// Which models the network currently needs more of.
#[derive(Debug, Clone, Default)]
pub struct DemandSignal {
    pub undersupplied: Vec<String>,
}

/// Recommend the best single model for this machine to host.
pub fn recommend(
    profile: &HardwareProfile,
    catalog: &[ModelSpec],
    demand: &DemandSignal,
) -> Result<ModelRecommendation> {
    let usable = profile.vram_bytes.unwrap_or(profile.ram_bytes);

    let mut fitting: Vec<&ModelSpec> = catalog
        .iter()
        .filter(|s| usable >= s.min_ram_bytes)
        .collect();

    if fitting.is_empty() {
        return Err(LlumaError::NoFittingModel {
            ram_bytes: profile.ram_bytes,
        });
    }

    // Prefer undersupplied models; then the largest that still fits.
    fitting.sort_by(|a, b| {
        let a_needed = demand.undersupplied.contains(&a.id.0);
        let b_needed = demand.undersupplied.contains(&b.id.0);
        b_needed
            .cmp(&a_needed)
            .then(b.params_billions.total_cmp(&a.params_billions))
    });

    let best = fitting[0].clone();
    let needed = demand.undersupplied.contains(&best.id.0);
    let reason = if needed {
        format!(
            "Fits your hardware and the network needs {} right now.",
            best.display_name
        )
    } else {
        format!("Best fit for your hardware ({}).", best.display_name)
    };

    Ok(ModelRecommendation { spec: best, reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lluma_core::{ModelId, Quant};

    fn spec(id: &str, params: f32, min_ram: u64) -> ModelSpec {
        ModelSpec {
            id: ModelId(id.into()),
            display_name: id.into(),
            quant: Quant::Q4KM,
            params_billions: params,
            download_bytes: 1,
            min_ram_bytes: min_ram,
            blake3_hex: "x".into(),
            url: "u".into(),
        }
    }

    fn profile(ram: u64, vram: Option<u64>) -> HardwareProfile {
        HardwareProfile { ram_bytes: ram, vram_bytes: vram, cpu_cores: 8, disk_free_bytes: 1 << 40 }
    }

    #[test]
    fn errors_when_nothing_fits() {
        let cat = vec![spec("big", 70.0, 48_000_000_000)];
        let err = recommend(&profile(8_000_000_000, None), &cat, &DemandSignal::default());
        assert!(matches!(err, Err(LlumaError::NoFittingModel { .. })));
    }

    #[test]
    fn picks_largest_fitting_when_no_demand() {
        let cat = vec![
            spec("small", 3.0, 3_000_000_000),
            spec("mid", 8.0, 6_000_000_000),
        ];
        let rec = recommend(&profile(16_000_000_000, None), &cat, &DemandSignal::default()).unwrap();
        assert_eq!(rec.spec.id.0, "mid");
    }

    #[test]
    fn prefers_undersupplied_model_even_if_smaller() {
        let cat = vec![
            spec("small", 3.0, 3_000_000_000),
            spec("mid", 8.0, 6_000_000_000),
        ];
        let demand = DemandSignal { undersupplied: vec!["small".into()] };
        let rec = recommend(&profile(16_000_000_000, None), &cat, &demand).unwrap();
        assert_eq!(rec.spec.id.0, "small");
        assert!(rec.reason.contains("network needs"));
    }

    #[test]
    fn uses_vram_when_present() {
        // 32GB RAM but only 4GB VRAM => only the small model fits.
        let cat = vec![
            spec("small", 3.0, 3_000_000_000),
            spec("mid", 8.0, 6_000_000_000),
        ];
        let rec = recommend(&profile(32_000_000_000, Some(4_000_000_000)), &cat, &DemandSignal::default()).unwrap();
        assert_eq!(rec.spec.id.0, "small");
    }
}
