use lluma_core::{LlumaError, ModelId, ModelSpec, Quant, Result};

/// A small built-in catalog of models to host. In later phases this is fetched
/// from the network registry; for Phase 0 it is a static list.
///
/// NOTE: `blake3_hex` and `url` must be filled with real values before shipping.
/// The values here are placeholders that will fail verification by design until
/// a maintainer pins a real GGUF (see docs/architecture/model-catalog.md, Phase 2).
pub fn builtin_catalog() -> Vec<ModelSpec> {
    vec![
        ModelSpec {
            id: ModelId("qwen2.5-0.5b-instruct".into()),
            display_name: "Qwen2.5 0.5B Instruct".into(),
            quant: Quant::Q4KM,
            params_billions: 0.5,
            download_bytes: 400_000_000,
            min_ram_bytes: 1_500_000_000,
            blake3_hex: String::new(),
            url: String::new(),
        },
        ModelSpec {
            id: ModelId("llama-3.1-8b-instruct".into()),
            display_name: "Llama 3.1 8B Instruct".into(),
            quant: Quant::Q4KM,
            params_billions: 8.0,
            download_bytes: 4_920_000_000,
            min_ram_bytes: 6_500_000_000,
            blake3_hex: String::new(),
            url: String::new(),
        },
    ]
}

/// Find a model in a catalog by id.
pub fn find(catalog: &[ModelSpec], id: &ModelId) -> Result<ModelSpec> {
    catalog
        .iter()
        .find(|s| &s.id == id)
        .cloned()
        .ok_or_else(|| LlumaError::ModelNotFound(id.0.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_is_nonempty_and_findable() {
        let cat = builtin_catalog();
        assert!(!cat.is_empty());
        let id = cat[0].id.clone();
        assert_eq!(find(&cat, &id).unwrap().id, id);
    }

    #[test]
    fn find_missing_errors() {
        let cat = builtin_catalog();
        let err = find(&cat, &ModelId("nope".into()));
        assert!(matches!(err, Err(LlumaError::ModelNotFound(_))));
    }
}
