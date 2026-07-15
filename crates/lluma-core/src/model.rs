use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Quant {
    #[serde(rename = "Q4_K_M")]
    Q4KM,
    #[serde(rename = "Q5_K_M")]
    Q5KM,
    #[serde(rename = "Q8_0")]
    Q8,
    F16,
}

impl std::fmt::Display for Quant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Quant::Q4KM => "Q4_K_M",
            Quant::Q5KM => "Q5_K_M",
            Quant::Q8 => "Q8_0",
            Quant::F16 => "F16",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelId(pub String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelSpec {
    pub id: ModelId,
    pub display_name: String,
    pub quant: Quant,
    pub params_billions: f32,
    pub download_bytes: u64,
    pub min_ram_bytes: u64,
    pub blake3_hex: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelRecommendation {
    pub spec: ModelSpec,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quant_display_matches_gguf_naming() {
        assert_eq!(Quant::Q4KM.to_string(), "Q4_K_M");
        assert_eq!(Quant::F16.to_string(), "F16");
    }

    #[test]
    fn quant_serde_matches_display() {
        for q in [Quant::Q4KM, Quant::Q5KM, Quant::Q8, Quant::F16] {
            let json = serde_json::to_string(&q).unwrap();
            assert_eq!(json, format!("\"{}\"", q));
            let back: Quant = serde_json::from_str(&json).unwrap();
            assert_eq!(back, q);
        }
    }

    #[test]
    fn model_spec_round_trips_through_json() {
        let spec = ModelSpec {
            id: ModelId("llama-3.1-8b".into()),
            display_name: "Llama 3.1 8B".into(),
            quant: Quant::Q4KM,
            params_billions: 8.0,
            download_bytes: 4_920_000_000,
            min_ram_bytes: 6_000_000_000,
            blake3_hex: "abc123".into(),
            url: "https://example.com/model.gguf".into(),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: ModelSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }
}
