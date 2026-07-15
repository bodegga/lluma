use futures_util::StreamExt;
use lluma_core::{LlumaError, ModelSpec, Result};
use std::path::{Path, PathBuf};

/// Verify a byte buffer against an expected BLAKE3 hex digest.
pub fn verify_blake3(bytes: &[u8], expected_hex: &str) -> Result<()> {
    let actual = blake3::hash(bytes).to_hex().to_string();
    if actual == expected_hex {
        Ok(())
    } else {
        Err(LlumaError::HashMismatch {
            expected: expected_hex.to_string(),
            actual,
        })
    }
}

/// Download a model to `dest_dir`, verify its BLAKE3 hash, and return the path.
/// The file is only written to its final name after verification passes.
pub async fn download_verified(spec: &ModelSpec, dest_dir: &Path) -> Result<PathBuf> {
    tokio::fs::create_dir_all(dest_dir).await?;
    let final_path = dest_dir.join(format!("{}-{}.gguf", spec.id.0, spec.quant));

    let resp = reqwest::get(&spec.url)
        .await
        .map_err(|e| LlumaError::Download(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(LlumaError::Download(format!("http status {}", resp.status())));
    }

    let mut hasher = blake3::Hasher::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| LlumaError::Download(e.to_string()))?;
        hasher.update(&chunk);
        buf.extend_from_slice(&chunk);
    }

    let actual = hasher.finalize().to_hex().to_string();
    if actual != spec.blake3_hex {
        return Err(LlumaError::HashMismatch {
            expected: spec.blake3_hex.clone(),
            actual,
        });
    }

    tokio::fs::write(&final_path, &buf).await?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_correct_hash() {
        let data = b"hello lluma";
        let hex = blake3::hash(data).to_hex().to_string();
        assert!(verify_blake3(data, &hex).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_hash() {
        let err = verify_blake3(b"hello lluma", "deadbeef");
        assert!(matches!(err, Err(LlumaError::HashMismatch { .. })));
    }
}
