fn main() {
    // M3 (crypto-architect): if a trust anchor is baked in, it MUST be a valid
    // 32-byte base64 Ed25519 key. Fail the build on a malformed value rather
    // than silently shipping an *unanchored* release (which would fall back to
    // the manual/unverified flow). Absent var = intentional dev build.
    println!("cargo:rerun-if-env-changed=LLUMA_REGISTRY_PK_B64");
    if let Ok(b64) = std::env::var("LLUMA_REGISTRY_PK_B64") {
        let b64 = b64.trim();
        if !b64.is_empty() {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap_or_else(|e| panic!("LLUMA_REGISTRY_PK_B64 is not valid base64: {e}"));
            assert_eq!(
                decoded.len(),
                32,
                "LLUMA_REGISTRY_PK_B64 must decode to a 32-byte Ed25519 key, got {} bytes",
                decoded.len()
            );
        }
    }
    tauri_build::build()
}
