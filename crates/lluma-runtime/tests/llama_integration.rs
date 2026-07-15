//! Runs only when LLUMA_TEST_GGUF points to a real small GGUF file.
//! Example (PowerShell): $env:LLUMA_TEST_GGUF="C:\models\qwen0.5b.gguf"; cargo test -p lluma-runtime --test llama_integration -- --nocapture
use lluma_runtime::{GenerateRequest, LlamaRunner, ModelRunner};

#[test]
fn generates_tokens_from_a_real_model() {
    let Ok(path) = std::env::var("LLUMA_TEST_GGUF") else {
        eprintln!("skipping: set LLUMA_TEST_GGUF to a GGUF path to run this test");
        return;
    };
    let mut runner = LlamaRunner::load(std::path::Path::new(&path), 2048)
        .expect("load model");
    let mut streamed = String::new();
    let out = runner
        .generate(
            &GenerateRequest { prompt: "The capital of France is".into(), max_tokens: 16 },
            &mut |t| streamed.push_str(t),
        )
        .expect("generate");
    assert!(!out.is_empty(), "model should produce output");
    assert_eq!(out, streamed, "streamed and returned output must match");
}
