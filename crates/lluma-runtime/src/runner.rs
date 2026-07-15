use lluma_core::{LlumaError, Result};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct GenerateRequest {
    pub prompt: String,
    pub max_tokens: usize,
}

/// A model that can stream a completion. `on_token` is invoked with each decoded
/// text piece as it is produced; the full concatenated output is also returned.
pub trait ModelRunner {
    fn generate(&mut self, req: &GenerateRequest, on_token: &mut dyn FnMut(&str)) -> Result<String>;
}

/// A deterministic runner for tests and for wiring consumers before a real model
/// is available. Emits each string in `script` as one "token".
pub struct MockRunner {
    pub script: Vec<String>,
}

impl ModelRunner for MockRunner {
    fn generate(&mut self, req: &GenerateRequest, on_token: &mut dyn FnMut(&str)) -> Result<String> {
        let mut out = String::new();
        for piece in self.script.iter().take(req.max_tokens.max(1)) {
            on_token(piece);
            out.push_str(piece);
        }
        Ok(out)
    }
}

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;
use std::num::NonZeroU32;
use std::sync::Arc;

/// A real llama.cpp-backed runner loaded from a GGUF file.
pub struct LlamaRunner {
    backend: Arc<LlamaBackend>,
    model: LlamaModel,
    n_ctx: u32,
}

impl LlamaRunner {
    /// Load a GGUF model. `n_ctx` is the context window (e.g. 4096).
    pub fn load(model_path: &Path, n_ctx: u32) -> Result<Self> {
        let backend =
            LlamaBackend::init().map_err(|e| LlumaError::Backend(format!("backend init: {e}")))?;
        let model = LlamaModel::load_from_file(&backend, model_path, &LlamaModelParams::default())
            .map_err(|e| LlumaError::Backend(format!("load model: {e}")))?;
        Ok(Self { backend: Arc::new(backend), model, n_ctx })
    }
}

impl ModelRunner for LlamaRunner {
    fn generate(&mut self, req: &GenerateRequest, on_token: &mut dyn FnMut(&str)) -> Result<String> {
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(self.n_ctx));
        let mut ctx = self
            .model
            .new_context(&self.backend, ctx_params)
            .map_err(|e| LlumaError::Backend(format!("new context: {e}")))?;

        let tokens = self
            .model
            .str_to_token(&req.prompt, AddBos::Always)
            .map_err(|e| LlumaError::Backend(format!("tokenize: {e}")))?;

        let mut batch = LlamaBatch::new(512, 1);
        let last = tokens.len().saturating_sub(1);
        for (i, tok) in tokens.iter().enumerate() {
            batch
                .add(*tok, i as i32, &[0], i == last)
                .map_err(|e| LlumaError::Backend(format!("batch add: {e}")))?;
        }
        ctx.decode(&mut batch)
            .map_err(|e| LlumaError::Backend(format!("decode: {e}")))?;

        let mut sampler = LlamaSampler::chain_simple([
            LlamaSampler::top_p(0.9, 1),
            LlamaSampler::temp(0.7),
            LlamaSampler::dist(1234),
        ]);

        let mut out = String::new();
        let mut n_cur = tokens.len() as i32;
        let mut decoder = encoding_rs::UTF_8.new_decoder();

        for _ in 0..req.max_tokens {
            let next = sampler.sample(&ctx, batch.n_tokens() - 1);
            sampler.accept(next);
            if next == self.model.token_eos() {
                break;
            }
            // NOTE: brief called `token_to_piece(next, &mut decoder, false)` (3 args), but
            // llama-cpp-2 0.1.151's `LlamaModel::token_to_piece` takes a 4th `lstrip:
            // Option<NonZeroU16>` parameter. Pass `None` to preserve "no lstrip" behavior.
            let piece = self
                .model
                .token_to_piece(next, &mut decoder, false, None)
                .map_err(|e| LlumaError::Backend(format!("detokenize: {e}")))?;
            on_token(&piece);
            out.push_str(&piece);

            batch.clear();
            batch
                .add(next, n_cur, &[0], true)
                .map_err(|e| LlumaError::Backend(format!("batch add: {e}")))?;
            n_cur += 1;
            ctx.decode(&mut batch)
                .map_err(|e| LlumaError::Backend(format!("decode: {e}")))?;
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_runner_streams_and_returns_full_output() {
        let mut runner = MockRunner {
            script: vec!["Hel".into(), "lo".into(), "!".into()],
        };
        let mut streamed = String::new();
        let full = runner
            .generate(
                &GenerateRequest { prompt: "hi".into(), max_tokens: 10 },
                &mut |t| streamed.push_str(t),
            )
            .unwrap();
        assert_eq!(full, "Hello!");
        assert_eq!(streamed, "Hello!");
    }

    #[test]
    fn mock_runner_respects_max_tokens() {
        let mut runner = MockRunner { script: vec!["a".into(), "b".into(), "c".into()] };
        let full = runner
            .generate(&GenerateRequest { prompt: "x".into(), max_tokens: 2 }, &mut |_| {})
            .unwrap();
        assert_eq!(full, "ab");
    }
}
