use lluma_core::{HardwareProfile, ModelRecommendation};
use lluma_registry::builtin_catalog;
use lluma_runtime::{
    detect_hardware, recommend, DemandSignal, GenerateRequest, MockRunner, ModelRunner,
};
use serde::Serialize;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter};

/// App-wide state. In Phase 0 we keep it minimal; a loaded LlamaRunner will live
/// here in a later step once model download is wired end-to-end.
#[derive(Default)]
struct AppState {
    last_profile: Mutex<Option<HardwareProfile>>,
}

#[derive(Serialize, Clone)]
struct TokenEvent {
    text: String,
}

#[tauri::command]
fn detect_hardware_cmd(state: tauri::State<AppState>) -> HardwareProfile {
    let profile = detect_hardware();
    *state.last_profile.lock().unwrap() = Some(profile);
    profile
}

#[tauri::command]
fn recommend_model_cmd() -> std::result::Result<ModelRecommendation, String> {
    let profile = detect_hardware();
    let catalog = builtin_catalog();
    recommend(&profile, &catalog, &DemandSignal::default()).map_err(|e| e.to_string())
}

/// Start generation and stream tokens to the frontend via events.
/// Phase 0 uses MockRunner so the full UI loop is testable before a model is
/// downloaded; swapping in `LlamaRunner::load(...)` is a one-line change once a
/// verified GGUF exists on disk.
#[tauri::command]
fn start_generate(app: AppHandle, prompt: String) {
    std::thread::spawn(move || {
        let mut runner = MockRunner {
            script: vec![
                "Lluma ".into(),
                "is ".into(),
                "running ".into(),
                "locally. ".into(),
                "(prompt: ".into(),
                prompt.clone(),
                ")".into(),
            ],
        };
        let req = GenerateRequest { prompt, max_tokens: 256 };
        let result = runner.generate(&req, &mut |piece| {
            let _ = app.emit("token", TokenEvent { text: piece.to_string() });
        });
        match result {
            Ok(_) => {
                let _ = app.emit("done", ());
            }
            Err(e) => {
                let _ = app.emit("error", e.to_string());
            }
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            detect_hardware_cmd,
            recommend_model_cmd,
            start_generate
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lluma");
}
