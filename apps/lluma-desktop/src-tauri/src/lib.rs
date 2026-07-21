//! Lluma desktop app entrypoint. Command modules are added in later tasks.

mod account;
mod client;
mod host;
mod settings;
mod types;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Lluma");
}
