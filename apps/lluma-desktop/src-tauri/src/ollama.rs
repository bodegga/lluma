//! Managed auto-host: provision and drive a local [Ollama](https://ollama.com)
//! server so "Start serving" works even when the user has no model server
//! running. When [`detect_local_openai`](crate::host::detect_local_openai)
//! finds nothing, the host layer calls in here to (optionally) install Ollama,
//! start `ollama serve`, and pull a small default model, then serves against
//! `http://localhost:11434/v1`.
//!
//! Trust / lifecycle notes:
//! - **Install is opt-in.** Installing software on the user's machine happens
//!   only after explicit, persisted consent ([`Settings::ollama_install_consent`]).
//!   The host layer returns [`CONSENT_NEEDED`] instead of installing silently.
//! - **We only supervise what we start.** [`ensure_serving`] returns a child
//!   handle *only* when it spawned `ollama serve` itself; a server the user was
//!   already running is left untouched (and never killed on "Stop serving").
//! - No `unwrap`/`expect`; every fallible step yields a typed `String` error the
//!   UI can surface.

use std::path::PathBuf;
use std::time::Duration;

use tauri::{AppHandle, Emitter};
use tokio::process::{Child, Command};

use crate::types::HostProgress;

/// Ollama's local HTTP endpoint (native API + OpenAI-compatible under `/v1`).
pub const OLLAMA_HOST: &str = "http://localhost:11434";
/// OpenAI-compatible base the host serving loop points its upstream at.
pub const OLLAMA_OPENAI_BASE: &str = "http://localhost:11434/v1";
/// Small, fast, low-VRAM default so first-run hosting works on modest hardware.
pub const DEFAULT_MODEL: &str = "qwen2.5:0.5b";
/// Sentinel error returned by the host layer when install consent is required.
/// The frontend matches this exactly to show the one-time consent dialog.
pub const CONSENT_NEEDED: &str = "OLLAMA_CONSENT_NEEDED";
/// Upper bound on a single newline-delimited pull-status line (real ones are
/// well under 1 KiB). Guards the stream parser against unbounded growth.
const MAX_PULL_LINE: usize = 1 << 20;

/// Resolve the effective model tag, falling back to [`DEFAULT_MODEL`] when the
/// config leaves it blank.
pub fn model_tag(configured: &str) -> String {
    let t = configured.trim();
    if t.is_empty() { DEFAULT_MODEL.to_string() } else { t.to_string() }
}

/// Locate the `ollama` binary: PATH first (via the platform `where`/`which`),
/// then well-known per-platform install locations.
pub fn find_binary() -> Option<PathBuf> {
    if let Some(p) = which_ollama() {
        return Some(p);
    }
    well_known_paths().into_iter().find(|cand| cand.is_file())
}

/// True if an `ollama` binary can be located on this machine.
pub fn is_installed() -> bool {
    find_binary().is_some()
}

#[cfg(windows)]
fn which_ollama() -> Option<PathBuf> {
    let out = std::process::Command::new("where").arg("ollama").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines().next().map(|l| PathBuf::from(l.trim()))
}

#[cfg(not(windows))]
fn which_ollama() -> Option<PathBuf> {
    let out = std::process::Command::new("which").arg("ollama").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let first = s.lines().next()?.trim();
    if first.is_empty() { None } else { Some(PathBuf::from(first)) }
}

#[cfg(windows)]
fn well_known_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        v.push(PathBuf::from(local).join("Programs").join("Ollama").join("ollama.exe"));
    }
    if let Ok(pf) = std::env::var("ProgramFiles") {
        v.push(PathBuf::from(pf).join("Ollama").join("ollama.exe"));
    }
    v
}

#[cfg(not(windows))]
fn well_known_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr/local/bin/ollama"),
        PathBuf::from("/opt/homebrew/bin/ollama"),
        PathBuf::from("/usr/bin/ollama"),
        PathBuf::from("/snap/bin/ollama"),
    ]
}

/// A short-timeout HTTP client for probing the local server.
fn probe_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
        .map_err(|e| format!("http client: {e}"))
}

/// True if an Ollama server is answering on the local port.
pub async fn server_up(http: &reqwest::Client) -> bool {
    http.get(format!("{OLLAMA_HOST}/api/version"))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

fn emit(app: &AppHandle, stage: &str, message: impl Into<String>, percent: Option<u8>) {
    // Progress is advisory; a dropped event must never fail the operation.
    let _ = app.emit(
        "host-progress",
        HostProgress { stage: stage.into(), message: message.into(), percent },
    );
}

/// Install Ollama, after the caller has confirmed consent. Best-effort and
/// platform-specific; returns a guiding error if the automated path is
/// unavailable so the user can install manually.
pub async fn install(app: &AppHandle) -> Result<(), String> {
    emit(app, "install", "Installing Ollama…", None);
    let status = install_command()
        .await
        .map_err(|e| format!("could not launch the Ollama installer: {e}"))?;
    if !status.success() {
        return Err(format!(
            "automatic Ollama install failed (exit {}). Install it from https://ollama.com/download and click Start serving again.",
            status.code().map(|c| c.to_string()).unwrap_or_else(|| "unknown".into())
        ));
    }
    // Give a freshly-installed binary a moment to land on PATH / disk.
    for _ in 0..20 {
        if is_installed() {
            emit(app, "install", "Ollama installed.", None);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err("Ollama installed but its binary was not found — you may need to restart the app.".into())
}

#[cfg(windows)]
async fn install_command() -> std::io::Result<std::process::ExitStatus> {
    // winget installs the Ollama package per-user (no UAC prompt in the common
    // case). Agreements are auto-accepted so the run is non-interactive.
    Command::new("winget")
        .args([
            "install",
            "--id",
            "Ollama.Ollama",
            "-e",
            // Pin the source so the exact id can't be satisfied by another
            // configured winget source (review M-1).
            "--source",
            "winget",
            "--silent",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ])
        .status()
        .await
}

#[cfg(target_os = "macos")]
async fn install_command() -> std::io::Result<std::process::ExitStatus> {
    // Prefer Homebrew when present (scriptable, non-interactive).
    Command::new("brew").args(["install", "ollama"]).status().await
}

#[cfg(all(unix, not(target_os = "macos")))]
async fn install_command() -> std::io::Result<std::process::ExitStatus> {
    // Official Linux install script. Download fully to a temp file THEN run it,
    // rather than piping curl→sh, so a dropped connection can't execute a
    // truncated script (review M-2). Fixed official HTTPS URL, no interpolation.
    Command::new("sh")
        .arg("-c")
        .arg(
            "t=$(mktemp) && curl -fsSL https://ollama.com/install.sh -o \"$t\" && sh \"$t\"; \
             r=$?; rm -f \"$t\"; exit $r",
        )
        .status()
        .await
}

/// Ensure a server is listening. If one is already up, returns `Ok(None)` (not
/// ours to manage). Otherwise spawns `ollama serve`, waits until it answers,
/// and returns the child so the caller can stop it later.
pub async fn ensure_serving(app: &AppHandle) -> Result<Option<Child>, String> {
    let http = probe_client()?;
    if server_up(&http).await {
        return Ok(None);
    }
    let bin = find_binary().ok_or("Ollama is not installed")?;
    emit(app, "serve", "Starting the Ollama server…", None);
    let mut cmd = Command::new(&bin);
    cmd.arg("serve");
    // Pin the bind so an inherited OLLAMA_HOST (e.g. 0.0.0.0) can't silently
    // expose the unauthenticated model API to the LAN, and so the readiness
    // probe against `localhost:11434` is deterministic (review I-3).
    cmd.env("OLLAMA_HOST", "127.0.0.1:11434");
    cmd.kill_on_drop(false); // we stop it explicitly on "Stop serving"
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW: don't flash a console window on Windows.
        // `creation_flags` is an inherent method on tokio's Command (cfg windows).
        cmd.creation_flags(0x0800_0000);
    }
    let child = cmd
        .spawn()
        .map_err(|e| format!("could not start `ollama serve`: {e}"))?;
    // Poll until the server answers (or give up after ~20s).
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if server_up(&http).await {
            emit(app, "serve", "Ollama server is up.", None);
            return Ok(Some(child));
        }
    }
    // Failed to come up: don't leak the process.
    let mut child = child;
    let _ = child.kill().await;
    Err("the Ollama server did not become ready in time".into())
}

/// True if `tag` is already present locally.
pub async fn has_model(http: &reqwest::Client, tag: &str) -> Result<bool, String> {
    let resp = http
        .get(format!("{OLLAMA_HOST}/api/tags"))
        .send()
        .await
        .map_err(|e| format!("querying local models: {e}"))?;
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parsing local models: {e}"))?;
    let want = tag.trim();
    let want_base = want.split(':').next().unwrap_or(want);
    let present = json
        .get("models")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter().any(|m| {
                let name = m.get("name").and_then(|n| n.as_str()).unwrap_or("");
                // Exact match, or (when no explicit tag was requested) a base match.
                name == want || (want == want_base && name.split(':').next() == Some(want_base))
            })
        })
        .unwrap_or(false);
    Ok(present)
}

/// Pull `tag` if it is not already present, streaming download progress to the
/// UI via `host-progress` events.
pub async fn ensure_model(app: &AppHandle, tag: &str) -> Result<(), String> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(60 * 30)) // model pulls can be slow
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    if has_model(&http, tag).await.unwrap_or(false) {
        return Ok(());
    }
    emit(app, "pull", format!("Downloading model {tag}…"), Some(0));
    let body = serde_json::json!({ "name": tag, "stream": true });
    let mut resp = http
        .post(format!("{OLLAMA_HOST}/api/pull"))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("starting model download: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("model download rejected (HTTP {})", resp.status().as_u16()));
    }
    // /api/pull streams newline-delimited JSON status objects.
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let chunk = match resp.chunk().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => return Err(format!("model download interrupted: {e}")),
        };
        buf.extend_from_slice(&chunk);
        drain_pull_lines(app, &mut buf, tag)?;
        // Bound the line buffer: genuine pull-status lines are < 1 KiB, so a
        // peer streaming newline-free bytes is either broken or hostile (review
        // M-5). Refuse rather than grow without limit.
        if buf.len() > MAX_PULL_LINE {
            return Err("model download response was malformed (unbounded line)".into());
        }
    }
    // Flush any trailing line the stream didn't newline-terminate.
    if !buf.is_empty() {
        buf.push(b'\n');
        drain_pull_lines(app, &mut buf, tag)?;
    }
    emit(app, "pull", format!("Model {tag} ready."), Some(100));
    Ok(())
}

/// Parse whole newline-terminated JSON lines out of `buf`, emitting progress and
/// surfacing any error status. Leaves a trailing partial line in `buf`.
fn drain_pull_lines(app: &AppHandle, buf: &mut Vec<u8>, tag: &str) -> Result<(), String> {
    while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = buf.drain(..=nl).collect();
        let line = &line[..line.len().saturating_sub(1)];
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else { continue };
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            return Err(format!("model download failed: {err}"));
        }
        let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
        let pct = pull_percent(&v);
        emit(app, "pull", format!("{tag}: {status}"), pct);
    }
    Ok(())
}

/// Compute a 0–100 percent from an Ollama pull status object, if it carries
/// `total`/`completed` byte counters.
fn pull_percent(v: &serde_json::Value) -> Option<u8> {
    let total = v.get("total").and_then(|t| t.as_u64())?;
    let completed = v.get("completed").and_then(|c| c.as_u64()).unwrap_or(0);
    if total == 0 {
        return None;
    }
    let pct = (completed.saturating_mul(100) / total).min(100);
    Some(pct as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_tag_falls_back_to_default() {
        assert_eq!(model_tag(""), DEFAULT_MODEL);
        assert_eq!(model_tag("   "), DEFAULT_MODEL);
        assert_eq!(model_tag("llama3.2:1b"), "llama3.2:1b");
    }

    #[test]
    fn pull_percent_from_counters() {
        let v = serde_json::json!({ "status": "downloading", "total": 200u64, "completed": 50u64 });
        assert_eq!(pull_percent(&v), Some(25));
        let done = serde_json::json!({ "total": 10u64, "completed": 10u64 });
        assert_eq!(pull_percent(&done), Some(100));
        // No counters, or zero total ⇒ no percent.
        assert_eq!(pull_percent(&serde_json::json!({ "status": "pulling manifest" })), None);
        assert_eq!(pull_percent(&serde_json::json!({ "total": 0u64, "completed": 0u64 })), None);
        // Over-report is clamped, never panics.
        let over = serde_json::json!({ "total": 10u64, "completed": 999u64 });
        assert_eq!(pull_percent(&over), Some(100));
    }
}
