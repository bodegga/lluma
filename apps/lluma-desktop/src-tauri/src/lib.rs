//! Lluma desktop app: managed state + the Tauri command layer wiring the
//! account, client (chat), settings, and host (contribute) modules to the UI.

mod account;
mod anchor;
mod client;
mod host;
mod ollama;
mod settings;
mod types;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use tauri::Manager;
use tokio::sync::Mutex;

use account::Account;
use client::{TokenStore, VerifiedNet};
use host::HostHandle;
use types::{AccountStatus, ChatReply, HostStatus, NetworkStatus, NewAccount, Settings};

/// Everything mutable behind one async mutex. The lock is short-lived except
/// across network calls in chat/acquire/host-start, which serialize by design
/// (a desktop app does one of these at a time).
struct Inner {
    settings: Settings,
    /// Present only while unlocked. Holds the in-memory account keys.
    account: Option<Account>,
    /// Unspent tokens; meaningful only while unlocked.
    tokens: TokenStore,
    /// Passphrase kept in memory while unlocked, to re-seal the token store on
    /// balance changes. Cleared on `lock`.
    passphrase: Option<String>,
    /// Trusted network params for THIS session. Set ONLY by a verified path:
    /// `auto_connect` (signed bootstrap vs the pinned anchor) on anchored builds,
    /// or manual entry on self-host/dev builds. Chat/acquire refuse when `None`.
    /// Persisted `settings.*_b64` are display-only and never trusted for verification.
    verified: Option<VerifiedNet>,
    host: Option<HostHandle>,
}

struct AppState {
    data_dir: PathBuf,
    inner: Mutex<Inner>,
    /// Single-flight latch for `host_start`. Provisioning runs without the
    /// `inner` lock (it can take minutes), so this serializes starts and closes
    /// the double-start race where a loser could kill the winner's upstream.
    starting: AtomicBool,
}

impl AppState {
    fn new(data_dir: PathBuf) -> Self {
        let settings = Settings::load(&data_dir);
        // Anchored builds must (re)establish trust via auto_connect each launch;
        // self-host/dev builds may restore the operator's manually-entered
        // endpoints (an explicit user-trust choice), never unverified relay data.
        let verified = if anchor::has_anchor() {
            None
        } else {
            client::manual_verified(&settings).ok()
        };
        AppState {
            data_dir,
            inner: Mutex::new(Inner {
                settings,
                account: None,
                tokens: TokenStore::default(),
                passphrase: None,
                verified,
                host: None,
            }),
            starting: AtomicBool::new(false),
        }
    }
}

// ---- settings ----

#[tauri::command]
async fn get_settings(state: tauri::State<'_, AppState>) -> Result<Settings, String> {
    Ok(state.inner.lock().await.settings.clone())
}

#[tauri::command]
async fn set_settings(
    state: tauri::State<'_, AppState>,
    settings: Settings,
) -> Result<(), String> {
    settings.save(&state.data_dir)?;
    let mut inner = state.inner.lock().await;
    let relay_changed = inner.settings.relay_url != settings.relay_url;
    inner.settings = settings;
    // On anchored (official) builds, trust comes ONLY from the pinned-key-verified
    // bootstrap — webview-supplied endpoint fields are never promoted to trust.
    // Changing the relay invalidates the current verified params (they were
    // bootstrapped from a different relay) → clear so the next auto_connect
    // re-verifies against the new relay.
    // On self-host/dev builds, manual entry IS the (explicit) trust path.
    if anchor::has_anchor() {
        if relay_changed {
            inner.verified = None;
        }
    } else {
        inner.verified = client::manual_verified(&inner.settings).ok();
    }
    Ok(())
}

// ---- account ----

fn account_status_of(inner: &Inner, dir: &Path) -> AccountStatus {
    match &inner.account {
        Some(a) => AccountStatus {
            has_account: true,
            unlocked: true,
            account_id_hex: a.account_id_hex(),
            balance: inner.tokens.balance(),
        },
        None => AccountStatus {
            has_account: Account::exists(dir),
            unlocked: false,
            account_id_hex: String::new(),
            balance: 0,
        },
    }
}

#[tauri::command]
async fn account_status(state: tauri::State<'_, AppState>) -> Result<AccountStatus, String> {
    let inner = state.inner.lock().await;
    Ok(account_status_of(&inner, &state.data_dir))
}

#[tauri::command]
async fn create_account(
    state: tauri::State<'_, AppState>,
    passphrase: String,
) -> Result<NewAccount, String> {
    let acct = Account::create(&state.data_dir, &passphrase)?;
    let out = NewAccount {
        account_id_hex: acct.account_id_hex(),
        recovery_phrase: acct.recovery_phrase()?,
    };
    let mut inner = state.inner.lock().await;
    inner.tokens = TokenStore::load(&state.data_dir, &passphrase);
    inner.account = Some(acct);
    inner.passphrase = Some(passphrase);
    Ok(out)
}

#[tauri::command]
async fn import_account(
    state: tauri::State<'_, AppState>,
    phrase: String,
    passphrase: String,
) -> Result<NewAccount, String> {
    let acct = Account::import(&state.data_dir, &phrase, &passphrase)?;
    let out = NewAccount {
        account_id_hex: acct.account_id_hex(),
        recovery_phrase: acct.recovery_phrase()?,
    };
    let mut inner = state.inner.lock().await;
    inner.tokens = TokenStore::load(&state.data_dir, &passphrase);
    inner.account = Some(acct);
    inner.passphrase = Some(passphrase);
    Ok(out)
}

#[tauri::command]
async fn unlock(
    state: tauri::State<'_, AppState>,
    passphrase: String,
) -> Result<AccountStatus, String> {
    let acct = Account::unlock(&state.data_dir, &passphrase)?;
    let mut inner = state.inner.lock().await;
    inner.tokens = TokenStore::load(&state.data_dir, &passphrase);
    inner.account = Some(acct);
    inner.passphrase = Some(passphrase);
    Ok(account_status_of(&inner, &state.data_dir))
}

#[tauri::command]
async fn lock(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut inner = state.inner.lock().await;
    inner.account = None;
    inner.passphrase = None;
    inner.tokens = TokenStore::default();
    Ok(())
}

// ---- network / chat ----

/// Whether this build has a pinned trust anchor (i.e. secure auto-connect is
/// available). The frontend uses this to choose the automatic vs manual flow.
#[tauri::command]
fn has_anchor() -> bool {
    anchor::has_anchor()
}

/// Secure auto-connect: if an anchor is pinned, fetch + verify the signed
/// bootstrap from the relay, populate the endpoints (gateway key-config +
/// the pinned registry key + issuer key-id), persist, and report reachability.
/// If no anchor is pinned, this is a no-op that returns the current status —
/// the manual (Advanced) flow applies. A malicious relay cannot subvert this:
/// the bootstrap is signature-verified against the compiled-in key.
#[tauri::command]
async fn auto_connect(state: tauri::State<'_, AppState>) -> Result<NetworkStatus, String> {
    let Some(anchor_pk) = anchor::pinned_registry_pk() else {
        // Unanchored (self-host/dev) build: no signed bootstrap to fetch; trust
        // comes from manual entry. Just report current reachability.
        return network_status(state).await;
    };
    let relay = state.inner.lock().await.settings.relay_url.clone();
    // Verified against the COMPILED-IN key — a malicious relay cannot subvert this.
    let doc = lluma_client::fetch_bootstrap(&relay, &anchor_pk)
        .await
        .map_err(|e| format!("auto-connect failed ({e}) — check your connection and try again"))?;
    {
        let mut inner = state.inner.lock().await;
        inner.verified = Some(VerifiedNet {
            gateway_kc: lluma_core::wire::OhttpKeyConfig(doc.gateway_kc.clone()),
            registry_pk: anchor_pk.clone(),
            issuer_key_id: Some(doc.issuer_key_id),
        });
        // Cache for display only (never trusted for verification).
        inner.settings.gateway_kc_b64 =
            base64::engine::general_purpose::STANDARD.encode(&doc.gateway_kc);
        inner.settings.registry_pk_b64 =
            base64::engine::general_purpose::STANDARD.encode(&anchor_pk.0);
        inner.settings.issuer_key_id_hex =
            doc.issuer_key_id.iter().map(|b| format!("{b:02x}")).collect();
        inner.settings.save(&state.data_dir)?;
    }
    network_status(state).await
}

#[tauri::command]
async fn network_status(state: tauri::State<'_, AppState>) -> Result<NetworkStatus, String> {
    // Probing needs the session's verified gateway key-config. If trust has not
    // been established this session, report "not connected" rather than trusting
    // any persisted/unverified value.
    let (relay, verified, acct_keys) = {
        let inner = state.inner.lock().await;
        (
            inner.settings.relay_url.clone(),
            inner.verified.clone(),
            inner.account.as_ref().map(|a| (a.sk.clone(), a.pk.clone())),
        )
    };
    let Some(v) = verified else {
        return Ok(NetworkStatus {
            reachable: false,
            epoch: 0,
            denomination: 0,
            latency_ms: 0,
            message: "not connected".into(),
        });
    };
    // Ephemeral throwaway account when none is unlocked — key-config needs no
    // real account, only the gateway key-config to seal OHTTP.
    let (sk, pk) = match acct_keys {
        Some(keys) => keys,
        None => {
            let mut rng = rand_core::OsRng;
            let m = lluma_crypto::account::account_mnemonic_new(&mut rng)
                .map_err(|e| e.to_string())?;
            lluma_crypto::account::derive_keypair_from_seed(&m).map_err(|e| e.to_string())?
        }
    };
    let cli = client::build_client(&relay, &sk, &pk, &v);
    Ok(client::network_status(&cli).await)
}

#[tauri::command]
async fn acquire_tokens(
    state: tauri::State<'_, AppState>,
    n: usize,
) -> Result<usize, String> {
    let mut inner = state.inner.lock().await;
    let Inner { settings, account, tokens, passphrase, verified, .. } = &mut *inner;
    let acct = account.as_ref().ok_or("unlock your account first")?;
    let pass = passphrase.as_ref().ok_or("unlock your account first")?;
    let v = verified.as_ref().ok_or("not connected — connect to the network first")?;
    let cli = client::build_client(&settings.relay_url, &acct.sk, &acct.pk, v);
    client::acquire(&cli, tokens, &state.data_dir, pass, n).await
}

#[tauri::command]
async fn send_message(
    state: tauri::State<'_, AppState>,
    prompt: String,
) -> Result<ChatReply, String> {
    let mut inner = state.inner.lock().await;
    let Inner { settings, account, tokens, passphrase, verified, .. } = &mut *inner;
    let acct = account.as_ref().ok_or("unlock your account first")?;
    let pass = passphrase.as_ref().ok_or("unlock your account first")?;
    let v = verified.as_ref().ok_or("not connected — connect to the network first")?;
    let registry_pk = v.registry_pk.clone();
    let cli = client::build_client(&settings.relay_url, &acct.sk, &acct.pk, v);
    client::send_message(&cli, tokens, &registry_pk, &state.data_dir, pass, &prompt).await
}

// ---- host (contribute) ----

#[tauri::command]
async fn host_start(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<HostStatus, String> {
    // Single-flight latch (review M-6): only one host_start body runs at a time.
    // The guard clears it on EVERY exit (early `?`, error, success), closing the
    // double-start race even though provisioning below holds no `inner` lock.
    if state.starting.swap(true, Ordering::SeqCst) {
        return Err("already starting — please wait".into());
    }
    struct StartGuard<'a>(&'a AtomicBool);
    impl Drop for StartGuard<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    let _start_guard = StartGuard(&state.starting);

    // Phase 1 — read what we need under the lock, then release it. Provisioning
    // (below) can take minutes (model download); holding the lock would freeze
    // every other command. Live progress reaches the UI via `host-progress`
    // events, not via polling this lock.
    let (mut cfg, pass, consent) = {
        let inner = state.inner.lock().await;
        if inner.account.is_none() {
            return Err("unlock your account first".into());
        }
        if inner.host.is_some() {
            return Err("already serving — stop first".into());
        }
        let pass = inner.passphrase.clone().ok_or("unlock your account first")?;
        (inner.settings.host.clone(), pass, inner.settings.ollama_install_consent)
    };

    // Phase 2 — auto-host (no lock held). If an OpenAI upstream is selected with
    // no base URL, first try to reuse a server the user is already running
    // (Ollama / LM Studio / llama.cpp). If nothing is running, provision Ollama:
    // install (only with prior consent), `serve`, and pull a small default model.
    // Once we hold a managed child, EVERY subsequent early return must stop it,
    // or the server strands and later masquerades as a user-run one (review I-1).
    let mut managed_ollama: Option<tokio::process::Child> = None;
    async fn reap(child: &mut Option<tokio::process::Child>) {
        if let Some(mut c) = child.take() {
            let _ = c.kill().await;
        }
    }
    if matches!(cfg.upstream, types::UpstreamKind::OpenAi) && cfg.openai_base.trim().is_empty() {
        match host::detect_local_openai().await {
            Some((base, model)) => {
                cfg.openai_base = base;
                if cfg.openai_model.trim().is_empty() {
                    cfg.openai_model = model;
                }
            }
            None => {
                // Managed fallback. Installing software is gated on one-time
                // consent; the UI catches CONSENT_NEEDED and asks, then retries.
                if !ollama::is_installed() {
                    if !consent {
                        return Err(ollama::CONSENT_NEEDED.into());
                    }
                    ollama::install(&app).await?; // no child yet — nothing to reap
                }
                managed_ollama = ollama::ensure_serving(&app).await?;
                let tag = ollama::model_tag(&cfg.ollama_model);
                if let Err(e) = ollama::ensure_model(&app, &tag).await {
                    reap(&mut managed_ollama).await;
                    return Err(e);
                }
                cfg.upstream = types::UpstreamKind::OpenAi;
                cfg.openai_base = ollama::OLLAMA_OPENAI_BASE.to_string();
                cfg.openai_model = tag;
            }
        }
    }

    let (host_sk, _host_pk) = match host::load_or_create_host_key(&state.data_dir, &pass) {
        Ok(k) => k,
        Err(e) => {
            reap(&mut managed_ollama).await;
            return Err(e);
        }
    };
    // HostHandle::start takes ownership of the child and reaps it on its own
    // internal failures, so from here the child can no longer strand.
    let handle = HostHandle::start(&cfg, host_sk, managed_ollama).await?;
    let status = handle.snapshot_status();

    // Phase 3 — re-acquire the lock to persist the resolved upstream and store
    // the running handle. The latch already prevents a concurrent start; this
    // guard is belt-and-suspenders.
    let mut inner = state.inner.lock().await;
    if inner.host.is_some() {
        handle.stop().await; // also stops any Ollama we just started
        return Err("already serving — stop first".into());
    }
    inner.settings.host = cfg;
    let _ = inner.settings.save(&state.data_dir);
    inner.host = Some(handle);
    Ok(status)
}

#[tauri::command]
async fn host_stop(state: tauri::State<'_, AppState>) -> Result<HostStatus, String> {
    let handle = {
        let mut inner = state.inner.lock().await;
        inner.host.take()
    };
    if let Some(h) = handle {
        h.stop().await; // stops the serve task and any managed Ollama server
    }
    Ok(host::stopped_status())
}

/// Record the user's one-time consent for the app to install Ollama. The
/// Contribute tab calls this after the user accepts the install prompt, then
/// retries `host_start`.
#[tauri::command]
async fn grant_ollama_consent(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut inner = state.inner.lock().await;
    inner.settings.ollama_install_consent = true;
    inner.settings.save(&state.data_dir)
}

#[tauri::command]
async fn host_status(state: tauri::State<'_, AppState>) -> Result<HostStatus, String> {
    let inner = state.inner.lock().await;
    Ok(match &inner.host {
        Some(h) => h.snapshot_status(),
        None => host::stopped_status(),
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("no app data dir: {e}"))?;
            std::fs::create_dir_all(&dir).ok();
            app.manage(AppState::new(dir));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_settings,
            set_settings,
            has_anchor,
            auto_connect,
            account_status,
            create_account,
            import_account,
            unlock,
            lock,
            network_status,
            acquire_tokens,
            send_message,
            host_start,
            host_stop,
            host_status,
            grant_ollama_consent,
        ])
        .build(tauri::generate_context!())
        .expect("error while building Lluma")
        .run(|app_handle, event| {
            // Reap a managed Ollama server on app exit so quitting while hosting
            // never strands it (review I-2). Best-effort + synchronous: the async
            // runtime may be winding down, so use try_lock + start_kill (no await).
            if matches!(event, tauri::RunEvent::Exit) {
                if let Some(state) = app_handle.try_state::<AppState>() {
                    if let Ok(mut inner) = state.inner.try_lock() {
                        if let Some(h) = inner.host.as_mut() {
                            h.kill_managed_now();
                        }
                    }
                }
            }
        });
}
