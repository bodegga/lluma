//! Lluma desktop app: managed state + the Tauri command layer wiring the
//! account, client (chat), settings, and host (contribute) modules to the UI.

mod account;
mod anchor;
mod client;
mod host;
mod settings;
mod types;

use std::path::{Path, PathBuf};

use base64::Engine;
use tauri::Manager;
use tokio::sync::Mutex;

use account::Account;
use client::TokenStore;
use host::HostHandle;
use types::{
    AccountStatus, BootstrapDoc, ChatReply, HostStatus, NetworkStatus, NewAccount, Settings,
};

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
    host: Option<HostHandle>,
}

struct AppState {
    data_dir: PathBuf,
    inner: Mutex<Inner>,
}

impl AppState {
    fn new(data_dir: PathBuf) -> Self {
        let settings = Settings::load(&data_dir);
        AppState {
            data_dir,
            inner: Mutex::new(Inner {
                settings,
                account: None,
                tokens: TokenStore::default(),
                passphrase: None,
                host: None,
            }),
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
    state.inner.lock().await.settings = settings;
    Ok(())
}

/// Pull endpoint material from the relay's signed bootstrap, if published.
#[tauri::command]
async fn fetch_bootstrap(state: tauri::State<'_, AppState>) -> Result<Settings, String> {
    let relay = state.inner.lock().await.settings.relay_url.clone();
    let url = format!("{}/v1/bootstrap", relay.trim_end_matches('/'));
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = http.get(&url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err("relay does not publish bootstrap yet — paste values manually".into());
    }
    let doc: BootstrapDoc = resp.json().await.map_err(|_| {
        "relay does not publish bootstrap yet — paste values manually".to_string()
    })?;
    let mut inner = state.inner.lock().await;
    if !doc.gateway_kc_b64.is_empty() {
        inner.settings.gateway_kc_b64 = doc.gateway_kc_b64;
    }
    if !doc.registry_pk_b64.is_empty() {
        inner.settings.registry_pk_b64 = doc.registry_pk_b64;
    }
    if !doc.issuer_key_id_hex.is_empty() {
        inner.settings.issuer_key_id_hex = doc.issuer_key_id_hex;
    }
    inner.settings.save(&state.data_dir)?;
    Ok(inner.settings.clone())
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
        return network_status(state).await;
    };
    let relay = state.inner.lock().await.settings.relay_url.clone();
    let doc = lluma_client::fetch_bootstrap(&relay, &anchor_pk)
        .await
        .map_err(|e| format!("auto-connect failed ({e}) — check your connection or set endpoints manually"))?;
    {
        let mut inner = state.inner.lock().await;
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
    // Build a probe client. If no account is unlocked, use an ephemeral one —
    // key-config needs no account, only the gateway key-config to seal OHTTP.
    let (settings, acct_keys) = {
        let inner = state.inner.lock().await;
        let keys = inner
            .account
            .as_ref()
            .map(|a| (a.sk.clone(), a.pk.clone()));
        (inner.settings.clone(), keys)
    };
    let client = match acct_keys {
        Some((sk, pk)) => {
            let (kc, _reg) = client::decode_settings(&settings)?;
            lluma_client::Client::new(
                settings.relay_url.clone(),
                kc,
                sk,
                pk,
                lluma_core::wire::HostPublicKey(vec![0u8; 32]),
                [0u8; 32],
            )
        }
        None => {
            // Ephemeral throwaway account just to probe key-config.
            let (kc, _reg) = client::decode_settings(&settings)?;
            let mut rng = rand_core::OsRng;
            let m = lluma_crypto::account::account_mnemonic_new(&mut rng)
                .map_err(|e| e.to_string())?;
            let (sk, pk) =
                lluma_crypto::account::derive_keypair_from_seed(&m).map_err(|e| e.to_string())?;
            lluma_client::Client::new(
                settings.relay_url.clone(),
                kc,
                sk,
                pk,
                lluma_core::wire::HostPublicKey(vec![0u8; 32]),
                [0u8; 32],
            )
        }
    };
    Ok(client::network_status(&client).await)
}

#[tauri::command]
async fn acquire_tokens(
    state: tauri::State<'_, AppState>,
    n: usize,
) -> Result<usize, String> {
    let mut inner = state.inner.lock().await;
    let Inner { settings, account, tokens, passphrase, .. } = &mut *inner;
    let acct = account.as_ref().ok_or("unlock your account first")?;
    let pass = passphrase.as_ref().ok_or("unlock your account first")?;
    let cli = client::build_client(settings, acct)?;
    client::acquire(&cli, tokens, &state.data_dir, pass, n).await
}

#[tauri::command]
async fn send_message(
    state: tauri::State<'_, AppState>,
    prompt: String,
) -> Result<ChatReply, String> {
    let mut inner = state.inner.lock().await;
    let Inner { settings, account, tokens, passphrase, .. } = &mut *inner;
    let acct = account.as_ref().ok_or("unlock your account first")?;
    let pass = passphrase.as_ref().ok_or("unlock your account first")?;
    let (_kc, registry_pk) = client::decode_settings(settings)?;
    let cli = client::build_client(settings, acct)?;
    client::send_message(&cli, tokens, &registry_pk, &state.data_dir, pass, &prompt).await
}

// ---- host (contribute) ----

#[tauri::command]
async fn host_start(state: tauri::State<'_, AppState>) -> Result<HostStatus, String> {
    let mut inner = state.inner.lock().await;
    if inner.account.is_none() {
        return Err("unlock your account first".into());
    }
    let pass = inner.passphrase.clone().ok_or("unlock your account first")?;
    let cfg = inner.settings.host.clone();
    let (host_sk, _host_pk) = host::load_or_create_host_key(&state.data_dir, &pass)?;
    let handle = HostHandle::start(&cfg, host_sk).await?;
    let status = handle.snapshot_status();
    inner.host = Some(handle);
    Ok(status)
}

#[tauri::command]
async fn host_stop(state: tauri::State<'_, AppState>) -> Result<HostStatus, String> {
    let mut inner = state.inner.lock().await;
    if let Some(h) = inner.host.take() {
        h.stop();
    }
    Ok(host::stopped_status())
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
            fetch_bootstrap,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lluma");
}
