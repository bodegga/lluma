// Lluma desktop UI wiring. Talks to the Rust command layer via the global
// Tauri API (withGlobalTauri). Every command call is wrapped so a returned
// Err(String) surfaces as an inline message or toast, never a silent failure.

const invoke = window.__TAURI__?.core?.invoke;

const $ = (id) => document.getElementById(id);
const show = (el, on) => el && el.classList.toggle("hidden", !on);

async function call(cmd, args) {
  if (!invoke) throw new Error("Tauri bridge unavailable");
  return invoke(cmd, args);
}

function toast(msg, kind = "info") {
  const t = $("toast");
  t.textContent = msg;
  t.className = `toast ${kind}`;
  requestAnimationFrame(() => t.classList.remove("hidden"));
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.add("hidden"), 3200);
}

// ---- tab switching ----
function switchTab(name) {
  document.querySelectorAll(".nav-item").forEach((b) =>
    b.classList.toggle("active", b.dataset.tab === name)
  );
  document.querySelectorAll(".panel").forEach((p) =>
    p.classList.toggle("active", p.id === `panel-${name}`)
  );
  if (name === "status") refreshStatus();
  if (name === "contribute") refreshHost();
}

document.querySelectorAll(".nav-item").forEach((b) =>
  b.addEventListener("click", () => switchTab(b.dataset.tab))
);
document.querySelectorAll("[data-goto]").forEach((b) =>
  b.addEventListener("click", () => switchTab(b.dataset.goto))
);

// ---- shared account/balance state ----
let acct = { has_account: false, unlocked: false, account_id_hex: "", balance: 0 };

function renderAccount() {
  $("rail-bal-val").textContent = acct.unlocked ? acct.balance : "—";
  $("chat-balance").textContent = `${acct.unlocked ? acct.balance : "—"} credits`;
  $("stat-balance").textContent = acct.unlocked ? acct.balance : "—";
  $("stat-locked").textContent = acct.unlocked ? "unlocked" : (acct.has_account ? "locked" : "no account");
  $("account-id").textContent = acct.account_id_hex || (acct.has_account ? "locked — unlock in Settings" : "no account yet");

  // Chat availability
  const canChat = acct.unlocked && acct.balance > 0;
  $("prompt").disabled = !canChat;
  $("send-btn").disabled = !canChat;

  // Adaptive guidance banner (Chat) — steer a new user to the exact next step.
  let banner = null;
  if (!acct.has_account) {
    banner = { title: "No account yet.", sub: "Create an anonymous account to get started — it's sealed on this device with your passphrase.", label: "Create account" };
  } else if (!acct.unlocked) {
    banner = { title: "Account locked.", sub: "Unlock your account with your passphrase to start chatting.", label: "Unlock" };
  } else if (acct.balance === 0) {
    banner = { title: "No credits yet.", sub: "Copy your account id from Status and ask your operator to grant credits, then Acquire tokens in Settings.", label: "Acquire tokens" };
  }
  show($("fund-banner"), !!banner);
  if (banner) {
    $("fund-title").textContent = banner.title;
    $("fund-sub").textContent = banner.sub;
    $("fund-cta").textContent = banner.label;
  }

  // Status account-id card: adaptive action + copy visibility.
  const cta = $("acct-cta");
  if (!acct.has_account) { cta.textContent = "Create account"; show(cta, true); show($("copy-id"), false); }
  else if (!acct.unlocked) { cta.textContent = "Unlock"; show(cta, true); show($("copy-id"), false); }
  else { show(cta, false); show($("copy-id"), true); }

  $("thread-empty") && show($("thread-empty"), $("thread").childElementCount <= 1);

  // Settings account section
  $("acct-state").textContent = acct.unlocked ? "unlocked" : (acct.has_account ? "locked" : "no account");
  show($("acct-none"), !acct.has_account);
  show($("acct-locked"), acct.has_account && !acct.unlocked);
  show($("acct-unlocked"), acct.unlocked);
  if (acct.unlocked) $("set-account-id").textContent = acct.account_id_hex;
}

async function refreshAccount() {
  try {
    acct = await call("account_status");
    renderAccount();
  } catch (e) { /* leave defaults */ }
}

// ---- network status ----
function dot(el, state) { // state: ok | warn | bad
  el.className = `dot ${state}`;
}

// Reflect connection state in the Settings "Network" card. When the endpoints
// needed to connect are missing, reveal the Advanced section so the next step
// is visible — but never silently trust the relay for them.
function updateConn(reachable, message) {
  const needsEndpoints = !$("set-gwkc").value.trim() || !$("set-regpk").value.trim();
  dot($("conn-dot"), reachable ? "ok" : (needsEndpoints ? "warn" : "bad"));
  $("conn-text").textContent = reachable ? "connected" : (needsEndpoints ? "not configured" : "offline");
  $("conn-hint").textContent = reachable
    ? "Connected to the network."
    : (needsEndpoints
        ? "This relay needs a gateway key-config + registry pubkey to connect. Add them under Advanced."
        : (message || "Relay unreachable."));
  if (!reachable && needsEndpoints) $("advanced-endpoints").open = true;
}

async function refreshStatus() {
  $("net-val").textContent = "…";
  try {
    const ns = await call("network_status");
    dot($("net-dot"), ns.reachable ? "ok" : "bad");
    dot($("rail-net-dot"), ns.reachable ? "ok" : "bad");
    $("net-val").textContent = ns.reachable ? "connected" : "offline";
    $("rail-net-label").textContent = ns.reachable ? "connected" : "offline";
    $("net-latency").textContent = `${ns.latency_ms} ms`;
    $("net-epoch").textContent = ns.reachable ? ns.epoch : "—";
    $("net-denom").textContent = ns.reachable ? `denom ${ns.denomination}` : "denom —";
    if (!ns.reachable) $("net-latency").textContent = ns.message;
    updateConn(ns.reachable, ns.message);
  } catch (e) {
    dot($("net-dot"), "bad"); dot($("rail-net-dot"), "bad");
    $("net-val").textContent = "offline";
    $("rail-net-label").textContent = "offline";
    $("net-latency").textContent = String(e);
    updateConn(false, String(e));
  }
  await refreshAccount();
}

$("refresh-status").addEventListener("click", refreshStatus);

// Explicit connect: save the current relay + endpoints, then probe.
$("connect-btn").addEventListener("click", async () => {
  $("settings-msg").textContent = "Connecting…";
  try {
    const base = await call("get_settings");
    await call("set_settings", { settings: currentSettingsFromForm(base) });
    await refreshStatus();
    $("settings-msg").textContent = "";
  } catch (e) { $("settings-msg").textContent = String(e); }
});

$("copy-id").addEventListener("click", () => {
  if (acct.account_id_hex) { navigator.clipboard.writeText(acct.account_id_hex); toast("Account id copied"); }
});

// Jump to Settings and focus the field that matches the current account state.
function gotoAccountStep() {
  switchTab("settings");
  setTimeout(() => {
    const el = !acct.has_account ? $("acct-pass")
      : (!acct.unlocked ? $("unlock-pass") : $("acquire-n"));
    el?.focus();
    el?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, 40);
}
$("acct-cta").addEventListener("click", gotoAccountStep);
$("fund-cta").addEventListener("click", gotoAccountStep);

// ---- chat ----
function addBubble(role, text) {
  $("thread-empty")?.remove();
  const b = document.createElement("div");
  b.className = `bubble ${role}`;
  b.textContent = text;
  $("thread").appendChild(b);
  $("thread").scrollTop = $("thread").scrollHeight;
  return b;
}

const composer = $("composer");
const prompt = $("prompt");
prompt.addEventListener("input", () => {
  prompt.style.height = "auto";
  prompt.style.height = Math.min(prompt.scrollHeight, 160) + "px";
});
prompt.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); composer.requestSubmit(); }
});

composer.addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = prompt.value.trim();
  if (!text) return;
  addBubble("user", text);
  prompt.value = ""; prompt.style.height = "auto";
  const pending = addBubble("host pending", "…");
  $("send-btn").disabled = true;
  try {
    const reply = await call("send_message", { prompt: text });
    pending.classList.remove("pending");
    pending.textContent = reply.answer;
    acct.balance = reply.balance;
    renderAccount();
  } catch (err) {
    pending.classList.remove("pending");
    pending.classList.add("error");
    pending.textContent = String(err);
  } finally {
    $("send-btn").disabled = false;
    renderAccount();
  }
});

// ---- settings: endpoints ----
async function loadSettings() {
  try {
    const s = await call("get_settings");
    $("set-relay").value = s.relay_url || "";
    $("set-gwkc").value = s.gateway_kc_b64 || "";
    $("set-regpk").value = s.registry_pk_b64 || "";
    // host config
    $("host-upstream").value = s.host?.upstream || "open_ai";
    $("host-openai-base").value = s.host?.openai_base || "";
    $("host-openai-model").value = s.host?.openai_model || "";
    $("host-openai-key").value = s.host?.openai_api_key || "";
    $("host-ingress").value = s.host?.ingress_addr || "";
    $("host-model-id").value = s.host?.model_id || "";
    toggleOpenAiFields();
    return s;
  } catch (e) { toast(String(e), "error"); return null; }
}

function currentSettingsFromForm(base) {
  return {
    relay_url: $("set-relay").value.trim(),
    gateway_kc_b64: $("set-gwkc").value.trim(),
    registry_pk_b64: $("set-regpk").value.trim(),
    issuer_key_id_hex: base?.issuer_key_id_hex || "",
    host: {
      upstream: $("host-upstream").value,
      ingress_addr: $("host-ingress").value.trim(),
      openai_base: $("host-openai-base").value.trim(),
      openai_model: $("host-openai-model").value.trim(),
      openai_api_key: $("host-openai-key").value,
      broker_ingress: base?.host?.broker_ingress || "",
      epoch_salt_b64: base?.host?.epoch_salt_b64 || "",
      pow_difficulty: base?.host?.pow_difficulty || 0,
      model_id: $("host-model-id").value.trim(),
    },
  };
}

$("save-settings").addEventListener("click", async () => {
  try {
    const base = await call("get_settings");
    await call("set_settings", { settings: currentSettingsFromForm(base) });
    $("settings-msg").textContent = "Saved.";
    toast("Settings saved");
    refreshStatus();
  } catch (e) { $("settings-msg").textContent = String(e); }
});

$("fetch-bootstrap").addEventListener("click", async () => {
  try {
    const s = await call("fetch_bootstrap");
    $("set-gwkc").value = s.gateway_kc_b64 || "";
    $("set-regpk").value = s.registry_pk_b64 || "";
    toast("Fetched endpoint material from relay");
  } catch (e) { toast(String(e), "error"); }
});

// ---- account actions ----
function showPhrase(newAcct) {
  $("phrase-box").textContent = newAcct.recovery_phrase;
  show($("phrase-modal"), true);
}
$("phrase-copy").addEventListener("click", () => {
  navigator.clipboard.writeText($("phrase-box").textContent); toast("Phrase copied");
});
$("phrase-done").addEventListener("click", () => show($("phrase-modal"), false));

$("acct-create").addEventListener("click", async () => {
  const pass = $("acct-pass").value;
  if (!pass) { $("acct-pass").focus(); return toast("Choose a passphrase", "error"); }
  try {
    const na = await call("create_account", { passphrase: pass });
    showPhrase(na);
    $("acct-pass").value = "";
    await refreshAccount();
    toast("Account created");
  } catch (e) { toast(String(e), "error"); }
});

$("acct-import").addEventListener("click", async () => {
  const pass = $("acct-pass").value;
  const phrase = $("acct-phrase").value.trim();
  if (!pass || !phrase) return toast("Enter a phrase and a passphrase", "error");
  try {
    const na = await call("import_account", { phrase, passphrase: pass });
    showPhrase(na);
    $("acct-pass").value = ""; $("acct-phrase").value = "";
    await refreshAccount();
    toast("Account imported");
  } catch (e) { toast(String(e), "error"); }
});

$("acct-unlock").addEventListener("click", async () => {
  try {
    acct = await call("unlock", { passphrase: $("unlock-pass").value });
    $("unlock-pass").value = "";
    renderAccount();
    toast("Unlocked");
  } catch (e) { toast(String(e), "error"); }
});

$("acct-lock").addEventListener("click", async () => {
  try { await call("lock"); await refreshAccount(); toast("Locked"); } catch (e) { toast(String(e), "error"); }
});

$("acquire-btn").addEventListener("click", async () => {
  const n = parseInt($("acquire-n").value, 10) || 1;
  $("acct-msg").textContent = "Acquiring…";
  try {
    const bal = await call("acquire_tokens", { n });
    acct.balance = bal; renderAccount();
    $("acct-msg").textContent = `Balance: ${bal} credits.`;
    toast(`Acquired — ${bal} credits`);
  } catch (e) { $("acct-msg").textContent = String(e); }
});

// ---- host / contribute ----
function toggleOpenAiFields() {
  show($("openai-fields"), $("host-upstream").value === "open_ai");
}
$("host-upstream").addEventListener("change", toggleOpenAiFields);

function renderHost(hs) {
  dot($("host-dot"), hs.running ? (hs.reachable ? "ok" : "warn") : "bad");
  $("host-state").textContent = hs.state;
  $("host-reach").textContent = hs.running ? (hs.reachable ? "yes" : "no") : "—";
  $("host-served").textContent = hs.requests_served;
  $("host-earned").textContent = hs.credits_earned;
  $("host-msg").textContent = hs.message || "";
}

async function refreshHost() {
  try { renderHost(await call("host_status")); } catch (e) { /* ignore */ }
}

$("host-start").addEventListener("click", async () => {
  // Persist host config first so the backend serves with current form values.
  try {
    const base = await call("get_settings");
    await call("set_settings", { settings: currentSettingsFromForm(base) });
    renderHost(await call("host_start"));
    toast("Host started");
  } catch (e) { $("host-msg").textContent = String(e); toast(String(e), "error"); }
});

$("host-stop").addEventListener("click", async () => {
  try { renderHost(await call("host_stop")); toast("Host stopped"); } catch (e) { toast(String(e), "error"); }
});

// ---- boot ----
(async function boot() {
  if (!invoke) { toast("Tauri bridge unavailable — run inside the app", "error"); return; }
  await loadSettings();
  await refreshAccount();
  await refreshStatus();
  // First run with no account: land on Settings so creating one is the obvious step.
  if (!acct.has_account) gotoAccountStep();
  setInterval(() => {
    if ($("panel-contribute").classList.contains("active")) refreshHost();
  }, 4000);
})();
