const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

function showTab(name) {
  document.getElementById("panel-contribute").classList.toggle("hidden", name !== "contribute");
  document.getElementById("panel-chat").classList.toggle("hidden", name !== "chat");
  document.getElementById("tab-contribute").classList.toggle("active", name === "contribute");
  document.getElementById("tab-chat").classList.toggle("active", name === "chat");
}
document.getElementById("tab-contribute").onclick = () => showTab("contribute");
document.getElementById("tab-chat").onclick = () => showTab("chat");

function fmtGB(bytes) {
  return (bytes / 1e9).toFixed(1) + " GB";
}

document.getElementById("btn-detect").onclick = async () => {
  const hw = await invoke("detect_hardware_cmd");
  const vram = hw.vram_bytes ? fmtGB(hw.vram_bytes) : "n/a";
  document.getElementById("hw").textContent =
    `RAM ${fmtGB(hw.ram_bytes)} · VRAM ${vram} · ${hw.cpu_cores} cores · disk free ${fmtGB(hw.disk_free_bytes)}`;
};

document.getElementById("btn-recommend").onclick = async () => {
  try {
    const rec = await invoke("recommend_model_cmd");
    document.getElementById("rec").textContent =
      `Recommended: ${rec.spec.display_name} (${rec.spec.quant}) — ${rec.reason}`;
  } catch (e) {
    document.getElementById("rec").textContent = `No recommendation: ${e}`;
  }
};

const output = document.getElementById("output");
await listen("token", (e) => { output.textContent += e.payload.text; });
await listen("done", () => { output.textContent += "\n"; });
await listen("error", (e) => { output.textContent += `\n[error] ${e.payload}\n`; });

document.getElementById("chat-form").onsubmit = async (ev) => {
  ev.preventDefault();
  const input = document.getElementById("prompt");
  const prompt = input.value.trim();
  if (!prompt) return;
  output.textContent += `\n> ${prompt}\n`;
  input.value = "";
  await invoke("start_generate", { prompt });
};
