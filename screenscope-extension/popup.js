let TAB = null;
const $ = (id) => document.getElementById(id);

function setStatus(text, cls) {
  const s = $("status");
  if (!text) { s.style.display = "none"; return; }
  s.style.display = "flex";
  $("msg").textContent = text;
  $("dot").className = "dot" + (cls ? " " + cls : "");
  s.classList.toggle("error", cls === "err");
}
function send(cmd, extra = {}) {
  return new Promise((res) => chrome.runtime.sendMessage({ cmd, tabId: TAB, ...extra }, res));
}
async function getCfg() { return chrome.storage.local.get(["bridgeUrl", "bridgeToken"]); }

document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  TAB = tab ? tab.id : null;
  const cfg = await getCfg();
  $("url").value = cfg.bridgeUrl || "";
  $("token").value = cfg.bridgeToken || "";
  if (!cfg.bridgeUrl || !cfg.bridgeToken) $("cfg").open = true;
  // re-open the on-page tools if they were closed
  if (TAB != null) {
    chrome.storage.local.set({ ssBoxHidden: false, ssPanelHidden: false });
    try { chrome.tabs.sendMessage(TAB, { cmd: "showTools" }, () => void chrome.runtime.lastError); } catch (e) { /* ignore */ }
  }
  const s = await send("status");
  if (s && s.sent) setStatus(s.sent + " frame(s) sent this session", "on");
});

$("save").onclick = async () => {
  await chrome.storage.local.set({ bridgeUrl: $("url").value.trim(), bridgeToken: $("token").value.trim() });
  setStatus("Saved.", "on");
};
$("test").onclick = async () => {
  await chrome.storage.local.set({ bridgeUrl: $("url").value.trim(), bridgeToken: $("token").value.trim() });
  setStatus("Testing…", "on");
  const r = await send("test");
  if (r && r.ok) setStatus("Connected to " + (r.service || "bridge") + (r.hasToken ? "" : " (no token!)"), "on");
  else setStatus("Not reachable: " + (r ? r.error : "?"), "err");
};
$("send").onclick = async () => {
  const cfg = await getCfg();
  if (!cfg.bridgeUrl || !cfg.bridgeToken) {
    $("cfg").open = true;
    setStatus("No bridge configured — set URL + token under “bridge connection”.", "err");
    return;
  }
  setStatus("Sending…", "on");
  const r = await send("sendFrame");
  if (r && r.ok) setStatus("✓ Sent frame #" + r.seq + " (" + r.sent + " this session)", "on");
  else setStatus("Send failed: " + ((r && r.error) || "?"), "err");
};
$("end").onclick = async () => {
  await send("end");
  setStatus("Session ended — the AI will stop awaiting.", "on");
};
