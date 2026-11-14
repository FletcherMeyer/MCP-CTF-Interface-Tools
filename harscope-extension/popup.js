let TAB = null;

const $ = (id) => document.getElementById(id);

function setStatus(text, cls) {
  const s = $("status");
  if (!text) { s.style.display = "none"; return; }  // idle: show nothing
  s.style.display = "flex";
  $("msg").textContent = text;
  $("dot").className = "dot" + (cls ? " " + cls : "");
  s.classList.toggle("error", cls === "err");
}

function send(cmd, extra = {}) {
  return new Promise((res) => chrome.runtime.sendMessage({ cmd, tabId: TAB, ...extra }, res));
}

async function getCfg() {
  return chrome.storage.local.get(["bridgeUrl", "bridgeToken"]);
}

async function refresh() {
  const s = await send("status");
  if (s && s.capturing) {
    setStatus("Recording — " + s.count + " requests captured", "rec");
    $("start").disabled = true; $("stop").disabled = false;
  } else {
    setStatus("", "");  // idle: no text
    $("start").disabled = false; $("stop").disabled = true;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  TAB = tab ? tab.id : null;
  const cfg = await getCfg();
  $("url").value = cfg.bridgeUrl || "";
  $("token").value = cfg.bridgeToken || "";
  if (!cfg.bridgeUrl || !cfg.bridgeToken) $("cfg").open = true;
  // clicking the toolbar icon re-opens the on-page panel if it was closed
  if (TAB != null) {
    chrome.storage.local.set({ uiHidden: false });
    try { chrome.tabs.sendMessage(TAB, { cmd: "showTools" }, () => void chrome.runtime.lastError); } catch (e) { /* ignore */ }
  }
  refresh();
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

$("start").onclick = async () => {
  const cfg = await getCfg();
  if (!cfg.bridgeUrl || !cfg.bridgeToken) {
    $("cfg").open = true;
    setStatus("No bridge configured — set URL + token under “bridge connection”.", "err");
    return;
  }
  const r = await send("start");
  if (r && r.ok) {
    refresh();
  } else {
    setStatus("Couldn’t start capture: " + ((r && r.error) || "unknown error"), "err");
  }
};

$("stop").onclick = async () => { await send("stop"); refresh(); };

$("send").onclick = async () => {
  setStatus("Sending…", "on");
  const r = await send("send");
  if (r && r.ok) setStatus("Sent " + r.entries + " requests to the AI.", "on");
  else setStatus("Failed: " + (r ? r.error : "?"), "err");
};
