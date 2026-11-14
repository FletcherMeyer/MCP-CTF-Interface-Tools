// screenscope — service worker.
// Captures the active tab ~1x/sec, crops to the user's capture box, and POSTs the
// cropped image to the local screenscope bridge. Also polls the bridge for the AI's
// updates and relays them to the in-page panel. Localhost only.

const INTERVAL_MS = 1100;
const tabs = new Map();      // tabId -> { recording, rect, dpr, paused, lastB64 }
const panelPorts = new Set();
let captureTimer = null;
let recordingTab = null;
let pollTimer = null;
let lastMsgId = 0;

async function getConfig() {
  const d = await chrome.storage.local.get(["bridgeUrl", "bridgeToken"]);
  return { url: (d.bridgeUrl || "").replace(/\/+$/, ""), token: d.bridgeToken || "" };
}

// tell the bridge the stream started/ended (so watch_screen can end on Stop)
async function postStream(active) {
  const { url, token } = await getConfig();
  if (!url || !token) return;
  try {
    await fetch(url + "/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Screenscope-Token": token },
      body: JSON.stringify({ active: !!active }),
    });
  } catch (e) { /* ignore */ }
}
function st(tabId) {
  if (!tabs.has(tabId)) tabs.set(tabId, { recording: false, rect: null, dpr: 1, paused: false, lastB64: "" });
  return tabs.get(tabId);
}

// ---- cropping (OffscreenCanvas in the worker) ----
async function cropToBase64(dataUrl, rect, dpr) {
  const blob = await (await fetch(dataUrl)).blob();
  const bmp = await createImageBitmap(blob);
  let sx = Math.round(rect.x * dpr), sy = Math.round(rect.y * dpr);
  let sw = Math.max(1, Math.round(rect.w * dpr)), sh = Math.max(1, Math.round(rect.h * dpr));
  sx = Math.min(Math.max(0, sx), bmp.width - 1);
  sy = Math.min(Math.max(0, sy), bmp.height - 1);
  sw = Math.min(sw, bmp.width - sx);
  sh = Math.min(sh, bmp.height - sy);
  const canvas = new OffscreenCanvas(sw, sh);
  canvas.getContext("2d").drawImage(bmp, sx, sy, sw, sh, 0, 0, sw, sh);
  bmp.close();
  const out = await canvas.convertToBlob({ type: "image/jpeg", quality: 0.72 });
  const arr = new Uint8Array(await out.arrayBuffer());
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}

async function tick() {
  const tabId = recordingTab;
  if (tabId == null) return;
  const s = st(tabId);
  if (!s.recording || s.paused || !s.rect) return;
  const cfg = await getConfig();
  if (!cfg.url || !cfg.token) return;
  let tab;
  try { tab = await chrome.tabs.get(tabId); } catch (e) { return; }
  // only the active, visible tab can be captured
  const [active] = await chrome.tabs.query({ active: true, windowId: tab.windowId });
  if (!active || active.id !== tabId) return;
  let dataUrl;
  try {
    dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "jpeg", quality: 80 });
  } catch (e) { return; }
  let b64;
  try { b64 = await cropToBase64(dataUrl, s.rect, s.dpr); } catch (e) { return; }
  if (b64 === s.lastB64) return;   // unchanged frame — don't resend
  s.lastB64 = b64;
  let resp;
  try {
    resp = await fetch(cfg.url + "/frame", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Screenscope-Token": cfg.token },
      body: JSON.stringify({ img: b64, fmt: "jpeg" }),
    });
  } catch (e) { return; }  // bridge down — ignore this tick
  if (resp && resp.ok) {
    // ACK: the bridge confirmed receipt — surface it to the user in the box bar
    s.sent = (s.sent || 0) + 1;
    let seq = 0;
    try { seq = (await resp.json()).seq || 0; } catch (e) { /* ignore */ }
    try { chrome.tabs.sendMessage(tabId, { cmd: "ack", seq, sent: s.sent }, () => void chrome.runtime.lastError); } catch (e) { /* ignore */ }
  }
}

function startLoop(tabId) {
  recordingTab = tabId;
  const s = st(tabId);
  s.recording = true;
  s.lastB64 = "";
  s.sent = 0;
  postStream(true);
  if (!captureTimer) captureTimer = setInterval(tick, INTERVAL_MS);
  tick();
}
function stopLoop(tabId) {
  if (tabs.has(tabId)) tabs.get(tabId).recording = false;
  if (recordingTab === tabId) recordingTab = null;
  if (captureTimer) { clearInterval(captureTimer); captureTimer = null; }
  postStream(false);   // tell the bridge the stream ended -> watch_screen stops
  setBadge(tabId, "");
}
function setBadge(tabId, text) {
  try {
    chrome.action.setBadgeBackgroundColor({ color: "#7c3aed" });
    chrome.action.setBadgeText({ tabId, text });
  } catch (e) { /* ignore */ }
}

async function testConnection() {
  const { url, token } = await getConfig();
  if (!url) return { ok: false, error: "No bridge URL set." };
  try {
    const r = await fetch(url + "/ping");
    if (!r.ok) return { ok: false, error: "HTTP " + r.status };
    const j = await r.json();
    return { ok: true, service: j.service, hasToken: !!token };
  } catch (e) { return { ok: false, error: String(e) }; }
}

// ---- messaging ----
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    const tabId = sender.tab ? sender.tab.id : msg.tabId;
    try {
      if (msg.cmd === "rect") {
        const s = st(tabId); s.rect = msg.rect; s.dpr = msg.dpr || 1;
        sendResponse({ ok: true });
      } else if (msg.cmd === "paused") {
        st(tabId).paused = !!msg.paused; sendResponse({ ok: true });
      } else if (msg.cmd === "status") {
        const s = st(msg.tabId);
        sendResponse({ ok: true, recording: s.recording, haveRect: !!s.rect });
      } else if (msg.cmd === "test") {
        sendResponse(await testConnection());
      } else if (msg.cmd === "start") {
        const s = st(msg.tabId);
        if (!s.rect) { sendResponse({ ok: false, error: "No capture box on this tab yet." }); return; }
        startLoop(msg.tabId); setBadge(msg.tabId, "REC");
        sendResponse({ ok: true });
      } else if (msg.cmd === "stop") {
        stopLoop(msg.tabId); sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false, error: "unknown command" });
      }
    } catch (e) { sendResponse({ ok: false, error: String(e) }); }
  })();
  return true;
});

// ---- panel polling (keeps SW alive while a panel is connected) ----
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "screenscope-panel") return;
  panelPorts.add(port);
  startPolling();
  port.onDisconnect.addListener(() => {
    panelPorts.delete(port);
    if (panelPorts.size === 0) stopPolling();
  });
});
function startPolling() { if (!pollTimer) { pollTimer = setInterval(pollMessages, 1500); pollMessages(); } }
function stopPolling() { if (pollTimer) clearInterval(pollTimer); pollTimer = null; }
async function pollMessages() {
  const { url, token } = await getConfig();
  if (!url || !token || panelPorts.size === 0) return;
  try {
    const r = await fetch(url + "/messages?since=" + lastMsgId, { headers: { "X-Screenscope-Token": token } });
    if (!r.ok) return;
    const data = await r.json();
    for (const m of (data.messages || [])) {
      lastMsgId = Math.max(lastMsgId, m.id);
      for (const p of panelPorts) { try { p.postMessage({ msg: m }); } catch (e) { /* ignore */ } }
    }
  } catch (e) { /* ignore */ }
}

chrome.tabs.onRemoved.addListener((tabId) => { stopLoop(tabId); tabs.delete(tabId); });
