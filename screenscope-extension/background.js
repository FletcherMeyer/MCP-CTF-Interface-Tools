// screenscope — service worker (MANUAL capture).
// Nothing is streamed automatically. When the user clicks "Send frame", this grabs
// the active tab, crops to the capture box, and POSTs the image to the local bridge
// (one frame per click). It also relays the AI's panel messages. Localhost only.

const tabs = new Map();      // tabId -> { rect, dpr, sent }
const panelPorts = new Set();
let pollTimer = null;
let lastMsgId = 0;

async function getConfig() {
  const d = await chrome.storage.local.get(["bridgeUrl", "bridgeToken"]);
  return { url: (d.bridgeUrl || "").replace(/\/+$/, ""), token: d.bridgeToken || "" };
}
function st(tabId) {
  if (!tabs.has(tabId)) tabs.set(tabId, { rect: null, dpr: 1, sent: 0 });
  return tabs.get(tabId);
}

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

// crop the captured viewport to the box rect, return base64 jpeg
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
  const out = await canvas.convertToBlob({ type: "image/jpeg", quality: 0.82 });
  const arr = new Uint8Array(await out.arrayBuffer());
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}

// capture + send ONE frame (on a button click)
async function sendFrame(tabId) {
  const s = st(tabId);
  if (!s.rect) return { ok: false, error: "No capture box on this tab — reload the page, then frame the console." };
  const cfg = await getConfig();
  if (!cfg.url || !cfg.token) return { ok: false, error: "No bridge configured — set URL + token first." };
  let tab;
  try { tab = await chrome.tabs.get(tabId); } catch (e) { return { ok: false, error: "tab not found" }; }
  const [active] = await chrome.tabs.query({ active: true, windowId: tab.windowId });
  if (!active || active.id !== tabId) return { ok: false, error: "This tab isn't the active/focused tab." };
  let dataUrl;
  try { dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "jpeg", quality: 90 }); }
  catch (e) { return { ok: false, error: "capture failed: " + e }; }
  let b64;
  try { b64 = await cropToBase64(dataUrl, s.rect, s.dpr); } catch (e) { return { ok: false, error: "crop failed" }; }
  await postStream(true);  // mark the session active so watch_screen keeps awaiting
  let resp;
  try {
    resp = await fetch(cfg.url + "/frame", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Screenscope-Token": cfg.token },
      body: JSON.stringify({ img: b64, fmt: "jpeg" }),
    });
  } catch (e) { return { ok: false, error: "bridge unreachable at " + cfg.url }; }
  if (!resp || !resp.ok) return { ok: false, error: "bridge HTTP " + (resp ? resp.status : "?") };
  s.sent = (s.sent || 0) + 1;
  let seq = 0;
  try { seq = (await resp.json()).seq || 0; } catch (e) { /* ignore */ }
  // ACK -> show the user a live "sent" count in the box bar
  try { chrome.tabs.sendMessage(tabId, { cmd: "ack", seq, sent: s.sent }, () => void chrome.runtime.lastError); } catch (e) { /* ignore */ }
  setBadge(tabId, String(s.sent));
  return { ok: true, seq, sent: s.sent };
}

async function endSession(tabId) {
  await postStream(false);   // -> watch_screen returns SESSION ENDED
  setBadge(tabId, "");
  return { ok: true };
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

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    const senderTab = sender.tab ? sender.tab.id : msg.tabId;
    try {
      if (msg.cmd === "rect") {
        const s = st(senderTab); s.rect = msg.rect; s.dpr = msg.dpr || 1;
        sendResponse({ ok: true });
      } else if (msg.cmd === "status") {
        const s = st(msg.tabId);
        sendResponse({ ok: true, sent: s.sent || 0, haveRect: !!s.rect });
      } else if (msg.cmd === "test") {
        sendResponse(await testConnection());
      } else if (msg.cmd === "sendFrame") {
        sendResponse(await sendFrame(msg.tabId));
      } else if (msg.cmd === "sendActive") {           // from the box's own Send button
        sendResponse(await sendFrame(senderTab));
      } else if (msg.cmd === "end") {
        sendResponse(await endSession(senderTab));
      } else {
        sendResponse({ ok: false, error: "unknown command" });
      }
    } catch (e) { sendResponse({ ok: false, error: String(e) }); }
  })();
  return true;
});

// keep the panel's AI messages flowing (service worker alive while a panel is open)
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

chrome.tabs.onRemoved.addListener((tabId) => { tabs.delete(tabId); });
