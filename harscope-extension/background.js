// harscope capture — service worker.
// Captures a tab's HTTP traffic via the DevTools Protocol (chrome.debugger),
// builds a HAR, and POSTs it to the local harscope bridge. Also polls the bridge
// for the AI's messages and relays them to the in-page panel.
// All network access is to 127.0.0.1/localhost only.

const PROTO = "1.3";
const caps = new Map();        // tabId -> { entries: Map(requestId -> item) }
const panelPorts = new Set();  // live ports from in-page panels
let pollTimer = null;
let lastMsgId = 0;

// ---------- config ----------
async function getConfig() {
  const d = await chrome.storage.local.get(["bridgeUrl", "bridgeToken"]);
  return { url: (d.bridgeUrl || "").replace(/\/+$/, ""), token: d.bridgeToken || "" };
}

// ---------- helpers ----------
function objToHeaders(obj) {
  if (!obj) return [];
  return Object.keys(obj).map((k) => ({ name: k, value: String(obj[k]) }));
}
function headerVal(obj, name) {
  if (!obj) return "";
  const k = Object.keys(obj).find((h) => h.toLowerCase() === name.toLowerCase());
  return k ? String(obj[k]) : "";
}
function parseQuery(url) {
  try {
    const u = new URL(url);
    return [...u.searchParams.entries()].map(([name, value]) => ({ name, value }));
  } catch (e) {
    return [];
  }
}

// ---------- capture lifecycle ----------
async function startCapture(tabId) {
  if (caps.has(tabId)) return;
  await chrome.debugger.attach({ tabId }, PROTO);
  await chrome.debugger.sendCommand({ tabId }, "Network.enable", {});
  caps.set(tabId, { entries: new Map() });
  setBadge(tabId, "REC");
}

async function stopCapture(tabId) {
  if (!caps.has(tabId)) return;
  try { await chrome.debugger.detach({ tabId }); } catch (e) { /* already gone */ }
  caps.delete(tabId);
  setBadge(tabId, "");
}

function setBadge(tabId, text) {
  try {
    chrome.action.setBadgeBackgroundColor({ color: "#c0392b" });
    chrome.action.setBadgeText({ tabId, text });
  } catch (e) { /* ignore */ }
}

chrome.debugger.onDetach.addListener((source) => {
  if (source.tabId != null) { caps.delete(source.tabId); setBadge(source.tabId, ""); }
});

chrome.debugger.onEvent.addListener((source, method, params) => {
  const tabId = source.tabId;
  const cap = caps.get(tabId);
  if (!cap) return;
  const E = cap.entries;
  if (method === "Network.requestWillBeSent") {
    if (E.has(params.requestId)) return; // keep the first (ignore redirect chains re-using id)
    E.set(params.requestId, {
      startedDateTime: new Date((params.wallTime ? params.wallTime * 1000 : Date.now())).toISOString(),
      request: params.request || {},
      response: null,
      content: null,
    });
  } else if (method === "Network.responseReceived") {
    const it = E.get(params.requestId);
    if (it) it.response = params.response || {};
  } else if (method === "Network.loadingFinished") {
    const it = E.get(params.requestId);
    if (!it) return;
    chrome.debugger.sendCommand({ tabId }, "Network.getResponseBody",
      { requestId: params.requestId }, (res) => {
        if (chrome.runtime.lastError || !res) return;
        it.content = { text: res.body || "", base64: !!res.base64Encoded };
      });
  }
});

function buildHar(tabId) {
  const cap = caps.get(tabId);
  const entries = [];
  if (cap) {
    for (const it of cap.entries.values()) {
      const req = it.request || {};
      const url = req.url || "";
      const postText = req.postData;
      const postData = (postText != null)
        ? { mimeType: headerVal(req.headers, "content-type") || "application/octet-stream", text: postText }
        : undefined;
      let response;
      if (it.response) {
        const rp = it.response;
        const content = { size: rp.encodedDataLength || 0, mimeType: rp.mimeType || "" };
        if (it.content) {
          content.text = it.content.text || "";
          if (it.content.base64) content.encoding = "base64";
        }
        response = {
          status: rp.status || 0, statusText: rp.statusText || "", httpVersion: "HTTP/1.1",
          headers: objToHeaders(rp.headers), cookies: [], content,
          redirectURL: "", headersSize: -1, bodySize: -1,
        };
      } else {
        response = {
          status: 0, statusText: "", httpVersion: "HTTP/1.1", headers: [], cookies: [],
          content: { size: 0, mimeType: "" }, redirectURL: "", headersSize: -1, bodySize: -1,
        };
      }
      const request = {
        method: req.method || "GET", url, httpVersion: "HTTP/1.1",
        headers: objToHeaders(req.headers), queryString: parseQuery(url), cookies: [],
        headersSize: -1, bodySize: postText ? String(postText).length : 0,
      };
      if (postData) request.postData = postData;
      entries.push({ startedDateTime: it.startedDateTime, time: 0, request, response,
                     cache: {}, timings: { send: 0, wait: 0, receive: 0 } });
    }
  }
  entries.sort((a, b) => (a.startedDateTime < b.startedDateTime ? -1 : 1));
  return { log: { version: "1.2", creator: { name: "harscope-ext", version: "0.1.0" }, entries } };
}

async function sendHar(tabId) {
  const { url, token } = await getConfig();
  if (!url || !token) return { ok: false, error: "Set bridge URL + token in the popup first." };
  const har = buildHar(tabId);
  const n = har.log.entries.length;
  if (!n) return { ok: false, error: "No requests captured yet. Start capture, browse, then Send." };
  let resp;
  try {
    resp = await fetch(url + "/har", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Harscope-Token": token, "X-Har-Name": "tab-" + tabId + ".har" },
      body: JSON.stringify(har),
    });
  } catch (e) {
    return { ok: false, error: "Cannot reach bridge at " + url + " (" + e + ")" };
  }
  if (!resp.ok) return { ok: false, error: "Bridge returned HTTP " + resp.status };
  return { ok: true, entries: n };
}

async function testConnection() {
  const { url, token } = await getConfig();
  if (!url) return { ok: false, error: "No bridge URL set." };
  try {
    const r = await fetch(url + "/ping");
    if (!r.ok) return { ok: false, error: "HTTP " + r.status };
    const j = await r.json();
    return { ok: true, service: j.service, hasToken: !!token };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

// ---------- popup / content messaging ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg.cmd === "status") {
        const tabId = msg.tabId;
        sendResponse({ ok: true, capturing: caps.has(tabId),
                       count: caps.get(tabId)?.entries.size || 0 });
      } else if (msg.cmd === "test") {
        sendResponse(await testConnection());
      } else if (msg.cmd === "start") {
        await startCapture(msg.tabId); sendResponse({ ok: true });
      } else if (msg.cmd === "stop") {
        await stopCapture(msg.tabId); sendResponse({ ok: true });
      } else if (msg.cmd === "send") {
        sendResponse(await sendHar(msg.tabId));
      } else if (msg.cmd === "sendActive") {
        const tabId = sender.tab ? sender.tab.id : msg.tabId;
        sendResponse(await sendHar(tabId));
      } else {
        sendResponse({ ok: false, error: "unknown command" });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true; // async response
});

// ---------- panel polling (kept alive while a panel port is connected) ----------
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "harscope-panel") return;
  panelPorts.add(port);
  startPolling();
  port.onDisconnect.addListener(() => {
    panelPorts.delete(port);
    if (panelPorts.size === 0) stopPolling();
  });
});

function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(pollMessages, 2000);
  pollMessages();
}
function stopPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}
async function pollMessages() {
  const { url, token } = await getConfig();
  if (!url || !token || panelPorts.size === 0) return;
  let data;
  try {
    const r = await fetch(url + "/messages?since=" + lastMsgId, { headers: { "X-Harscope-Token": token } });
    if (!r.ok) return;
    data = await r.json();
  } catch (e) { return; }
  for (const m of (data.messages || [])) {
    lastMsgId = Math.max(lastMsgId, m.id);
    for (const p of panelPorts) { try { p.postMessage({ msg: m }); } catch (e) { /* ignore */ } }
  }
}
