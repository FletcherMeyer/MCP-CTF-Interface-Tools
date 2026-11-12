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

async function refresh() {
  const s = await send("status");
  if (s && s.recording) {
    setStatus("Reading — streaming the framed region ~1×/sec", "rec");
    $("start").disabled = true; $("stop").disabled = false;
  } else {
    setStatus("", ""); $("start").disabled = false; $("stop").disabled = true;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  TAB = tab ? tab.id : null;
  const cfg = await getCfg();
  $("url").value = cfg.bridgeUrl || "";
  $("token").value = cfg.bridgeToken || "";
  if (!cfg.bridgeUrl || !cfg.bridgeToken) $("cfg").open = true;
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
  if (r && r.ok) refresh();
  else setStatus("Couldn’t start: " + ((r && r.error) || "unknown error")
                 + (r && /capture box/.test(r.error || "") ? " — open the page and position the frame." : ""), "err");
};
$("stop").onclick = async () => { await send("stop"); refresh(); };
