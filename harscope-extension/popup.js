let TAB = null;

const $ = (id) => document.getElementById(id);
function setStatus(text, cls) {
  $("msg").textContent = text;
  $("dot").className = "dot" + (cls ? " " + cls : "");
}
function send(cmd, extra = {}) {
  return new Promise((res) => chrome.runtime.sendMessage({ cmd, tabId: TAB, ...extra }, res));
}

async function refresh() {
  const s = await send("status");
  if (s && s.capturing) {
    setStatus("Recording — " + s.count + " requests captured", "rec");
    $("start").disabled = true; $("stop").disabled = false;
  } else {
    setStatus("Idle. Start capture, browse the challenge, then Send.", "");
    $("start").disabled = false; $("stop").disabled = true;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  TAB = tab ? tab.id : null;
  const cfg = await chrome.storage.local.get(["bridgeUrl", "bridgeToken"]);
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
  setStatus("Testing…", "");
  const r = await send("test");
  if (r && r.ok) setStatus("Connected to " + (r.service || "bridge") + (r.hasToken ? "" : " (no token!)"), "on");
  else setStatus("Not reachable: " + (r ? r.error : "?"), "");
};
$("start").onclick = async () => { await send("start"); refresh(); };
$("stop").onclick = async () => { await send("stop"); refresh(); };
$("send").onclick = async () => {
  setStatus("Sending…", "");
  const r = await send("send");
  if (r && r.ok) setStatus("Sent " + r.entries + " requests to the AI.", "on");
  else setStatus("Failed: " + (r ? r.error : "?"), "");
};
