// harscope in-page panel: a small, draggable, minimizable box that shows the AI's
// answers and action requests. Controls (start/stop/send) live in the toolbar popup.
(function () {
  if (window.__harscopePanel) return;
  window.__harscopePanel = true;

  const panel = document.createElement("div");
  panel.id = "harscope-panel";
  panel.classList.add("hs-min");
  panel.innerHTML =
    '<div id="hs-head">' +
      '<span id="hs-title">harscope</span>' +
      '<span id="hs-actions">' +
        '<button id="hs-send" title="Send this tab\'s capture to the AI">send</button>' +
        '<button id="hs-toggle" title="minimize / expand">—</button>' +
      '</span>' +
    '</div>' +
    '<div id="hs-body"><div id="hs-empty">Idle. Capture a tab from the toolbar, then answers appear here.</div></div>';
  (document.body || document.documentElement).appendChild(panel);

  const head = panel.querySelector("#hs-head");
  const body = panel.querySelector("#hs-body");

  // minimize / expand
  panel.querySelector("#hs-toggle").addEventListener("click", (e) => {
    e.stopPropagation();
    panel.classList.toggle("hs-min");
  });

  // send current tab's capture
  panel.querySelector("#hs-send").addEventListener("click", (e) => {
    e.stopPropagation();
    chrome.runtime.sendMessage({ cmd: "sendActive" }, (r) => {
      addMsg({ type: "system", text: (r && r.ok) ? ("Sent " + r.entries + " requests.") : ("Send failed: " + (r ? r.error : "?")) });
    });
  });

  // dragging by the header
  let drag = null;
  head.addEventListener("mousedown", (e) => {
    if (e.target.tagName === "BUTTON") return;
    const r = panel.getBoundingClientRect();
    drag = { x: e.clientX, y: e.clientY, left: r.left, top: r.top };
    e.preventDefault();
  });
  window.addEventListener("mousemove", (e) => {
    if (!drag) return;
    panel.style.left = Math.max(0, drag.left + (e.clientX - drag.x)) + "px";
    panel.style.top = Math.max(0, drag.top + (e.clientY - drag.y)) + "px";
    panel.style.right = "auto";
    panel.style.bottom = "auto";
  });
  window.addEventListener("mouseup", () => { drag = null; });

  function addMsg(m) {
    const empty = body.querySelector("#hs-empty");
    if (empty) empty.remove();
    const d = document.createElement("div");
    d.className = "hs-msg hs-" + (m.type || "answer");
    const tag = m.type === "request" ? "⚑ action needed\n" : "";
    d.textContent = tag + m.text;
    body.appendChild(d);
    body.scrollTop = body.scrollHeight;
    if (m.type !== "system") panel.classList.remove("hs-min"); // pop open on AI messages
  }

  // live message stream from the bridge (via the service worker)
  try {
    const port = chrome.runtime.connect({ name: "harscope-panel" });
    port.onMessage.addListener(({ msg }) => { if (msg) addMsg(msg); });
  } catch (e) { /* extension context not ready */ }
})();
