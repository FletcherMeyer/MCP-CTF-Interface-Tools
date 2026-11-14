// screenscope content script: the capture box (defines the region) + the
// bottom-right updates panel (shows the AI's readings).
(function () {
  if (window.__screenscope) return;
  window.__screenscope = true;

  // ---------------- capture box ----------------
  const box = document.createElement("div");
  box.id = "ss-box";
  box.style.left = "80px";
  box.style.top = "130px";
  box.style.width = "460px";
  box.style.height = "170px";
  box.innerHTML =
    '<div id="ss-bar">' +
      '<span id="ss-bar-title">▣ screenscope · capture region</span>' +
      '<button id="ss-bar-min" title="minimize / expand">—</button>' +
      '<button id="ss-bar-close" title="close (reopen from the toolbar icon)">×</button>' +
    '</div>' +
    '<div id="ss-resize" title="drag to resize"></div>';
  document.documentElement.appendChild(box);

  const bar = box.querySelector("#ss-bar");
  const resize = box.querySelector("#ss-resize");

  function reportRect() {
    const r = box.getBoundingClientRect();
    try {
      chrome.runtime.sendMessage({
        cmd: "rect",
        rect: { x: r.left, y: r.top, w: r.width, h: r.height },
        dpr: window.devicePixelRatio || 1,
      });
    } catch (e) { /* worker asleep */ }
  }
  function setPaused(p) { try { chrome.runtime.sendMessage({ cmd: "paused", paused: p }); } catch (e) {} }

  // drag (move) via the bar
  let drag = null;
  bar.addEventListener("mousedown", (e) => {
    if (e.target.tagName === "BUTTON") return;
    drag = { x: e.clientX, y: e.clientY, l: box.offsetLeft, t: box.offsetTop };
    e.preventDefault();
  });
  // resize via the corner handle
  let rs = null;
  resize.addEventListener("mousedown", (e) => {
    rs = { x: e.clientX, y: e.clientY, w: box.offsetWidth, h: box.offsetHeight };
    e.preventDefault();
    e.stopPropagation();
  });
  window.addEventListener("mousemove", (e) => {
    if (drag) {
      box.style.left = Math.max(0, drag.l + e.clientX - drag.x) + "px";
      box.style.top = Math.max(0, drag.t + e.clientY - drag.y) + "px";
    } else if (rs) {
      box.style.width = Math.max(60, rs.w + e.clientX - rs.x) + "px";
      box.style.height = Math.max(28, rs.h + e.clientY - rs.y) + "px";
    }
  });
  window.addEventListener("mouseup", () => {
    if (drag || rs) { drag = null; rs = null; reportRect(); }
  });

  // minimize: collapse to just the bar, pause streaming
  box.querySelector("#ss-bar-min").addEventListener("click", (e) => {
    e.stopPropagation();
    const min = box.classList.toggle("ss-min");
    setPaused(min);
    if (!min) reportRect();
  });

  window.addEventListener("resize", reportRect);
  setTimeout(reportRect, 300);

  // ---------------- updates panel ----------------
  const panel = document.createElement("div");
  panel.id = "ss-panel";
  panel.classList.add("ss-min");
  panel.innerHTML =
    '<div id="ssp-head"><span id="ssp-title">screenscope</span>' +
      '<span><button id="ssp-toggle" title="minimize / expand">—</button>' +
      '<button id="ssp-close" title="close (reopen from the toolbar icon)">×</button></span></div>' +
    '<div id="ssp-body"><div id="ssp-empty">Readings from the AI appear here.</div></div>';
  document.documentElement.appendChild(panel);

  const phead = panel.querySelector("#ssp-head");
  const pbody = panel.querySelector("#ssp-body");
  panel.querySelector("#ssp-toggle").addEventListener("click", (e) => {
    e.stopPropagation();
    panel.classList.toggle("ss-min");
  });

  let pdrag = null;
  phead.addEventListener("mousedown", (e) => {
    if (e.target.tagName === "BUTTON") return;
    const r = panel.getBoundingClientRect();
    pdrag = { x: e.clientX, y: e.clientY, l: r.left, t: r.top };
    e.preventDefault();
  });
  window.addEventListener("mousemove", (e) => {
    if (!pdrag) return;
    panel.style.left = Math.max(0, pdrag.l + e.clientX - pdrag.x) + "px";
    panel.style.top = Math.max(0, pdrag.t + e.clientY - pdrag.y) + "px";
    panel.style.right = "auto"; panel.style.bottom = "auto";
  });
  window.addEventListener("mouseup", () => { pdrag = null; });

  function addMsg(m) {
    const empty = pbody.querySelector("#ssp-empty");
    if (empty) empty.remove();
    const d = document.createElement("div");
    d.className = "ssp-msg ssp-" + (m.type || "answer");
    d.textContent = (m.type === "request" ? "⚑ " : "") + m.text;
    pbody.appendChild(d);
    pbody.scrollTop = pbody.scrollHeight;
    panel.classList.remove("ss-min");
  }

  // ---------------- close / reopen ----------------
  // × closes a tool; clicking the extension icon reopens both.
  box.querySelector("#ss-bar-close").addEventListener("click", (e) => {
    e.stopPropagation();
    box.style.display = "none";
    setPaused(true);  // a hidden box must not keep streaming
    try { chrome.storage.local.set({ ssBoxHidden: true }); } catch (err) {}
  });
  panel.querySelector("#ssp-close").addEventListener("click", (e) => {
    e.stopPropagation();
    panel.style.display = "none";
    try { chrome.storage.local.set({ ssPanelHidden: true }); } catch (err) {}
  });
  try {
    chrome.storage.local.get(["ssBoxHidden", "ssPanelHidden"], (d) => {
      if (d && d.ssBoxHidden) { box.style.display = "none"; setPaused(true); }
      if (d && d.ssPanelHidden) panel.style.display = "none";
    });
  } catch (e) { /* ignore */ }
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.cmd === "showTools") {
      box.style.display = ""; panel.style.display = "";
      try { chrome.storage.local.set({ ssBoxHidden: false, ssPanelHidden: false }); } catch (e) {}
      setPaused(false);
      reportRect();
    }
  });

  try {
    const port = chrome.runtime.connect({ name: "screenscope-panel" });
    port.onMessage.addListener(({ msg }) => { if (msg) addMsg(msg); });
  } catch (e) { /* extension context not ready */ }
})();
