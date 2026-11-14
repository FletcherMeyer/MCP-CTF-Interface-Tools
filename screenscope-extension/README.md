# screenscope capture — Chrome / Edge extension

Frame a region of a **web-based VM console / terminal** and stream the cropped
image ~1×/sec to a **screenscope** Claude Code session, so the AI can read and
interpret the console live. Purple sibling of the harscope extension.

- **Capture box** — a movable, resizable, minimizable purple frame. Its interior is
  transparent (the console shows through and stays clickable) and the frame is drawn
  *outside* the captured area, so your box borders never appear in what's sent.
- **Updates panel** — a movable box in the bottom-right where the AI's readings
  (purple) and action requests (amber) appear.

Everything is local: the extension only talks to `127.0.0.1` (the screenscope
bridge). No capture data leaves your machine.

## Install (load unpacked)

1. `chrome://extensions` (or `edge://extensions`) → enable **Developer mode**.
2. **Load unpacked** → select this `screenscope-extension` folder.

## Connect & use

1. In the session running `screen_server.py`, ask the AI to run **`bridge_status`**.
   It returns a URL like `http://127.0.0.1:7333` and a token.
2. Click the extension icon → **bridge connection** → paste URL + token → **Save** →
   **Test** (should say "Connected").
3. Drag the **purple frame** over the console text, resize it with the corner handle.
4. Click **Send frame** — in the popup, or the **send** button on the box itself —
   each time you want the AI to read the current frame. Capture is **manual**: one
   frame per click, nothing is streamed automatically. The box bar shows a live
   **✓ sent N** ACK each time the bridge accepts a frame, and the AI's
   `watch_screen` call is blocked waiting for exactly that Send.
5. Watch the bottom-right panel for the AI's readings; drag either box anywhere,
   minimize with **—**, close with **×** (reopen by clicking the toolbar icon).
6. Click **End session** when you're done — a blocked `watch_screen` then returns
   `SESSION ENDED` so the AI stops awaiting.

## Notes & limits

- **Web consoles only.** Capture uses `chrome.tabs.captureVisibleTab`, which grabs
  the browser tab — so the console must be shown in a tab (noVNC/Proxmox, vSphere
  web console, cloud serial console, a browser terminal…). Native windows outside
  the browser aren't capturable.
- **Send from the focused tab.** Only the active, visible tab can be captured.
- **Errors surface in the popup.** If you Send with no bridge configured (or the box
  isn't on the page yet), a red indicator in the bottom-left says why.
- **Manual = you control the cadence.** One frame per click, so you decide exactly
  what the AI sees and when.

## Files

| File | Role |
|------|------|
| `manifest.json` | MV3 manifest. |
| `background.js` | Capture loop: grab tab, crop to the box, POST the image; poll AI updates. |
| `content.js` / `panel.css` | The capture box + the bottom-right updates panel. |
| `popup.html` / `popup.js` | Toolbar control panel: connect, Start/Stop. |
| `icons/` | Purple project icon (PNG). |
