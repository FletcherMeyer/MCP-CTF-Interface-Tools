# screenscope — let an AI read a region of your screen

For watching a **web-based VM console / terminal** (Proxmox noVNC, vSphere web
console, cloud serial consoles, a browser terminal, etc.) where the text is drawn
as pixels, not selectable DOM. You frame a region with a movable box and click
**Send frame** whenever you want the AI to read it (capture is **manual**, not an
automatic stream). The extension crops that frame and POSTs it to this MCP server's
localhost bridge; the AI `watch_screen()` call blocks until your Send, reads the
console off the image, and pushes interpretations to an on-screen panel.

Decision baked in: the **AI reads the image** (its own vision) rather than the
extension running OCR — no bulky OCR engine, better on console fonts, and it works
offline. Nothing leaves your machine: the bridge is `127.0.0.1` only, token-gated.

## Pieces

- **`screen_server.py`** — the MCP server + embedded localhost bridge.
- **`screenscope-extension/`** — the Chrome/Edge extension (purple): a movable,
  resizable, minimizable capture box + a movable bottom-right updates panel. See
  [screenscope-extension/README.md](screenscope-extension/README.md).

## Server tools

| Tool | Purpose |
|------|---------|
| `bridge_status()` | URL + token to paste into the extension. |
| `watch_screen(timeout?)` | **Async wait**: BLOCKS until the user clicks **Send frame**, then returns that frame as an image. Await it like an async call; returns "no frame sent yet" on timeout (await again) and `SESSION ENDED` when the user clicks **End**. |
| `read_screen()` | Non-blocking: returns the most recently sent frame, if any (a one-off look). |
| `say(text)` | Show an interpretation/update in the extension's panel. |
| `ask(text)` | Ask the user to do something on the console (shown in the panel). |

**Manual / ACK model:** capture is on-demand — the user clicks **Send frame** (in the
popup or on the capture box) to push one frame. Each Send is acknowledged
synchronously by the bridge (HTTP 200 + a sequence number), and the extension shows a
live **"✓ sent N"** count in the box bar. So you **await** the user's Send with
`watch_screen` rather than polling; **End** makes a blocked `watch_screen` return
`SESSION ENDED`.

## Typical flow

```
bridge_status()                 -> http://127.0.0.1:7333 + token  (paste into the extension)
# user frames the console box, then clicks "Send frame" when they want it read
watch_screen()                  -> blocks… returns [image] the moment they click Send
say("Boot hung at 'A start job is running for /dev/sdb'. 90s timeout counting up.")
ask("Press Ctrl+C in the console, then click Send frame again.")
watch_screen()                  -> blocks until their next Send, returns the new frame
# ... until the user clicks End -> watch_screen returns SESSION ENDED
```

## Register

```bash
claude mcp add screenscope -- python "C:\path\to\screen_server.py"
```

No extra Python dependencies (standard library + `mcp`). Env (optional):
`SCREENSCOPE_BRIDGE_PORT` (default 7333).

## Limits & safety

- **Web consoles only.** `chrome.tabs.captureVisibleTab` captures the browser tab,
  so the console must be shown **in a browser tab**. A native VM window outside the
  browser can't be captured by an extension.
- **Active tab only.** Only the focused, visible tab can be captured; Send from the
  tab showing the console.
- **No network, token-gated, in-memory.** Frames are held only as the latest frame
  in memory and sent only to your local screenscope process. Capture only consoles
  you're authorized to view.
