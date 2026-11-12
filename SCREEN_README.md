# screenscope — let an AI read a region of your screen

For watching a **web-based VM console / terminal** (Proxmox noVNC, vSphere web
console, cloud serial consoles, a browser terminal, etc.) where the text is drawn
as pixels, not selectable DOM. You frame a region with a movable box; the browser
extension captures and crops it ~1×/sec and streams the image to this MCP server's
localhost bridge; the AI calls `read_screen()`, reads the console off the image,
and pushes interpretations to an on-screen panel.

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
| `read_screen()` | Returns the **latest captured frame as an image** (with its age/seq). Read the console text off it; call repeatedly to follow live. |
| `say(text)` | Show an interpretation/update in the extension's panel. |
| `ask(text)` | Ask the user to do something on the console (shown in the panel). |

## Typical flow

```
bridge_status()                 -> http://127.0.0.1:7333 + token  (paste into the extension)
# user frames the console box and clicks Start
read_screen()                   -> [image of the console]   ← the AI reads it
say("Boot hung at 'A start job is running for /dev/sdb'. 90s timeout counting up.")
ask("Press Ctrl+C in the console to skip the mount, then I'll re-read.")
read_screen()                   -> follow what changed
```

To follow the screen continuously, call `read_screen()` on a loop (e.g. via `/loop`),
interpreting each frame and `say()`-ing only when something changes.

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
- **Active tab only.** Only the focused, visible tab is captured; if you switch
  away, streaming pauses until you return.
- **No network, token-gated, in-memory.** Frames are held only as the latest frame
  in memory and sent only to your local screenscope process. Capture only consoles
  you're authorized to view.
