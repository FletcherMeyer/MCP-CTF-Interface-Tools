# harscope capture — Chrome / Edge extension

Capture the current tab's HTTP traffic as a HAR and push it straight to a
**harscope** Claude Code session, then see the AI's answers and action requests in
a small floating panel on the page. Built for the loop:

1. You tell the AI the challenge and the questions.
2. You point the extension at the AI's session (paste a URL + token once).
3. You browse the challenge — click through endpoints/buttons — then hit **Send**.
4. The AI receives the HAR, interprets it, and replies in the floating panel.
5. Answers appear in both the session and the panel; if the AI needs more, it asks
   you (in the panel) to visit an endpoint or run a command and **Send** again.

Everything is **local**: the extension only talks to `127.0.0.1` (the harscope
bridge). No capture data leaves your machine.

## How it connects (the honest architecture)

A browser extension can't push data *into* an AI session directly, so harscope's
MCP server runs a tiny **localhost-only HTTP bridge** inside itself. The extension
`POST`s the HAR there; the AI **pulls** it with `bridge_poll` and **pushes** replies
with `bridge_say` / `bridge_ask`, which this panel polls every ~2s. The AI reacts
when it polls — so either run the session in a polling loop (feels automatic) or
just type "check" after you hit Send.

## Install (load unpacked)

1. Chrome/Edge → `chrome://extensions` (or `edge://extensions`).
2. Toggle **Developer mode** on.
3. **Load unpacked** → select this `harscope-extension` folder.

## Connect to a session

1. In the Claude Code session running harscope, ask the AI to run **`bridge_status`**.
   It returns a URL like `http://127.0.0.1:7331` and a token.
2. Click the extension icon → **Bridge connection** → paste the URL and token →
   **Save** → **Test** (should say "Connected").

## Use

1. Click the extension icon → **Start capture** (a red **REC** badge appears; Chrome
   shows a "harscope capture is debugging this browser" banner — that's the capture
   working).
2. Browse the challenge in that tab — visit the endpoints, click the buttons.
3. Click **Send capture to AI** (in the popup, or **send** in the floating panel).
4. Watch the panel: blue = answers, amber = "action needed" requests. Drag the
   header to move it; click **—** to minimize.
5. If the AI asks for more, do it (e.g. visit `/admin` with capture still on) and
   **Send** again — each Send is a fresh snapshot.

## Caveats & limits

- **Response bodies need the debugger API**, which is why Chrome shows the debugging
  banner and why capture must be **started** before you browse (traffic before Start
  isn't recorded). Leaving Start on captures everything in that tab.
- **Service-worker lifecycle:** capture state lives in the extension's worker. It
  stays alive while recording or while the panel is open; in rare idle-eviction
  cases a capture can be cut short — just Start again.
- **One session at a time** is the simple case. To target a different session, paste
  that session's URL + token (each session gets its own port + token).
- **Security:** the bridge binds `127.0.0.1` only and requires the random token on
  every write/read, so other local apps or web pages can't post to or read it. The
  HAR contains cookies and auth tokens for the sites you captured — it's sent only to
  your local harscope process. Capture only challenges you're authorized to test.

## Files

| File | Role |
|------|------|
| `manifest.json` | MV3 manifest (debugger + localhost host permissions). |
| `background.js` | Captures traffic via DevTools Protocol, builds the HAR, POSTs to the bridge, polls for AI messages. |
| `popup.html` / `popup.js` | Toolbar control panel: connect, Start/Stop, Send. |
| `content.js` / `panel.css` | The draggable, minimizable in-page answer panel. |
