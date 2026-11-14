#!/usr/bin/env python3
"""
screenscope — an MCP server that lets an AI watch a region of the screen.

Companion to the screenscope browser extension: the extension captures a movable
box over a (web-based) VM console / terminal and POSTs the cropped image ~1x/sec
to this server's localhost bridge. The AI calls read_screen() to see the latest
frame and interpret the console, then say()/ask() to push updates to the
extension's on-screen panel.

NO network: the embedded bridge binds 127.0.0.1 only and requires a per-session
token. Frames live in memory and are never written out or sent anywhere.

Environment variables:
    SCREENSCOPE_BRIDGE_PORT  Preferred bridge port (default 7333)
    SCREENSCOPE_MAX_CHARS    Max characters a text tool returns (default 8000)
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP, Image

MAX_CHARS = int(os.environ.get("SCREENSCOPE_MAX_CHARS", "8000"))
BRIDGE_START_PORT = int(os.environ.get("SCREENSCOPE_BRIDGE_PORT", "7333"))

INSTRUCTIONS = """\
screenscope lets you watch a region of the user's screen (a web VM console or
terminal) that they framed with the screenscope extension's capture box. The
extension streams the cropped image ~1x/sec to a localhost bridge; nothing leaves
the machine.

Workflow:
  1. bridge_status()   -> give the user the URL + token to paste into the extension.
  2. watch_screen()    -> the async way to follow a live stream: it BLOCKS until the
                          next new frame arrives and returns it as an image. Call it
                          in a loop — it waits server-side, so it's efficient. It
                          returns "STREAM ENDED" when the user clicks Stop in the
                          extension; when you see that, stop looping.
     read_screen()     -> non-blocking: returns the latest frame right now (for a
                          one-off look rather than following).
  3. say(text)         -> show an update in the extension's bottom-right panel.
     ask(text)         -> ask the user to do something on the console.

The frame is a picture — read the text off it yourself. Each frame the extension
sends is ACKed synchronously by the bridge (the extension shows the user a live
"sent" count), so if the user says nothing is being ACKed, frames aren't leaving
the extension — have them reload the console page and click Start.
"""

mcp = FastMCP("screenscope", instructions=INSTRUCTIONS)

_BRIDGE = {
    "token": None,
    "port": None,
    "frame": None,       # {"img": bytes, "fmt": str, "seq": int, "ts": float}
    "outgoing": [],      # messages AI -> extension panel
    "msg_id": 0,
    "streaming": False,  # True while the extension is actively sending frames
    "lock": threading.Lock(),
}
# Condition (shares the lock) to wake watch_screen on a new frame or stream end.
_BRIDGE["cond"] = threading.Condition(_BRIDGE["lock"])
_last_watch_seq = 0  # highest frame seq already delivered to watch_screen


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "X-Screenscope-Token, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _send(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _auth(self) -> bool:
        return bool(_BRIDGE["token"]) and self.headers.get("X-Screenscope-Token") == _BRIDGE["token"]

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path == "/ping":
            with _BRIDGE["lock"]:
                have = _BRIDGE["frame"] is not None
                streaming = _BRIDGE["streaming"]
            return self._send(200, {"ok": True, "service": "screenscope-bridge",
                                    "frame": have, "streaming": streaming})
        if self.path == "/state":
            with _BRIDGE["lock"]:
                return self._send(200, {
                    "streaming": _BRIDGE["streaming"],
                    "seq": _BRIDGE["frame"]["seq"] if _BRIDGE["frame"] else 0,
                })
        if self.path.startswith("/messages"):
            if not self._auth():
                return self._send(401, {"error": "bad or missing token"})
            from urllib.parse import urlsplit, parse_qs
            try:
                since = int(parse_qs(urlsplit(self.path).query).get("since", ["0"])[0])
            except ValueError:
                since = 0
            with _BRIDGE["lock"]:
                msgs = [m for m in _BRIDGE["outgoing"] if m["id"] > since]
            return self._send(200, {"messages": msgs})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            return self._send(401, {"error": "bad or missing token"})
        if self.path == "/stream":
            # extension marks the stream started/ended (Start / Stop buttons)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                active = bool(json.loads(self.rfile.read(length)).get("active"))
            except (ValueError, OSError):
                return self._send(400, {"error": "bad payload"})
            with _BRIDGE["cond"]:
                _BRIDGE["streaming"] = active
                _BRIDGE["cond"].notify_all()  # wake watch_screen so it can end
            return self._send(200, {"ok": True, "streaming": active})
        if self.path == "/frame":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length))
                raw = base64.b64decode(payload["img"])
            except (ValueError, KeyError, OSError, binascii.Error):
                return self._send(400, {"error": "bad frame payload"})
            with _BRIDGE["cond"]:
                seq = (_BRIDGE["frame"]["seq"] + 1) if _BRIDGE["frame"] else 1
                _BRIDGE["frame"] = {"img": raw, "fmt": payload.get("fmt", "jpeg"),
                                    "seq": seq, "ts": time.time()}
                _BRIDGE["streaming"] = True
                _BRIDGE["cond"].notify_all()  # wake a waiting watch_screen
            # the ACK the extension shows the user: HTTP 200 + the frame's seq
            return self._send(200, {"ok": True, "seq": seq})
        return self._send(404, {"error": "not found"})


def _push(kind: str, text: str) -> int:
    with _BRIDGE["lock"]:
        _BRIDGE["msg_id"] += 1
        mid = _BRIDGE["msg_id"]
        _BRIDGE["outgoing"].append({"id": mid, "type": kind, "text": text, "ts": time.time()})
        _BRIDGE["outgoing"][:] = _BRIDGE["outgoing"][-100:]
    return mid


def _bridge_start() -> Optional[int]:
    if _BRIDGE["port"]:
        return _BRIDGE["port"]
    _BRIDGE["token"] = secrets.token_urlsafe(18)
    srv = None
    for p in range(BRIDGE_START_PORT, BRIDGE_START_PORT + 25):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), _Handler)
            _BRIDGE["port"] = p
            break
        except OSError:
            continue
    if not srv:
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        d = Path.home() / ".screenscope"
        d.mkdir(exist_ok=True)
        (d / "bridge.json").write_text(json.dumps({
            "port": _BRIDGE["port"], "token": _BRIDGE["token"],
            "pid": os.getpid(), "ts": time.time(),
        }))
    except OSError:
        pass
    return _BRIDGE["port"]


@mcp.tool()
def bridge_status() -> str:
    """Report the bridge URL + token to paste into the screenscope extension."""
    if not _BRIDGE["port"]:
        return "Bridge not running (port busy or disabled)."
    with _BRIDGE["lock"]:
        have = _BRIDGE["frame"] is not None
    return (f"Bridge live:  http://127.0.0.1:{_BRIDGE['port']}\n"
            f"Token:        {_BRIDGE['token']}\n"
            f"Frame waiting: {'yes' if have else 'no'}\n\n"
            "Paste the URL + token into the screenscope extension, Connect, frame the "
            "console with the capture box, and click Start. Then call read_screen().")


@mcp.tool()
def read_screen():
    """
    Return the LATEST captured frame of the user's framed screen region as an image.
    Read the console/terminal text off the image and interpret it. Call repeatedly
    (e.g. on a loop) to follow the screen live.
    """
    with _BRIDGE["lock"]:
        fr = _BRIDGE["frame"]
    if not fr:
        return ("No frame yet. Ask the user to position the capture box over the "
                "console and click Start in the screenscope extension, then retry.")
    age = time.time() - fr["ts"]
    img = Image(data=fr["img"], format=fr["fmt"])
    # Return the image plus a short caption so the AI knows the frame's age/seq.
    return [f"frame #{fr['seq']}, {age:.1f}s old:", img]


@mcp.tool()
def watch_screen(timeout_seconds: int = 45):
    """
    Block until the NEXT new frame arrives, then return it as an image — an async
    long-poll for live monitoring. Call it repeatedly in a loop: each call waits
    server-side for a fresh frame instead of busy-polling, so it's efficient and
    near-real-time. It returns one of:
      • the next frame (image) when one arrives — read the console off it;
      • "STREAM ENDED ..." when the user clicks Stop in the extension — STOP looping;
      • "still streaming, no change ..." if nothing new within the timeout — loop again.

    Args:
        timeout_seconds: how long to wait for a new frame before returning the
                         no-change note (clamped to 5..55s).
    """
    global _last_watch_seq
    if not _BRIDGE["port"]:
        return "Bridge not running."
    timeout = max(5, min(int(timeout_seconds), 55))
    deadline = time.time() + timeout
    with _BRIDGE["cond"]:
        while True:
            fr = _BRIDGE["frame"]
            streaming = _BRIDGE["streaming"]
            if fr and fr["seq"] > _last_watch_seq:
                _last_watch_seq = fr["seq"]
                age = time.time() - fr["ts"]
                return [f"frame #{fr['seq']}, {age:.1f}s old:",
                        Image(data=fr["img"], format=fr["fmt"])]
            if not streaming:
                if fr is not None:
                    return ("STREAM ENDED — the user stopped the capture in the "
                            "extension. Stop looping / watching.")
                return ("No stream yet — ask the user to frame the console and click "
                        "Start in the screenscope extension, then call watch_screen again.")
            remaining = deadline - time.time()
            if remaining <= 0:
                return (f"still streaming, no change in {timeout}s (console idle). "
                        "Call watch_screen again to keep following.")
            _BRIDGE["cond"].wait(remaining)


@mcp.tool()
def say(text: str) -> str:
    """Show an interpretation/update in the extension's bottom-right panel."""
    if not _BRIDGE["port"]:
        return "Bridge not running."
    _push("answer", text)
    return "Sent to the screenscope panel."


@mcp.tool()
def ask(text: str) -> str:
    """Ask the user to do something on the console (shown in the panel)."""
    if not _BRIDGE["port"]:
        return "Bridge not running."
    _push("request", text)
    return "Request sent to the screenscope panel."


def main() -> None:
    _bridge_start()
    mcp.run()


if __name__ == "__main__":
    main()
