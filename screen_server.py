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
  1. bridge_status() -> give the user the URL + token to paste into the extension.
  2. read_screen()   -> returns the LATEST captured frame as an image. Read the
                        console text from it and interpret what's happening. Call
                        it again (e.g. in a loop) to follow the screen live.
  3. say(text)       -> show an update in the extension's bottom-right panel.
     ask(text)       -> ask the user to do something on the console.

The frame is a picture — read the text off it yourself. If frames aren't arriving,
tell the user to position the box over the console and click Start in the extension.
"""

mcp = FastMCP("screenscope", instructions=INSTRUCTIONS)

_BRIDGE = {
    "token": None,
    "port": None,
    "frame": None,       # {"img": bytes, "fmt": str, "seq": int, "ts": float}
    "outgoing": [],      # messages AI -> extension panel
    "msg_id": 0,
    "lock": threading.Lock(),
}


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
            return self._send(200, {"ok": True, "service": "screenscope-bridge", "frame": have})
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
        if self.path != "/frame":
            return self._send(404, {"error": "not found"})
        if not self._auth():
            return self._send(401, {"error": "bad or missing token"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            raw = base64.b64decode(payload["img"])
        except (ValueError, KeyError, OSError, binascii.Error):
            return self._send(400, {"error": "bad frame payload"})
        with _BRIDGE["lock"]:
            _BRIDGE["msg_id"]  # noqa
            seq = (_BRIDGE["frame"]["seq"] + 1) if _BRIDGE["frame"] else 1
            _BRIDGE["frame"] = {"img": raw, "fmt": payload.get("fmt", "jpeg"),
                                "seq": seq, "ts": time.time()}
        return self._send(200, {"ok": True, "seq": seq})


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
