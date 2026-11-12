#!/usr/bin/env python3
"""
harscope — an MCP server for interpreting HAR files, built for CTF work.

Why this is not just "grep the file"
------------------------------------
A HAR is a single JSON document (`log.entries[]`). Response bodies are frequently
base64-encoded and bodies/JSON are often minified, so raw text search and raw
reads are useless and blow the model's context. harscope instead:

    1. LOADS the HAR once (parse + index + decode bodies) and returns a compact
       profile (hosts, methods, statuses, mime types, and a CTF artifact scan).
    2. Answers STRUCTURED, BOUNDED queries against that index:
       list_entries / entry / body / search / find_flags / extract / decode

It NEVER makes a network request. It only reads and interprets the HAR file you
point it at. Everything it returns is capped, so even a huge capture stays small
in context.

CTF-oriented features:
    * find_flags   — scan every decoded field for flag{...}/CTF{...}/... patterns
    * extract      — pull cookies, JWTs, auth tokens, params, comments, base64
                     blobs, emails, redirects, hosts across the whole capture
    * decode       — local base64/base64url/hex/url/jwt/rot13 decoder for values
                     you spot (no network, pure transform)

Environment variables:
    HARSCOPE_MAX_CHARS   Max characters any tool returns (default 12000)
    HARSCOPE_MAX_ITEMS   Max rows/matches a listing returns (default 200)
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import hashlib
import json
import os
import re
import zlib
import secrets
import tempfile
import threading
import time
import urllib.parse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

MAX_CHARS = int(os.environ.get("HARSCOPE_MAX_CHARS", "12000"))
MAX_ITEMS = int(os.environ.get("HARSCOPE_MAX_ITEMS", "200"))

# Default flag pattern: a short word tag followed by {...}. Covers flag{},
# CTF{}, picoCTF{}, HTB{}, FLAG{}, etc.
DEFAULT_FLAG_RE = r"[A-Za-z0-9_]{1,20}\{[^}\r\n]{1,256}\}"

INSTRUCTIONS = """\
harscope interprets HAR (HTTP Archive) files for CTF work. It makes NO network
requests — it only reads the capture you give it. Do NOT open a .har with generic
file tools: bodies are base64 and JSON is minified, so a raw read wastes context.

Workflow:
  1. load_har(path) -> parses the HAR, decodes bodies, returns a profile + a scan
                       that already counts flags/JWTs/cookies/base64 blobs found.
  2. Then query by the returned har_id:
       scan(har_id, patterns)        -> DYNAMIC, format-agnostic hunt. YOU supply the
                                        regex(es) for whatever matters in this app;
                                        with no patterns it surfaces generic secrets
                                        (API keys, JWTs, auth, hashes, high-entropy).
       find_flags(har_id, pattern)   -> shortcut that defaults to the literal
                                        word{...} flag format (override with pattern)
       extract(har_id, kind)         -> cookies | jwts | auth | params | comments
                                        | base64 | emails | redirects | hosts | setcookie
       search(har_id, pattern, ...)  -> regex across decoded urls/headers/bodies
       list_entries / entry / body   -> drill into a specific request
       decode(value, scheme)         -> locally decode a token you found

You drive the patterns. Do not assume the target is in flag{...} form — read the
traffic (list_entries/entry/body), form a hypothesis about THIS app, then scan()
with your own patterns. find_flags is just the convenience case of that.

IF THE ANSWER ISN'T IN THE CAPTURE, DO NOT GUESS. This server only sees the HAR
you were given and makes no network requests. When a question needs data that is
absent — an endpoint that was never requested, a response body that wasn't saved,
the result of a modified/authenticated request, a stripped header — say so plainly
and tell the user exactly what to do to get it: which URL to visit (with devtools
'Preserve log' on), which command to run (give a ready-to-paste curl), or which
flow to perform while recording, then ask them to export/send a fresh HAR and
reload it. Inventing an answer is worse than asking for one more capture.

Browser-extension bridge (optional): if the harscope extension is connected, the
user captures a tab's traffic and clicks Send instead of exporting a .har by hand.
Then: bridge_poll() receives the capture and auto-loads it; investigate as usual;
bridge_say(text) shows an answer in the extension's panel; bridge_ask(text) asks
the user to perform an action there. Call bridge_status() to get the URL+token to
give the user so their extension targets THIS session.
"""

mcp = FastMCP("harscope", instructions=INSTRUCTIONS)

# har_id -> {"path": str, "entries": [ indexed entry dicts ], "raw_log": {...}}
_HARS: dict[str, dict] = {}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _cap(text: str, limit: int = MAX_CHARS) -> str:
    if text is None:
        return "(none)"
    if len(text) > limit:
        return text[:limit] + f"\n\n[... truncated to {limit} chars — narrow your query ...]"
    return text or "(empty)"


def _headers_to_dict(headers: list) -> dict:
    out: dict[str, str] = {}
    for h in headers or []:
        n = str(h.get("name", ""))
        v = str(h.get("value", ""))
        if n in out:
            out[n] += ", " + v
        else:
            out[n] = v
    return out


# Optional brotli support (stdlib has gzip + deflate; brotli needs a package).
try:
    import brotli as _brotli_mod  # type: ignore
except ImportError:
    try:
        import brotlicffi as _brotli_mod  # type: ignore
    except ImportError:
        _brotli_mod = None


def _decompress(raw: bytes, encoding: str) -> bytes:
    """
    Undo HTTP Content-Encoding on a body's bytes. Handles gzip/deflate from the
    stdlib and brotli if a brotli package is installed; gzip is also detected by
    magic bytes even when the header is missing. Unknown/failed -> bytes unchanged.
    """
    enc = (encoding or "").lower()
    try:
        if "gzip" in enc or "x-gzip" in enc or raw[:2] == b"\x1f\x8b":
            return gzip.decompress(raw)
        if "deflate" in enc:
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)  # raw deflate
        if "br" in enc and _brotli_mod is not None:
            return _brotli_mod.decompress(raw)
    except (OSError, zlib.error, ValueError, Exception):
        return raw
    return raw


def _decode_content(content: dict, content_encoding: str = "") -> str:
    """
    Return the decoded textual body of a response/postData content block.

    Resolves base64 transport encoding (HAR `encoding: base64`) AND HTTP
    Content-Encoding compression (gzip / deflate / brotli), so a compressed body
    comes back as readable text instead of binary noise.
    """
    if not content:
        return ""
    text = content.get("text", "") or ""
    b64 = content.get("encoding", "").lower() == "base64"
    enc = (content_encoding or "").lower()
    compressed = any(x in enc for x in ("gzip", "deflate", "br"))

    if not b64 and not compressed:
        return text  # plain text — don't round-trip through bytes

    if b64:
        try:
            raw = base64.b64decode(text)
        except (binascii.Error, ValueError):
            return text
    else:
        raw = text.encode("latin-1", "replace")

    raw = _decompress(raw, enc)
    return raw.decode("utf-8", "replace")


def _looks_text(s: str) -> bool:
    """
    True if `s` is readable text. A compressed (gzip/br) or otherwise binary body
    decodes to mostly control bytes / U+FFFD replacement chars; we must NOT scan
    those for flags/secrets because random {...} byte sequences produce false
    positives. Only genuine text is worth reporting on.
    """
    if not s:
        return True
    sample = s[:4096]
    bad = sum(1 for c in sample if c == "�" or (ord(c) < 32 and c not in "\r\n\t"))
    return (bad / len(sample)) < 0.05


def _safe_resp(e: dict) -> str:
    """Response body for scanning — empty when the body isn't readable text."""
    return e["_resp_text"] if e.get("_resp_is_text") else ""


def _safe_req(e: dict) -> str:
    """Request body for scanning — empty when the body isn't readable text."""
    return e["_req_text"] if e.get("_req_is_text") else ""


def _netloc(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).netloc
    except ValueError:
        return ""


def _require(har_id: str) -> dict:
    h = _HARS.get(har_id)
    if not h:
        raise ValueError(
            f"Unknown har_id '{har_id}'. Call load_har(path) first; list with list_hars()."
        )
    return h


def _entries(har_id: str) -> list:
    return _require(har_id)["entries"]


def _snippets(text: str, rx: re.Pattern, max_hits: int = 3, ctx: int = 70) -> list[str]:
    out = []
    for m in rx.finditer(text):
        s, e = m.start(), m.end()
        frag = text[max(0, s - ctx): e + ctx].replace("\n", "\\n").replace("\r", "")
        out.append("…" + frag + "…")
        if len(out) >= max_hits:
            break
    return out


# --------------------------------------------------------------------------- #
# Server / tech fingerprinting (headers & cookies are the evidence)
# --------------------------------------------------------------------------- #

# Cookie name (lowercased) -> technology it implies.
_COOKIE_TECH = {
    "phpsessid": "PHP", "jsessionid": "Java (servlet/JSP)",
    "asp.net_sessionid": "ASP.NET", ".aspxauth": "ASP.NET Forms Auth",
    "connect.sid": "Node.js / Express", "laravel_session": "Laravel (PHP)",
    "xsrf-token": "Angular / Laravel", "csrftoken": "Django", "sessionid": "Django",
    "_rails": "Ruby on Rails", "ci_session": "CodeIgniter (PHP)",
    "wordpress_logged_in": "WordPress", "wp-settings": "WordPress",
    "sails.sid": "Sails.js", "spring-session": "Spring (Java)",
}
# Response header (lowercased) -> tech label, or None to use the header's value.
_FRAMEWORK_HEADERS = {
    "x-powered-by": None, "x-aspnet-version": "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC", "x-drupal-cache": "Drupal",
    "x-drupal-dynamic-cache": "Drupal", "x-generator": None,
    "x-pingback": "WordPress (XML-RPC)", "x-runtime": "Ruby on Rails",
    "x-turbo-charged-by": "LiteSpeed",
}
# Response header (lowercased) -> CDN/WAF/proxy label, or None to use the value.
_CDN_HEADERS = {
    "cf-ray": "Cloudflare", "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront", "x-amz-cf-pop": "AWS CloudFront",
    "x-served-by": "Fastly/Varnish", "x-cache": "CDN cache (Varnish/Fastly/CloudFront)",
    "x-azure-ref": "Azure Front Door", "x-fastly-request-id": "Fastly",
    "x-varnish": "Varnish", "via": None, "x-akamai-transformed": "Akamai",
}


def _server_fingerprint(entries: list):
    servers: Counter = Counter()
    powered: Counter = Counter()
    techs: dict[str, set] = {}

    def add(tech: str, evidence: str) -> None:
        if tech:
            techs.setdefault(tech, set()).add(evidence)

    for e in entries:
        rh = {k.lower(): v for k, v in e["resp_headers"].items()}
        if "server" in rh and rh["server"]:
            servers[rh["server"]] += 1
        if "x-powered-by" in rh and rh["x-powered-by"]:
            powered[rh["x-powered-by"]] += 1
        for h, lab in _FRAMEWORK_HEADERS.items():
            if h in rh:
                add(lab or rh[h], f"header {h}")
        for h, lab in _CDN_HEADERS.items():
            if h in rh:
                add(lab or rh[h], f"header {h}: {rh[h][:40]}")
        names = [c.get("name", "") for c in e["resp_cookies"] + e["req_cookies"]]
        for k, v in e["resp_headers"].items():
            if k.lower() == "set-cookie":
                names.append(v.split("=", 1)[0].strip())
        for nm in names:
            add(_COOKIE_TECH.get(nm.lower(), ""), f"cookie {nm}")

    top_srv = ", ".join(f"{s} ({n})" for s, n in servers.most_common(3)) or "(no Server header)"
    top_pow = ", ".join(s for s, _ in powered.most_common(3))
    oneliner = f"server: {top_srv}" + (f"  |  powered-by: {top_pow}" if top_pow else "")
    return oneliner, servers, powered, techs


def _fingerprint_report(entries: list) -> str:
    _, servers, powered, techs = _server_fingerprint(entries)
    out = ["Server/tech fingerprint",
           "(from response headers & cookies — these can be spoofed or stripped/"
           "rewritten by a CDN or reverse proxy, so treat as evidence, not proof):",
           "",
           "Server header:"]
    out += [f"  {s}  (x{n})" for s, n in servers.most_common()] or ["  (none seen)"]
    if powered:
        out.append("X-Powered-By:")
        out += [f"  {s}  (x{n})" for s, n in powered.most_common()]
    out.append("Detected frameworks / CMS / CDN:")
    if techs:
        for t, evs in sorted(techs.items()):
            out.append(f"  {t}  <- {', '.join(sorted(evs)[:4])}")
    else:
        out.append("  (no secondary fingerprints found — check error-page bodies "
                   "with body(), or header casing/order)")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Indexing
# --------------------------------------------------------------------------- #

def _content_encoding(headers: list) -> str:
    for h in headers or []:
        if str(h.get("name", "")).lower() == "content-encoding":
            return str(h.get("value", ""))
    return ""


def _index_entry(i: int, e: dict) -> dict:
    req = e.get("request", {}) or {}
    resp = e.get("response", {}) or {}
    content = resp.get("content", {}) or {}
    postdata = req.get("postData", {}) or {}

    resp_text = _decode_content(content, _content_encoding(resp.get("headers", [])))
    req_text = (_decode_content(postdata, _content_encoding(req.get("headers", [])))
                if postdata.get("text") else "")

    return {
        "i": i,
        "method": req.get("method", ""),
        "url": req.get("url", ""),
        "host": _netloc(req.get("url", "")),
        "status": resp.get("status", 0),
        "statusText": resp.get("statusText", ""),
        "mime": (content.get("mimeType", "") or "").split(";")[0],
        "resp_size": content.get("size", resp.get("bodySize", 0)) or 0,
        "req_headers": _headers_to_dict(req.get("headers", [])),
        "resp_headers": _headers_to_dict(resp.get("headers", [])),
        "req_cookies": req.get("cookies", []) or [],
        "resp_cookies": resp.get("cookies", []) or [],
        "query": req.get("queryString", []) or [],
        "post_params": postdata.get("params", []) or [],
        "post_mime": postdata.get("mimeType", ""),
        "redirectURL": resp.get("redirectURL", ""),
        "started": e.get("startedDateTime", ""),
        "_resp_text": resp_text,
        "_req_text": req_text,
        "_resp_is_text": _looks_text(resp_text),
        "_req_is_text": _looks_text(req_text),
    }


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #

@mcp.tool()
def load_har(path: str) -> str:
    """
    Load and index a HAR file. Do this FIRST — never read a .har raw.

    Parses the capture, decodes base64 bodies, and returns a compact profile:
    entry count, hosts, HTTP methods, status codes, mime types, time span, plus a
    quick CTF artifact scan (how many flags / JWTs / set-cookies / base64 blobs
    were spotted). Makes no network request.

    Args:
        path: Path to the .har file (Windows or POSIX path).
    """
    try:
        with open(os.path.expanduser(path), "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except FileNotFoundError:
        return f"File not found: {path}"
    except json.JSONDecodeError as ex:
        return f"Not valid JSON / HAR: {ex}"

    log = data.get("log", data)
    raw_entries = log.get("entries", [])
    if not isinstance(raw_entries, list):
        return "This file has no 'log.entries' array — it does not look like a HAR."

    entries = [_index_entry(i, e) for i, e in enumerate(raw_entries)]
    har_id = hashlib.sha1(os.path.abspath(os.path.expanduser(path)).encode()).hexdigest()[:10]
    _HARS[har_id] = {"path": path, "entries": entries, "raw_log": log}

    hosts = Counter(e["host"] for e in entries if e["host"])
    methods = Counter(e["method"] for e in entries if e["method"])
    statuses = Counter(e["status"] for e in entries if e["status"])
    mimes = Counter(e["mime"] for e in entries if e["mime"])

    # Quick CTF scan
    flag_rx = re.compile(DEFAULT_FLAG_RE)
    jwt_rx = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
    b64_rx = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
    flags = jwts = setcookies = b64 = 0
    for e in entries:
        blob = " ".join([
            e["url"], _safe_resp(e), _safe_req(e),
            " ".join(f"{k}:{v}" for k, v in e["req_headers"].items()),
            " ".join(f"{k}:{v}" for k, v in e["resp_headers"].items()),
        ])
        flags += len(flag_rx.findall(blob))
        jwts += len(jwt_rx.findall(blob))
        b64 += len(b64_rx.findall(_safe_resp(e)))
        if "set-cookie" in {k.lower() for k in e["resp_headers"]}:
            setcookies += 1

    def _top(c: Counter, n: int = 12) -> str:
        return ", ".join(f"{k} ({v})" for k, v in c.most_common(n)) or "(none)"

    span = ""
    starts = sorted(e["started"] for e in entries if e["started"])
    if starts:
        span = f"{starts[0]}  →  {starts[-1]}"

    fp_one, _, _, _ = _server_fingerprint(entries)

    return (
        f"Loaded {path}\n"
        f"har_id: {har_id}   entries: {len(entries)}\n"
        f"time span: {span or '(unknown)'}\n"
        f"stack:   {fp_one}\n\n"
        f"hosts:   {_top(hosts)}\n"
        f"methods: {_top(methods)}\n"
        f"status:  {_top(statuses)}\n"
        f"mime:    {_top(mimes)}\n\n"
        f"CTF scan: flag-pattern matches={flags}, JWTs={jwts}, "
        f"set-cookie responses={setcookies}, base64 blobs(≥24)={b64}\n\n"
        "Next: find_flags(har_id) or extract(har_id, kind) are usually the fastest "
        "route; use list_entries / entry / body to drill in."
    )


@mcp.tool()
def list_hars() -> str:
    """List HARs currently loaded, with their har_id and path."""
    if not _HARS:
        return "No HAR loaded. Call load_har(path) first."
    return "har_id    \tentries\tpath\n" + "\n".join(
        f"{k}\t{len(v['entries'])}\t{v['path']}" for k, v in _HARS.items()
    )


@mcp.tool()
def list_entries(har_id: str, host: str = "", method: str = "", status: str = "",
                 mime: str = "", url_contains: str = "", max_rows: int = 100) -> str:
    """
    List request/response entries as a compact table (index, method, status, mime,
    response size, URL). Use the filters to narrow before drilling in with entry().

    Args:
        host/method/mime: case-insensitive substring filters.
        status:           status code or prefix, e.g. "200", "30", "4", "5".
        url_contains:     case-insensitive substring of the URL.
        max_rows:         cap on rows returned.
    """
    rows = []
    for e in _entries(har_id):
        if host and host.lower() not in e["host"].lower():
            continue
        if method and method.lower() != e["method"].lower():
            continue
        if status and not str(e["status"]).startswith(status):
            continue
        if mime and mime.lower() not in e["mime"].lower():
            continue
        if url_contains and url_contains.lower() not in e["url"].lower():
            continue
        url = e["url"]
        if len(url) > 90:
            url = url[:87] + "..."
        rows.append(f'{e["i"]:>4}  {e["method"]:<6} {str(e["status"]):<4} '
                    f'{(e["mime"] or "-"):<22} {e["resp_size"]:>8}  {url}')
        if len(rows) >= min(max_rows, MAX_ITEMS):
            break
    if not rows:
        return "No entries match."
    header = f'{"idx":>4}  {"method":<6} {"st":<4} {"mime":<22} {"size":>8}  url'
    return _cap(header + "\n" + "\n".join(rows))


@mcp.tool()
def entry(har_id: str, index: int, part: str = "all") -> str:
    """
    Show one entry's details without dumping the body.

    Args:
        index: entry index from list_entries.
        part:  "all" (default), "request", "response", or "headers".
               Bodies are summarized here — use body() to pull a full body.
    """
    es = _entries(har_id)
    if index < 0 or index >= len(es):
        return f"index out of range (0..{len(es)-1})."
    e = es[index]
    out = []

    if part in ("all", "request", "headers"):
        out.append(f"REQUEST  {e['method']} {e['url']}")
        if e["query"]:
            out.append("  query: " + "  ".join(f'{q.get("name")}={q.get("value")}' for q in e["query"]))
        if e["req_cookies"]:
            out.append("  cookies: " + "  ".join(f'{c.get("name")}={c.get("value")}' for c in e["req_cookies"]))
        out.append("  headers:")
        out += [f"    {k}: {v}" for k, v in e["req_headers"].items()]
        if e["_req_text"]:
            body = e["_req_text"]
            if not e.get("_req_is_text"):
                out.append(f"  body ({e['post_mime'] or 'post'}): "
                           f"[binary or compressed, {len(body)} chars — not shown]")
            else:
                out.append(f"  body ({e['post_mime'] or 'post'} , {len(body)} chars): "
                           + body[:800] + ("…" if len(body) > 800 else ""))

    if part in ("all", "response", "headers"):
        out.append(f"\nRESPONSE  {e['status']} {e['statusText']}   {e['mime']}   {e['resp_size']} bytes")
        if e["redirectURL"]:
            out.append(f"  redirect -> {e['redirectURL']}")
        out.append("  headers:")
        out += [f"    {k}: {v}" for k, v in e["resp_headers"].items()]
        if part != "headers":
            body = e["_resp_text"]
            if body and not e.get("_resp_is_text"):
                out.append(f"  body: [binary or compressed, {len(body)} chars — not shown]")
            elif body:
                out.append(f"  body preview ({len(body)} chars): "
                           + body[:800] + ("…" if len(body) > 800 else ""))
                out.append("  (use body() for the full decoded body)")
    return _cap("\n".join(out))


@mcp.tool()
def body(har_id: str, index: int, which: str = "response", mode: str = "auto",
         max_chars: int = 8000) -> str:
    """
    Return a single entry's full decoded body (base64 is already decoded at load).

    Args:
        index:     entry index.
        which:     "response" (default) or "request".
        mode:      "auto" (text), or "hex" to view binary bodies as a hex dump.
        max_chars: cap on characters returned.
    """
    es = _entries(har_id)
    if index < 0 or index >= len(es):
        return f"index out of range (0..{len(es)-1})."
    e = es[index]
    text = e["_resp_text"] if which == "response" else e["_req_text"]
    if not text:
        return f"(no {which} body)"
    if mode == "hex":
        raw = text.encode("utf-8", "replace")[: max_chars // 3]
        hexd = " ".join(f"{b:02x}" for b in raw)
        return _cap(hexd, max_chars)
    return _cap(text, max_chars)


@mcp.tool()
def search(har_id: str, pattern: str, scope: str = "all", ignore_case: bool = True,
           max_results: int = 60) -> str:
    """
    Regex-search decoded fields across all entries and report where it matched.

    This searches DECODED bodies (base64 already undone), so it finds things raw
    grep on the .har never would.

    Args:
        pattern:     Python regex.
        scope:       "all" | "url" | "headers" | "cookies" | "params" |
                     "request_body" | "response_body".
        ignore_case: default True.
        max_results: cap on matching entries reported.
    """
    try:
        rx = re.compile(pattern, re.I if ignore_case else 0)
    except re.error as ex:
        return f"Bad regex: {ex}"

    def fields(e: dict) -> list[tuple[str, str]]:
        f = []
        if scope in ("all", "url"):
            f.append(("url", e["url"]))
        if scope in ("all", "headers"):
            f.append(("req.headers", " ".join(f"{k}: {v}" for k, v in e["req_headers"].items())))
            f.append(("resp.headers", " ".join(f"{k}: {v}" for k, v in e["resp_headers"].items())))
        if scope in ("all", "cookies"):
            f.append(("cookies", " ".join(f'{c.get("name")}={c.get("value")}'
                                          for c in e["req_cookies"] + e["resp_cookies"])))
        if scope in ("all", "params"):
            f.append(("params", " ".join(f'{p.get("name")}={p.get("value")}'
                                         for p in e["query"] + e["post_params"])))
        if scope in ("all", "request_body"):
            f.append(("req.body", e["_req_text"]))
        if scope in ("all", "response_body"):
            f.append(("resp.body", e["_resp_text"]))
        return f

    out, n = [], 0
    for e in _entries(har_id):
        for fname, val in fields(e):
            if val and rx.search(val):
                for snip in _snippets(val, rx):
                    out.append(f'#{e["i"]:>4} {e["method"]} {e["status"]} [{fname}] {snip}')
                    n += 1
                    if n >= min(max_results, MAX_ITEMS):
                        out.append("[... more matches; narrow the pattern/scope ...]")
                        return _cap("\n".join(out))
    return _cap("\n".join(out)) if out else f"No matches for /{pattern}/ in scope '{scope}'."


@mcp.tool()
def find_flags(har_id: str, pattern: str = "") -> str:
    """
    Hunt for CTF flags across every decoded field (urls, headers, cookies, params,
    request and response bodies). The fastest first move on a HAR challenge.

    Args:
        pattern: custom flag regex. Default matches word{...} forms such as
                 flag{...}, CTF{...}, picoCTF{...}, HTB{...}.
    """
    rx_src = pattern or DEFAULT_FLAG_RE
    try:
        rx = re.compile(rx_src)
    except re.error as ex:
        return f"Bad regex: {ex}"

    hits: list[str] = []
    seen: set[str] = set()
    for e in _entries(har_id):
        areas = {
            "url": e["url"],
            "req.headers": " ".join(f"{k}: {v}" for k, v in e["req_headers"].items()),
            "resp.headers": " ".join(f"{k}: {v}" for k, v in e["resp_headers"].items()),
            "cookies": " ".join(f'{c.get("name")}={c.get("value")}'
                                for c in e["req_cookies"] + e["resp_cookies"]),
            "params": " ".join(f'{p.get("name")}={p.get("value")}'
                               for p in e["query"] + e["post_params"]),
            "req.body": _safe_req(e),
            "resp.body": _safe_resp(e),
        }
        for where, val in areas.items():
            for m in rx.findall(val or ""):
                flag = m if isinstance(m, str) else m[0]
                key = (flag, where, e["i"])
                if key in seen:
                    continue
                seen.add(key)
                hits.append(f'#{e["i"]:>4} [{where}]  {flag}')
    if not hits:
        return (f"No flag-pattern matches for /{rx_src}/.\n"
                "Try extract(har_id,'base64') or extract(har_id,'jwts') — the flag "
                "may be encoded. Or search with a custom pattern.")
    return _cap(f"{len(hits)} candidate(s):\n" + "\n".join(hits))


# Generic, NOT-ctf-specific detectors. Each is (label, compiled regex).
_SECRET_DETECTORS = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")),
    ("bearer_auth", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}")),
    ("basic_auth", re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}")),
    ("sha256_hash", re.compile(r"\b[a-f0-9]{64}\b")),
    ("sha1_hash", re.compile(r"\b[a-f0-9]{40}\b")),
    ("md5_hash", re.compile(r"\b[a-f0-9]{32}\b")),
    ("uuid", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]
_SECRETY_PARAM = re.compile(r"token|auth|key|secret|session|passwo?r?d|pwd|jwt|sig|hash|otp|csrf", re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


@mcp.tool()
def scan(har_id: str, patterns: str = "", scope: str = "all",
         ignore_case: bool = True, max_results: int = 80) -> str:
    """
    General, format-agnostic scan — the dynamic alternative to find_flags.

    This does NOT assume any CTF flag format. Use it to hunt for whatever matters
    for THIS web app, or to discover secrets when you don't yet know what to look for.

    Two modes:
      * patterns GIVEN — supply one regex per line (or comma-separated). Every
        pattern is searched across all decoded fields (url, headers, cookies,
        params, request & response bodies) and hits are reported with location and
        a snippet. This is how you, the AI, drive the search with your own patterns
        derived from what you've learned about the app (usernames, endpoints, error
        strings, object IDs, config keys — anything).
      * patterns EMPTY — run a library of generic detectors (private keys, API keys
        for AWS/GitHub/Google/Slack/Stripe, JWTs, bearer/basic auth, md5/sha hashes,
        UUIDs, emails, IPs), flag secret-looking params by name, and surface
        high-entropy tokens that look like credentials. No flag format involved.

    Args:
        patterns:    newline- or comma-separated regexes; empty = generic detectors.
        scope:       "all" | "url" | "headers" | "cookies" | "params" |
                     "request_body" | "response_body" (applies to pattern mode).
        max_results: cap on hits reported.
    """
    es = _entries(har_id)
    cap = min(max_results, MAX_ITEMS)

    def field_map(e: dict) -> dict:
        return {
            "url": e["url"],
            "req.headers": " ".join(f"{k}: {v}" for k, v in e["req_headers"].items()),
            "resp.headers": " ".join(f"{k}: {v}" for k, v in e["resp_headers"].items()),
            "cookies": " ".join(f'{c.get("name")}={c.get("value")}'
                                for c in e["req_cookies"] + e["resp_cookies"]),
            "params": " ".join(f'{p.get("name")}={p.get("value")}'
                               for p in e["query"] + e["post_params"]),
            "req.body": _safe_req(e),
            "resp.body": _safe_resp(e),
        }

    scope_filter = {
        "url": {"url"}, "headers": {"req.headers", "resp.headers"},
        "cookies": {"cookies"}, "params": {"params"},
        "request_body": {"req.body"}, "response_body": {"resp.body"},
    }.get(scope)

    # ---- Mode 1: AI-supplied patterns ----
    if patterns.strip():
        pats = [p.strip() for p in re.split(r"[\n,]", patterns) if p.strip()]
        compiled = []
        for p in pats:
            try:
                compiled.append((p, re.compile(p, re.I if ignore_case else 0)))
            except re.error as ex:
                return f"Bad regex '{p}': {ex}"
        out, n = [], 0
        for e in es:
            fm = field_map(e)
            for fname, val in fm.items():
                if scope_filter and fname not in scope_filter:
                    continue
                for psrc, rx in compiled:
                    if val and rx.search(val):
                        for snip in _snippets(val, rx, max_hits=2):
                            out.append(f'#{e["i"]:>4} /{psrc}/ [{fname}] {snip}')
                            n += 1
                            if n >= cap:
                                out.append("[... more; narrow patterns/scope ...]")
                                return _cap("\n".join(out))
        return _cap("\n".join(out)) if out else f"No matches for the given pattern(s)."

    # ---- Mode 2: generic detectors (no preset flag format) ----
    found: list[str] = []
    seen: set = set()
    for e in es:
        blob = "\n".join(field_map(e).values())
        for label, rx in _SECRET_DETECTORS:
            for m in rx.findall(blob):
                val = m if isinstance(m, str) else m[0]
                key = (label, val)
                if key in seen:
                    continue
                seen.add(key)
                found.append(f'#{e["i"]:>4} [{label}] {val[:80]}')
        # secret-looking params by NAME (value may be anything)
        for p in e["query"] + e["post_params"]:
            nm = str(p.get("name", ""))
            if _SECRETY_PARAM.search(nm):
                key = ("param:" + nm, str(p.get("value")))
                if key not in seen:
                    seen.add(key)
                    found.append(f'#{e["i"]:>4} [param:{nm}] {str(p.get("value"))[:80]}')
        # high-entropy tokens in bodies/params/cookies (possible credentials)
        hay = " ".join([e["_resp_text"][:20000], e["_req_text"][:20000],
                        " ".join(f'{c.get("value")}' for c in e["req_cookies"] + e["resp_cookies"]),
                        " ".join(f'{p.get("value")}' for p in e["query"] + e["post_params"])])
        for tok in re.findall(r"[A-Za-z0-9+/_\-]{20,}={0,2}", hay):
            if tok in {k[1] for k in seen}:
                continue
            if _entropy(tok) >= 3.8:
                seen.add(("high_entropy", tok))
                found.append(f'#{e["i"]:>4} [high_entropy {_entropy(tok):.1f}] {tok[:60]}…')
        if len(found) >= cap:
            break
    if not found:
        return ("No generic secrets/high-entropy tokens detected. Supply your own "
                "patterns (newline/comma-separated) to scan for app-specific values.")
    return _cap(f"{len(found)} item(s) (generic detectors — no flag format assumed):\n"
                + "\n".join(found[:cap]))


@mcp.tool()
def extract(har_id: str, kind: str, max_items: int = 150) -> str:
    """
    Pull a category of artifacts across the whole capture.

    kind:
        fingerprint— web server + framework/CMS/CDN detected from headers & cookies
                     (Server, X-Powered-By, cookie names, CDN headers). Also aliased
                     as "server", "tech", "stack".
        cookies    — all request/response cookies (name=value, where seen)
        setcookie  — Set-Cookie response headers (with attributes)
        jwts       — JWT tokens, with decoded header+payload
        auth       — Authorization headers / Bearer / token-ish headers & params
        params     — all query + post parameters (name=value)
        comments   — HTML/JS/CSS comments found in response bodies
        base64     — long base64 blobs in bodies/params, with a decoded preview
        emails     — email addresses
        redirects  — 3xx entries and their Location/redirectURL
        hosts      — distinct hosts with request counts
    """
    kind = kind.lower().strip()
    es = _entries(har_id)
    lines: list[str] = []
    cap = min(max_items, MAX_ITEMS)

    if kind in ("fingerprint", "server", "tech", "stack"):
        return _cap(_fingerprint_report(es))

    if kind == "hosts":
        c = Counter(e["host"] for e in es if e["host"])
        return _cap("\n".join(f"{n:>5}  {h}" for h, n in c.most_common()))

    if kind == "cookies":
        seen = set()
        for e in es:
            for src, cks in (("req", e["req_cookies"]), ("resp", e["resp_cookies"])):
                for c in cks:
                    kv = f'{c.get("name")}={c.get("value")}'
                    if kv in seen:
                        continue
                    seen.add(kv)
                    lines.append(f'#{e["i"]:>4} [{src}] {kv}')
        return _cap("\n".join(lines[:cap])) if lines else "No cookies found."

    if kind == "setcookie":
        for e in es:
            for k, v in e["resp_headers"].items():
                if k.lower() == "set-cookie":
                    lines.append(f'#{e["i"]:>4} {v}')
        return _cap("\n".join(lines[:cap])) if lines else "No Set-Cookie headers found."

    if kind == "jwts":
        rx = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
        seen = set()
        for e in es:
            blob = " ".join([e["url"], e["_resp_text"], e["_req_text"],
                             " ".join(e["req_headers"].values()),
                             " ".join(e["resp_headers"].values()),
                             " ".join(f'{c.get("value")}' for c in e["req_cookies"] + e["resp_cookies"])])
            for tok in rx.findall(blob):
                if tok in seen:
                    continue
                seen.add(tok)
                lines.append(f'#{e["i"]:>4} {tok[:40]}…')
                lines.append("        " + _decode_jwt(tok).replace("\n", "\n        "))
        return _cap("\n".join(lines[:cap * 3])) if lines else "No JWTs found."

    if kind == "auth":
        for e in es:
            for k, v in list(e["req_headers"].items()) + list(e["resp_headers"].items()):
                lk = k.lower()
                if lk in ("authorization", "proxy-authorization", "x-api-key", "x-auth-token",
                          "x-access-token", "api-key", "cookie", "x-csrf-token", "www-authenticate"):
                    lines.append(f'#{e["i"]:>4} {k}: {v[:200]}')
            for p in e["query"] + e["post_params"]:
                if re.search(r"token|auth|key|secret|session|password|pwd|jwt", str(p.get("name", "")), re.I):
                    lines.append(f'#{e["i"]:>4} param {p.get("name")}={p.get("value")}')
        # de-dup preserving order
        seen = set(); dedup = [l for l in lines if not (l in seen or seen.add(l))]
        return _cap("\n".join(dedup[:cap])) if dedup else "No auth-looking headers/params found."

    if kind == "params":
        for e in es:
            for src, ps in (("q", e["query"]), ("p", e["post_params"])):
                for p in ps:
                    lines.append(f'#{e["i"]:>4} [{src}] {p.get("name")}={p.get("value")}')
        return _cap("\n".join(lines[:cap])) if lines else "No parameters found."

    if kind == "comments":
        rx = re.compile(r"<!--(.*?)-->|/\*(.*?)\*/", re.S)
        for e in es:
            if "html" in e["mime"] or "css" in e["mime"] or "javascript" in e["mime"] or "json" in e["mime"] or not e["mime"]:
                for m in rx.finditer(e["_resp_text"]):
                    c = (m.group(1) or m.group(2) or "").strip().replace("\n", " ")
                    if c:
                        lines.append(f'#{e["i"]:>4} {c[:200]}')
        return _cap("\n".join(lines[:cap])) if lines else "No HTML/JS/CSS comments found."

    if kind == "emails":
        rx = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
        seen = set()
        for e in es:
            for m in rx.findall(e["_resp_text"] + " " + e["_req_text"] + " " + e["url"]):
                if m not in seen:
                    seen.add(m); lines.append(f'#{e["i"]:>4} {m}')
        return _cap("\n".join(lines[:cap])) if lines else "No emails found."

    if kind == "redirects":
        for e in es:
            if 300 <= int(e["status"] or 0) < 400 or e["redirectURL"]:
                loc = e["resp_headers"].get("Location") or e["resp_headers"].get("location") or e["redirectURL"]
                lines.append(f'#{e["i"]:>4} {e["status"]} {e["url"]}  ->  {loc}')
        return _cap("\n".join(lines[:cap])) if lines else "No redirects found."

    if kind == "base64":
        rx = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
        seen = set()
        for e in es:
            haystack = e["_resp_text"] + " " + " ".join(f'{p.get("value")}' for p in e["query"] + e["post_params"])
            for blob in rx.findall(haystack):
                if blob in seen:
                    continue
                seen.add(blob)
                dec = _try_b64(blob)
                if dec is not None:
                    lines.append(f'#{e["i"]:>4} {blob[:36]}…  ->  {dec[:120]!r}')
        return _cap("\n".join(lines[:cap])) if lines else "No decodable base64 blobs (≥24 chars) found."

    return ("Unknown kind. Use one of: cookies, setcookie, jwts, auth, params, "
            "comments, base64, emails, redirects, hosts.")


@mcp.tool()
def decode(value: str, scheme: str = "auto") -> str:
    """
    Locally decode a value you found (a token, cookie, param). No network — pure
    transform. Great for peeking inside a JWT or a base64/hex/url-encoded string.

    scheme: "auto" (try several and show what's printable), or one of
            "base64", "base64url", "hex", "url", "jwt", "rot13".
    """
    value = value.strip()
    scheme = scheme.lower()

    def show(label: str, s: Optional[str]) -> Optional[str]:
        if s is None:
            return None
        printable = sum(c.isprintable() or c in "\n\r\t" for c in s) / max(1, len(s))
        if printable < 0.8 and scheme == "auto":
            return None
        return f"[{label}]\n{s}"

    if scheme == "jwt" or (scheme == "auto" and value.startswith("eyJ") and value.count(".") >= 1):
        return _cap(_decode_jwt(value))

    attempts = {
        "base64": _try_b64,
        "base64url": _try_b64url,
        "hex": _try_hex,
        "url": lambda v: urllib.parse.unquote_plus(v),
        "rot13": lambda v: codecs.encode(v, "rot_13"),
    }
    if scheme in attempts:
        res = attempts[scheme](value)
        return _cap(res if res is not None else f"Could not decode as {scheme}.")

    # auto: try all, report the printable ones
    outs = []
    for name, fn in attempts.items():
        r = show(name, fn(value))
        if r:
            outs.append(r)
    return _cap("\n\n".join(outs)) if outs else "Nothing decoded to printable text. Try an explicit scheme."


@mcp.tool()
def unload_har(har_id: str) -> str:
    """Forget a loaded HAR (frees memory). The file on disk is untouched."""
    if _HARS.pop(har_id, None):
        return f"Unloaded {har_id}."
    return f"No such har_id '{har_id}'."


# --------------------------------------------------------------------------- #
# Pure-local decoders (no network)
# --------------------------------------------------------------------------- #

def _try_b64(s: str) -> Optional[str]:
    try:
        pad = s + "=" * (-len(s) % 4)
        raw = base64.b64decode(pad, validate=True)
        return raw.decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None


def _try_b64url(s: str) -> Optional[str]:
    try:
        pad = s + "=" * (-len(s) % 4)
        raw = base64.urlsafe_b64decode(pad)
        return raw.decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None


def _try_hex(s: str) -> Optional[str]:
    t = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(t) < 2 or len(t) % 2:
        return None
    try:
        return bytes.fromhex(t).decode("utf-8", "replace")
    except ValueError:
        return None


def _decode_jwt(tok: str) -> str:
    parts = tok.split(".")
    if len(parts) < 2:
        return "(not a JWT)"
    out = []
    for name, seg in (("header", parts[0]), ("payload", parts[1])):
        dec = _try_b64url(seg) or _try_b64(seg) or ""
        try:
            dec = json.dumps(json.loads(dec), indent=2)
        except (json.JSONDecodeError, ValueError):
            pass
        out.append(f"{name}: {dec}")
    out.append(f"signature: {parts[2] if len(parts) > 2 else '(none)'}  [not verified; no network]")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Local bridge: a localhost-only HTTP listener embedded in this MCP process so a
# browser extension can POST a captured HAR and poll the AI's replies. NO traffic
# leaves the machine; it binds 127.0.0.1 and requires a per-session random token.
# --------------------------------------------------------------------------- #

_BRIDGE = {
    "token": None,
    "port": None,
    "incoming": [],   # HARs received from the extension (awaiting bridge_poll)
    "outgoing": [],   # messages from the AI to the extension panel
    "msg_id": 0,
    "lock": threading.Lock(),
}
BRIDGE_START_PORT = int(os.environ.get("HARSCOPE_BRIDGE_PORT", "7331"))


class _BridgeHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep stdout/stderr clean (stdout is the MCP channel)
        return

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "X-Harscope-Token, Content-Type")
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
        return bool(_BRIDGE["token"]) and self.headers.get("X-Harscope-Token") == _BRIDGE["token"]

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path == "/ping":
            return self._send(200, {"ok": True, "service": "harscope-bridge",
                                    "pending": len(_BRIDGE["incoming"])})
        if self.path.startswith("/messages"):
            if not self._auth():
                return self._send(401, {"error": "bad or missing token"})
            try:
                since = int(urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                            .get("since", ["0"])[0])
            except ValueError:
                since = 0
            with _BRIDGE["lock"]:
                msgs = [m for m in _BRIDGE["outgoing"] if m["id"] > since]
            return self._send(200, {"messages": msgs})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/har":
            return self._send(404, {"error": "not found"})
        if not self._auth():
            return self._send(401, {"error": "bad or missing token"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            har = json.loads(raw)
        except (ValueError, OSError):
            return self._send(400, {"error": "body is not valid JSON"})
        name = self.headers.get("X-Har-Name", "capture.har")
        with _BRIDGE["lock"]:
            _BRIDGE["incoming"].append({"name": name, "har": har, "ts": time.time()})
            pending = len(_BRIDGE["incoming"])
        return self._send(200, {"ok": True, "pending": pending})


def _bridge_push(kind: str, text: str) -> int:
    with _BRIDGE["lock"]:
        _BRIDGE["msg_id"] += 1
        mid = _BRIDGE["msg_id"]
        _BRIDGE["outgoing"].append({"id": mid, "type": kind, "text": text, "ts": time.time()})
        # keep only the most recent 100 messages
        _BRIDGE["outgoing"][:] = _BRIDGE["outgoing"][-100:]
    return mid


def _bridge_start() -> Optional[int]:
    if _BRIDGE["port"]:
        return _BRIDGE["port"]
    _BRIDGE["token"] = secrets.token_urlsafe(18)
    srv = None
    for p in range(BRIDGE_START_PORT, BRIDGE_START_PORT + 25):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), _BridgeHandler)
            _BRIDGE["port"] = p
            break
        except OSError:
            continue
    if not srv:
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        d = Path.home() / ".harscope"
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
    """
    Report the local bridge the browser extension connects to. Give the user the
    URL and token so their harscope extension targets THIS session.
    """
    if not _BRIDGE["port"]:
        return ("Bridge is not running (port busy or disabled). The extension can't "
                "reach this session; the user can still export a .har and load_har it.")
    with _BRIDGE["lock"]:
        pending = len(_BRIDGE["incoming"])
    return (f"Bridge live:  http://127.0.0.1:{_BRIDGE['port']}\n"
            f"Token:        {_BRIDGE['token']}\n"
            f"Pending captures: {pending}\n\n"
            "In the harscope extension's settings, paste that URL and token, then "
            "Connect. After the user captures a tab and clicks Send, call bridge_poll().")


@mcp.tool()
def bridge_poll() -> str:
    """
    Receive the next HAR the extension sent and auto-load it (returns the same
    profile as load_har, including the har_id). Call this after the user says they
    clicked Send, or on a loop. Returns a waiting message if nothing has arrived.
    """
    if not _BRIDGE["port"]:
        return "Bridge is not running. Ask the user to export a .har and use load_har()."
    with _BRIDGE["lock"]:
        item = _BRIDGE["incoming"].pop(0) if _BRIDGE["incoming"] else None
        remaining = len(_BRIDGE["incoming"])
    if not item:
        return ("No capture received yet. Ask the user to browse the challenge in the "
                "tab, then click Send in the harscope extension; call bridge_poll() again after.")
    fd, path = tempfile.mkstemp(suffix=".har", prefix="harscope_bridge_")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(item["har"], f)
    except OSError as ex:
        return f"Received a capture but could not stage it: {ex}"
    profile = load_har(path)
    return f"Received '{item['name']}' from the extension ({remaining} more queued).\n\n{profile}"


@mcp.tool()
def bridge_say(text: str) -> str:
    """
    Show an answer/finding in the extension's floating panel (and keep talking in
    the session too). Use for the actual answers to the user's questions.
    """
    if not _BRIDGE["port"]:
        return "Bridge not running; reply in the session instead."
    _bridge_push("answer", text)
    return "Sent to the extension panel."


@mcp.tool()
def bridge_ask(text: str) -> str:
    """
    Ask the user, in the extension panel, to perform an action and send a fresh
    capture — e.g. 'Visit /admin with Preserve log on, then click Send', or a curl
    to run. Use this instead of guessing when data is missing.
    """
    if not _BRIDGE["port"]:
        return "Bridge not running; ask in the session instead."
    _bridge_push("request", text)
    return "Action request sent to the extension panel."


def main() -> None:
    _bridge_start()
    mcp.run()


if __name__ == "__main__":
    main()
