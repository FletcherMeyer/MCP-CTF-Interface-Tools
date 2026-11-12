# harscope — interpret HAR files for CTF (no network)

A companion MCP server to `logsandbox`, but for **HAR files** (HTTP Archive JSON
exported from browser devtools / proxies). It is built for **CTF** work and makes
**zero network requests** — it only parses and interprets the capture you give it.

## Why not just grep the .har?

A HAR is one big JSON document, and response bodies are usually **base64-encoded**
and JSON is **minified**. Raw reads and raw `grep` are useless on it and flood the
model's context. `harscope` instead:

1. **`load_har`** — parses once, decodes base64 bodies and decompresses gzip /
   deflate / brotli (`Content-Encoding`) bodies, returns a compact profile
   (hosts / methods / statuses / mime types / time span) plus a **CTF artifact
   scan** (flag matches, JWTs, Set-Cookies, base64 blobs).
2. **Structured, bounded queries** against the index — you never pull the whole file.

## Tools

| Tool | Purpose |
|------|---------|
| `load_har(path)` | Parse + index a HAR. **Do this first.** |
| `list_hars()` | Show loaded HARs. |
| `scan(har_id, patterns?)` | **Dynamic, format-agnostic hunt.** You supply the regex(es) for whatever matters in this app; with no patterns it surfaces generic secrets (API keys, JWTs, auth, hashes, high-entropy tokens). |
| `find_flags(har_id, pattern?)` | Convenience shortcut defaulting to the literal `word{...}` flag format (override with your own `pattern`). |
| `extract(har_id, kind)` | Pull a category across the capture: `fingerprint` (web server + framework/CMS/CDN), `cookies`, `setcookie`, `jwts`, `auth`, `params`, `comments`, `base64`, `emails`, `redirects`, `hosts`. |
| `search(har_id, pattern, scope?)` | Regex across **decoded** urls/headers/cookies/params/bodies. |
| `list_entries(har_id, …)` | Table of requests (filter by host/method/status/mime/url). |
| `entry(har_id, index, part?)` | One entry's request/response/headers (body summarized). |
| `body(har_id, index, which?, mode?)` | Full decoded body of one entry (`hex` mode for binary). |
| `decode(value, scheme?)` | Local decoder: `base64`/`base64url`/`hex`/`url`/`jwt`/`rot13`/`auto`. |
| `unload_har(har_id)` | Free memory. |

## The AI drives the patterns

`scan` and `search` (and `find_flags`) all take **arbitrary regex supplied by the
AI** — nothing is hardcoded to a CTF keyword. The intended loop is:

1. Read the traffic generally (`list_entries` / `entry` / `body`) and form a
   hypothesis about *this* app.
2. `scan(har_id, patterns=...)` with your own patterns (a username you saw, an
   endpoint, an object id, an error string, a config key — whatever the app
   reveals). Format-agnostic; no `flag{}` assumption.
3. `scan(har_id)` with **no** pattern to surface generic secrets (API keys,
   private keys, JWTs, bearer/basic auth, hashes, UUIDs, high-entropy tokens,
   emails, IPs) and secret-looking params — useful when you don't yet know what
   you're looking for.

`find_flags` is just the special case of step 2 pre-filled with the literal
`word{...}` flag format.

## Typical CTF flow

```
load_har("C:\\ctf\\capture.har")      -> har_id a1b2c3, 142 entries, 3 JWTs, 7 base64 blobs
scan("a1b2c3")                         -> generic: 3 JWTs, 1 high-entropy cookie, password param
entry("a1b2c3", 7); body("a1b2c3", 7)  -> read what looks interesting
scan("a1b2c3", patterns="admin\\b, api_key, user_id=\\d+")   -> app-specific hunt, your patterns
extract("a1b2c3", "jwts")              -> payload has {"role":"user","note":"ZmxhZ3s..."}
decode("ZmxhZ3s...", "base64")         -> reveals the hidden value
find_flags("a1b2c3")                   -> only if the target really is in flag{...} form
```

## Install & register

```bash
pip install -r requirements.txt
```

```bash
claude mcp add harscope -- python "C:\path\to\har_server.py"
```

Or add to your MCP config (same shape as `claude_config_snippet.json`, with
`"harscope"` as the key and `har_server.py` as the arg). No env vars are required;
optional ones: `HARSCOPE_MAX_CHARS` (default 12000), `HARSCOPE_MAX_ITEMS` (200).

## Safety

- **No network, ever.** The server imports no HTTP client; it only reads the local
  `.har` and transforms bytes (base64/hex/url/jwt decoding is pure-local math).
- **Untrusted input.** CTF captures are adversarial data; `harscope` treats all
  bodies as data and never executes them. JWT signatures are shown but **not
  verified** (that would need a network/secret), and clearly labelled as such.
- **Bounded output.** Every tool caps characters/rows so a huge capture can't flood
  context.
