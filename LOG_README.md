# logsandbox — an MCP server for log files via a WSL sandbox

Log files are often huge. Reading one raw into the model's context is wasteful
and usually answers nothing. `logsandbox` makes the agent work a log the way a
human operator does on a box:

1. **Deploy** the log into an isolated WSL sandbox (a *copy*, never the original).
2. **Run bounded commands** on it there — with the patterns, fields and time
   formats **you** supply after looking at the log.

There is deliberately **no "read the whole file" tool**, and the tools make **no
assumptions about log format** — no canned level histogram, no fixed timestamp
shape. You read the sample, form a hypothesis, then drive the queries. Every
result is capped to a few hundred lines / tens of KB.

## Requirements

- Windows with **WSL** installed (`wsl.exe` on PATH) and a default distro.
- **Python 3.10+** (on Windows — it shells out to `wsl.exe`).
- `pip install -r requirements.txt` (just the `mcp` package).

## Register with Claude Code

```bash
claude mcp add logsandbox -- python C:\path\to\server.py
```

## Tools

| Tool | What it does |
|------|--------------|
| `deploy_log(path, label?)` | Copy a log into the sandbox; returns a `log_id` + **neutral** profile (size, line count, first/last line sample — no format assumed). `.gz` auto-decompressed. **Do this first.** |
| `list_logs()` | List deployed logs and their `log_id`s. |
| `search(log_id, pattern, …)` | Regex (grep -E) search with context lines, match cap, or `count_only`. |
| `filter(log_id, include, exclude, …)` | Keep lines matching `include`, drop lines matching `exclude`. |
| `tail` / `head(log_id, lines)` | Last / first N lines. |
| `slice(log_id, start, end)` | Exact 1-indexed line range. |
| `sample(log_id, n)` | N lines evenly spaced across the whole file. |
| `stats(log_id, pattern?)` | Line/word/byte counts + longest line; optional **your** pattern to count matching lines. |
| `timeline(log_id, time_regex?, bucket_chars?, pattern?)` | Bucket volume over time using a timestamp regex **you** define (works on any format, not just ISO). |
| `top(log_id, field_regex, …)` | Extract a value (IP, status, id…) with your regex and rank by frequency. |
| `pipeline(log_id, command)` | Custom read-only shell pipeline (allow-listed commands only). |
| `remove_log(log_id)` | Delete the sandbox copy (original untouched). |

## Typical flow (you drive every step)

```
deploy_log("C:\\logs\\app.log")   -> log_id abc1234567; read the first/last sample
top("abc1234567", "status=[0-9]{3}")          -> which statuses dominate
timeline("abc1234567", time_regex="^[0-9-]{10}T[0-9:]{8}", bucket_chars=13, pattern="ERROR")
search("abc1234567", "OutOfMemory", after=5)  -> line 7,431,002
slice("abc1234567", 7430990, 7431050)         -> read just that region
```

## Configuration (env vars)

| Variable | Default | Meaning |
|----------|---------|---------|
| `LOGSANDBOX_DIR` | `$HOME/.claude-logsandbox` | Sandbox path **inside WSL**. |
| `LOGSANDBOX_WSL_DISTRO` | *(default distro)* | Pin a specific distro (`wsl -d <name>`). |
| `LOGSANDBOX_TIMEOUT` | `30` | Per-command timeout (seconds). |
| `LOGSANDBOX_MAX_LINES` | `400` | Max lines any tool returns. |
| `LOGSANDBOX_MAX_BYTES` | `60000` | Max bytes any tool returns. |

## Safety model

- **Sandbox copy.** The original is read once at deploy and copied in; tools only
  touch the copy inside `LOGSANDBOX_DIR`. Use a throwaway distro via
  `LOGSANDBOX_WSL_DISTRO` for stronger isolation.
- **No shell injection.** User-supplied patterns/paths pass as positional `$1`,
  `$2` bash args, never interpolated into the script text.
- **`pipeline` is locked down.** Shell control characters are rejected, and every
  stage's command must be in a read-only allowlist. No redirection/subshells/chaining.
- **Bounded output.** Every tool caps lines and bytes and says when it truncated.
