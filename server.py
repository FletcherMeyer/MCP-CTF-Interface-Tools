#!/usr/bin/env python3
"""
logsandbox — an MCP server for interacting with log files through a WSL sandbox.

Philosophy
----------
Log files are often huge. Pulling them into the model's context raw wastes the
budget and usually answers nothing. This server makes the agent work the way a
human operator does on a box:

    1. DEPLOY the log into an isolated WSL sandbox (a copy, never the original).
    2. RUN bounded commands on it there (search / tail / stats / pipeline).

There is intentionally **no** "read this whole file" tool. Every tool returns a
bounded, truncated result, so the context stays small no matter how big the log
is. All work happens inside WSL, against a copy, under a size/time cap.

Environment variables
----------------------
    LOGSANDBOX_DIR        Sandbox path *inside WSL* (default: ~/.claude-logsandbox)
    LOGSANDBOX_WSL_DISTRO Optional WSL distro name to pin (wsl.exe -d <distro>)
    LOGSANDBOX_TIMEOUT    Default per-command timeout in seconds (default: 30)
    LOGSANDBOX_MAX_LINES  Max lines returned by any tool (default: 400)
    LOGSANDBOX_MAX_BYTES  Max bytes returned by any tool (default: 60000)
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import subprocess
import time
from typing import Optional

from mcp.server.fastmcp import FastMCP

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

SANDBOX_DIR = os.environ.get("LOGSANDBOX_DIR", "$HOME/.claude-logsandbox").strip()
WSL_DISTRO = os.environ.get("LOGSANDBOX_WSL_DISTRO", "").strip()
DEFAULT_TIMEOUT = int(os.environ.get("LOGSANDBOX_TIMEOUT", "30"))
MAX_LINES = int(os.environ.get("LOGSANDBOX_MAX_LINES", "400"))
MAX_BYTES = int(os.environ.get("LOGSANDBOX_MAX_BYTES", "60000"))

# Commands allowed inside a user-supplied pipeline. Read-only text tools only.
PIPELINE_ALLOW = {
    "grep", "egrep", "fgrep", "awk", "gawk", "sed", "tail", "head", "wc",
    "sort", "uniq", "cut", "tr", "rev", "nl", "cat", "tac", "fold", "column",
    "jq", "cut", "paste", "comm", "tee", "xxd", "od", "strings", "date",
}
# Sequences that could break out of a single read-only pipe chain into shell
# control. Note we deliberately ALLOW $ { } ( ) so awk/sed programs work
# (e.g. awk '{print $3}'); subshell/standalone stages are still caught by the
# per-stage command allowlist below. What we forbid is command substitution,
# command chaining, backgrounding, and redirection.
PIPELINE_FORBIDDEN = re.compile(r"\$\(|\$\{|`|;|&|>|<|\|\||\\|\n")

INSTRUCTIONS = """\
logsandbox gives you a WSL sandbox for log files. DO NOT read a log file raw with
generic file tools — a log can be gigabytes and will blow your context.

YOU drive this. The tools don't assume any log format or run canned checks; they
take the patterns, fields and time formats YOU supply after looking at the log.
Read the sample, form a hypothesis about THIS log, then query it.

Workflow:
  1. deploy_log(path) -> copies the log in and returns a neutral profile: size,
                         line count, and a sample of the first/last lines. Read it
                         to see the actual format before deciding anything.
  2. Investigate with bounded tools against that log_id, giving your own inputs:
       search / filter (your regex), top (your field regex), timeline (your time
       pattern), stats (optional pattern), slice / sample, pipeline (custom awk/sed).
     Every result is capped. Prefer counting/aggregating (top, stats, timeline,
     search count) over dumping lines; pull raw lines only once you've located the
     region of interest. Add your own commentary on what the data means.
"""

mcp = FastMCP("logsandbox", instructions=INSTRUCTIONS)

# log_id -> {"name": <sandbox filename>, "src": <original path>}
_REGISTRY: dict[str, dict] = {}


# --------------------------------------------------------------------------- #
# WSL plumbing
# --------------------------------------------------------------------------- #

def _wsl_base() -> list[str]:
    base = ["wsl.exe"]
    if WSL_DISTRO:
        base += ["-d", WSL_DISTRO]
    return base


class WslError(RuntimeError):
    pass


def _run_bash(script: str, *args: str, timeout: Optional[int] = None) -> str:
    """
    Run `script` with bash inside WSL. Positional args are passed safely as
    $1, $2, ... so user-supplied values (patterns, paths) are never interpolated
    into the script text and cannot inject shell.
    """
    timeout = timeout or DEFAULT_TIMEOUT
    cmd = _wsl_base() + ["-e", "bash", "-c", script, "logsandbox", *args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        raise WslError(
            "wsl.exe not found. This server requires Windows Subsystem for Linux."
        )
    except subprocess.TimeoutExpired:
        raise WslError(f"Command timed out after {timeout}s.")
    if proc.returncode != 0 and proc.stderr.strip():
        # grep returns 1 on "no match" with empty stderr — that's not an error.
        raise WslError(proc.stderr.strip())
    return proc.stdout


def _cap(text: str) -> str:
    """Trim output to the configured line/byte caps and annotate if trimmed."""
    trimmed = False
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES]
        trimmed = True
    out = "\n".join(lines)
    if len(out.encode("utf-8", "replace")) > MAX_BYTES:
        out = out.encode("utf-8", "replace")[:MAX_BYTES].decode("utf-8", "replace")
        trimmed = True
    if trimmed:
        out += (
            f"\n\n[... output truncated to {MAX_LINES} lines / {MAX_BYTES} bytes."
            " Narrow your query (add a pattern, a line range, or aggregate instead). ...]"
        )
    return out or "(no output)"


def _require(log_id: str) -> dict:
    entry = _REGISTRY.get(log_id)
    if not entry:
        # Attempt to rehydrate from the sandbox (e.g. after a server restart).
        _scan_sandbox()
        entry = _REGISTRY.get(log_id)
    if not entry:
        raise WslError(
            f"Unknown log_id '{log_id}'. Call list_logs() or deploy_log() first."
        )
    return entry


def _logfile(log_id: str) -> str:
    """Sandbox-absolute path (shell expression) for a deployed log."""
    name = _require(log_id)["name"]
    return f'"{SANDBOX_DIR}/{name}"'


def _scan_sandbox() -> None:
    """Repopulate the in-memory registry by listing the sandbox directory."""
    script = (
        f'mkdir -p "{SANDBOX_DIR}"; cd "{SANDBOX_DIR}" || exit 0; '
        'for f in *.log; do [ -e "$f" ] || continue; '
        'id="${f%.log}"; src="$(cat "$id.src" 2>/dev/null)"; '
        'printf "%s\\t%s\\n" "$id" "$src"; done'
    )
    try:
        out = _run_bash(script)
    except WslError:
        return
    for line in out.splitlines():
        if "\t" in line:
            lid, src = line.split("\t", 1)
        else:
            lid, src = line.strip(), ""
        if lid:
            _REGISTRY.setdefault(lid, {"name": f"{lid}.log", "src": src})


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #

@mcp.tool()
def deploy_log(path: str, label: str = "") -> str:
    """
    Deploy a log file into the WSL sandbox so you can run commands on it.

    This is the FIRST thing you do with any log. It copies the file (a Windows
    path like C:\\logs\\app.log, or an existing WSL/Linux path) into an isolated
    sandbox directory and returns a short `log_id` plus a neutral profile: size,
    line count, and a sample of the first and last lines so you can SEE the log's
    actual shape and decide what to do. It makes no assumptions about the log's
    format or levels — read the sample, then drive the query tools yourself.
    .gz files are decompressed automatically.

    Use the returned log_id with every other tool. Do NOT read the original file
    raw — work it through these tools instead.

    Args:
        path:  Path to the log file. Windows (C:\\...), /mnt/..., or ~/... all work.
        label: Optional human label, recorded alongside the log.
    """
    # Build an id from the path so re-deploying the same file is idempotent.
    log_id = hashlib.sha1(f"{path}".encode()).hexdigest()[:10]
    name = f"{log_id}.log"
    dest = f'"{SANDBOX_DIR}/{name}"'

    # Convert a Windows path to a WSL path; pass through anything already POSIX.
    script = f"""
set -e
mkdir -p "{SANDBOX_DIR}"
src="$1"
case "$src" in
  [A-Za-z]:\\\\*|[A-Za-z]:/*) src="$(wslpath -a "$src")" ;;
  '~'/*) src="$HOME/${{src#'~'/}}" ;;
esac
if [ ! -f "$src" ]; then echo "NO_SUCH_FILE:$src" >&2; exit 2; fi
case "$src" in
  *.gz) gzip -dc "$src" > {dest} ;;
  *)    cp -f "$src" {dest} ;;
esac
printf '%s' "$2" > "{SANDBOX_DIR}/{log_id}.src"
# Profile
bytes=$(wc -c < {dest} | tr -d ' ')
lines=$(wc -l < {dest} | tr -d ' ')
echo "BYTES=$bytes"
echo "LINES=$lines"
echo "---FIRST---"
head -n 3 {dest}
echo "---LAST---"
tail -n 3 {dest}
""".strip()

    src_label = label or path
    out = _run_bash(script, path, src_label, timeout=max(DEFAULT_TIMEOUT, 120))
    if "NO_SUCH_FILE:" in out:
        bad = out.split("NO_SUCH_FILE:", 1)[1].strip()
        return f"File not found inside the sandbox: {bad}\n(Original path given: {path})"

    _REGISTRY[log_id] = {"name": name, "src": src_label}

    # Format the profile nicely.
    def _section(tag: str) -> str:
        m = re.search(rf"---{tag}---\n(.*?)(?=\n---|\Z)", out, re.S)
        return (m.group(1).strip() if m else "")

    bytes_ = re.search(r"BYTES=(\d+)", out)
    lines_ = re.search(r"LINES=(\d+)", out)
    size_mb = (int(bytes_.group(1)) / 1_048_576) if bytes_ else 0.0

    def _indent(s: str) -> str:
        return "\n".join("  " + ln for ln in s.splitlines()) or "  (empty)"

    return (
        f"Deployed '{src_label}' -> log_id: {log_id}\n"
        f"Size: {size_mb:.2f} MB   Lines: {lines_.group(1) if lines_ else '?'}\n\n"
        f"First lines:\n{_indent(_section('FIRST'))}\n\n"
        f"Last lines:\n{_indent(_section('LAST'))}\n\n"
        "Read the sample above to see the log's format, then drive it: search / "
        "filter (your regex), top (your field regex), timeline (your time pattern), "
        "slice / sample, or pipeline for a custom awk/sed. No format is assumed."
    )


@mcp.tool()
def list_logs() -> str:
    """List every log currently deployed in the sandbox, with its log_id and source."""
    _scan_sandbox()
    if not _REGISTRY:
        return "No logs deployed yet. Call deploy_log(path) first."
    rows = [f"{lid}\t{e['src'] or '(unknown source)'}" for lid, e in _REGISTRY.items()]
    return "log_id    \tsource\n" + "\n".join(rows)


@mcp.tool()
def search(log_id: str, pattern: str, ignore_case: bool = True,
           before: int = 0, after: int = 0, max_matches: int = 200,
           count_only: bool = False) -> str:
    """
    Search a deployed log with a regular expression (grep -E).

    Start here to find where something happens. Use count_only=True first to see
    how common a pattern is before pulling matching lines.

    Args:
        log_id:      From deploy_log.
        pattern:     Extended regex (ERE), e.g. "ERROR|FATAL" or "user_id=42\\b".
        ignore_case: Case-insensitive match (default True).
        before/after: Context lines to include around each match.
        max_matches: Cap on matching lines returned (default 200).
        count_only:  Return just the number of matching lines.
    """
    f = _logfile(log_id)
    flags = "-naE"
    if ignore_case:
        flags += "i"
    if count_only:
        script = f'grep {flags} -c -- "$1" {f} || echo 0'
        out = _run_bash(script, pattern)
        return f"{out.strip()} matching lines for /{pattern}/ in {log_id}."
    ctx = ""
    if before:
        ctx += f" -B {int(before)}"
    if after:
        ctx += f" -A {int(after)}"
    script = f'grep {flags}{ctx} -- "$1" {f} | head -n {int(max_matches)} || true'
    out = _run_bash(script, pattern)
    return _cap(out) if out.strip() else f"No matches for /{pattern}/ in {log_id}."


@mcp.tool()
def filter(log_id: str, include: str = "", exclude: str = "",
           max_lines: int = 300) -> str:
    """
    Filter a log by an include pattern and/or an exclude pattern (both ERE regex).

    Handy for "show me ERROR lines but drop the noisy health-check ones":
        include="ERROR", exclude="healthcheck".

    Args:
        log_id:   From deploy_log.
        include:  Keep only lines matching this regex (empty = keep all).
        exclude:  Then drop lines matching this regex (empty = drop none).
        max_lines: Cap on lines returned.
    """
    if not include and not exclude:
        return "Provide at least an include or an exclude pattern."
    f = _logfile(log_id)
    parts = [f"cat {f}"]
    args: list[str] = []
    if include:
        parts.append('grep -aiE -- "$1"')
        args.append(include)
    if exclude:
        idx = len(args) + 1
        parts.append(f'grep -aivE -- "${idx}"')
        args.append(exclude)
    parts.append(f"head -n {int(max_lines)}")
    script = " | ".join(parts) + " || true"
    out = _run_bash(script, *args)
    return _cap(out) if out.strip() else "No lines matched the filter."


@mcp.tool()
def tail(log_id: str, lines: int = 50) -> str:
    """Return the last N lines of a deployed log (default 50). Good for 'what happened last'."""
    f = _logfile(log_id)
    out = _run_bash(f"tail -n {int(lines)} {f}")
    return _cap(out)


@mcp.tool()
def head(log_id: str, lines: int = 50) -> str:
    """Return the first N lines of a deployed log (default 50). Good for 'how does it start'."""
    f = _logfile(log_id)
    out = _run_bash(f"head -n {int(lines)} {f}")
    return _cap(out)


@mcp.tool()
def slice(log_id: str, start_line: int, end_line: int) -> str:
    """
    Return an exact line range [start_line, end_line] (1-indexed, inclusive).

    Use this to zoom into a region you located with search (grep reports line
    numbers) without dumping the whole file.
    """
    start_line = max(1, int(start_line))
    end_line = max(start_line, int(end_line))
    f = _logfile(log_id)
    out = _run_bash(f"sed -n '{start_line},{end_line}p' {f}")
    return _cap(out)


@mcp.tool()
def sample(log_id: str, n: int = 40) -> str:
    """
    Return N lines evenly spaced across the whole log (default 40).

    A fast way to see the shape of a large log without reading it top to bottom.
    """
    n = max(1, int(n))
    f = _logfile(log_id)
    script = (
        f'total=$(wc -l < {f}); if [ "$total" -le {n} ]; then cat {f}; else '
        f'awk -v t="$total" -v n={n} "NR % int(t/n+1)==0" {f} | head -n {n}; fi'
    )
    out = _run_bash(script)
    return _cap(out)


@mcp.tool()
def stats(log_id: str, pattern: str = "") -> str:
    """
    Structural summary of a log without dumping it: line / word / byte counts and
    the longest-line length. Makes no assumption about the log's format.

    Args:
        pattern: optional ERE regex. When given, also reports how many lines match
                 and what fraction of the file that is — so YOU decide what to
                 count (a level, a status, an id), rather than a preset schema.
                 For a frequency breakdown of a value, use top() with your regex.
    """
    f = _logfile(log_id)
    if pattern:
        script = (f'echo "--- counts (lines words bytes) ---"; wc {f}; '
                  f'echo "--- longest line (chars) ---"; awk \'{{ if (length>m) m=length }} END {{ print m }}\' {f}; '
                  f'echo "--- lines matching your pattern ---"; '
                  f'total=$(wc -l < {f}); hit=$(grep -aEc -- "$1" {f} || echo 0); '
                  f'echo "$hit of $total lines"')
        out = _run_bash(script, pattern)
    else:
        script = (f'echo "--- counts (lines words bytes) ---"; wc {f}; '
                  f'echo "--- longest line (chars) ---"; awk \'{{ if (length>m) m=length }} END {{ print m }}\' {f}')
        out = _run_bash(script)
    return _cap(out)


@mcp.tool()
def timeline(log_id: str, time_regex: str = "", bucket_chars: int = 0,
             pattern: str = "") -> str:
    """
    Bucket log volume over time to spot spikes. YOU define what a timestamp looks
    like, so this works on any format — not just ISO logs.

    Args:
        time_regex:   ERE that matches the timestamp token to group by. Default is
                      a leading ISO timestamp (^YYYY-MM-DDtHH:MM:SS). Override it to
                      fit the log you saw in deploy_log, e.g.
                      '^[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}' for Apache, or
                      '\\[[0-9]{2}:[0-9]{2}:[0-9]{2}' for a bracketed clock.
        bucket_chars: keep only the first N chars of each matched timestamp (coarser
                      buckets). 0 = keep the whole match. e.g. 13 = hour on ISO.
        pattern:      optional ERE to count only lines matching it (when does X spike).
    """
    f = _logfile(log_id)
    trx = time_regex or r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}"
    pre = f'grep -aiE -- "$2" {f}' if pattern else f"cat {f}"
    trunc = f"cut -c1-{int(bucket_chars)}" if bucket_chars and int(bucket_chars) > 0 else "cat"
    script = (
        f'{pre} | grep -oaE -- "$1" | {trunc} | sort | uniq -c | sort -k2 '
        f"| tail -n {MAX_LINES} || true"
    )
    args = [trx, pattern] if pattern else [trx]
    out = _run_bash(script, *args)
    if not out.strip():
        return (f"No matches for your time_regex /{trx}/. Look at deploy_log's sample "
                "lines and give a time_regex that matches this log's timestamp, or use "
                "top() / pipeline for a custom grouping.")
    return _cap("count  bucket\n" + out)


@mcp.tool()
def top(log_id: str, field_regex: str, max_items: int = 20,
        ignore_case: bool = True) -> str:
    """
    Extract a repeated value with a regex and rank it by frequency.

    Great for "which IPs / status codes / user ids appear most?". The first
    capture-group-free match on each line is counted. Example field_regex:
        status=[0-9]{3}      -> ranks status codes
        [0-9]{1,3}(\\.[0-9]{1,3}){3}  -> ranks IPv4 addresses

    Args:
        field_regex: ERE pattern whose match is the value to tally.
        max_items:   How many top values to return (default 20).
    """
    f = _logfile(log_id)
    flags = "-oaE" + ("i" if ignore_case else "")
    script = (
        f'grep {flags} -- "$1" {f} | sort | uniq -c | sort -rn '
        f"| head -n {int(max_items)} || true"
    )
    out = _run_bash(script, field_regex)
    return _cap("count  value\n" + out) if out.strip() else "No values matched."


@mcp.tool()
def pipeline(log_id: str, command: str) -> str:
    """
    Run a custom read-only shell pipeline against a deployed log (power user).

    The log is fed to the pipeline on stdin, so write the pipeline as if the file
    were `cat`-ed into it. Example:
        command = "awk '{print $1}' | sort | uniq -c | sort -rn | head"

    Only these commands are allowed (no redirection, subshells, or chaining):
        grep egrep fgrep awk gawk sed tail head wc sort uniq cut tr rev nl cat
        tac fold column jq paste comm tee xxd od strings date
    Output is capped. Use the purpose-built tools (search/stats/timeline/top)
    when they fit — reach for this only for something they don't cover.
    """
    cmd = command.strip()
    if not cmd:
        return "Empty pipeline."
    if PIPELINE_FORBIDDEN.search(cmd):
        return ("Rejected: the pipeline contains a forbidden shell sequence "
                "(command substitution $(…)/`…`/${…}, chaining ; && ||, "
                "backgrounding &, or redirection < >). Only a simple read-only "
                "pipe chain (stages joined by single |) is permitted. awk/sed "
                "braces and $fields are fine.")
    # Validate every stage's leading command against the allowlist.
    for stage in cmd.split("|"):
        tokens = shlex.split(stage.strip(), posix=True) if stage.strip() else []
        if not tokens:
            return "Rejected: empty pipeline stage."
        prog = os.path.basename(tokens[0])
        if prog not in PIPELINE_ALLOW:
            return (f"Rejected: command '{prog}' is not allowed. Allowed: "
                    + ", ".join(sorted(PIPELINE_ALLOW)))
    f = _logfile(log_id)
    # Feed the file on stdin; the validated pipeline runs as $2 via bash -c.
    script = f'exec < {f}; eval "$1"'
    # Re-cap on our side too, and hard-cap inside the shell as a safety net.
    out = _run_bash(script, cmd + f" | head -n {MAX_LINES}")
    return _cap(out)


@mcp.tool()
def remove_log(log_id: str) -> str:
    """Delete a deployed log (its copy) from the sandbox. The original is untouched."""
    name = _require(log_id)["name"]
    _run_bash(
        f'rm -f "{SANDBOX_DIR}/{name}" "{SANDBOX_DIR}/{log_id}.src"'
    )
    _REGISTRY.pop(log_id, None)
    return f"Removed {log_id} from the sandbox."


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
