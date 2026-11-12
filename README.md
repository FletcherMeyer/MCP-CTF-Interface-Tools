<p align="center">
  <img src="icon.svg" width="140" alt="Log & Capture MCP Toolkit">
</p>

<h1 align="center">Log &amp; Capture MCP Toolkit</h1>

<p align="center">
Four MCP servers that let an AI <b>interpret big, binary, or on-screen content through tooling</b>
— never by reading it raw into context.
</p>

---

These are **four separate, independently-runnable MCP servers**, bundled in one
repo. They share one philosophy:

- **Don't read the artifact raw.** Load/index it once, then run **bounded** queries.
- **The AI drives.** Tools take the patterns, fields, filters and ids *you* supply
  after looking at a neutral profile — no canned checks, no assumed format, no
  guessing. When the answer isn't in the data, they say so instead of inventing it.
- **Local & safe.** No network calls; every result is capped; input is treated as
  untrusted data; binary/compressed noise is never surfaced as a false positive.

| Server | For | Reads via | Docs |
|--------|-----|-----------|------|
| **logsandbox** | Huge **log files** | a WSL sandbox (grep/awk/sed on a copy) | [LOG_README.md](LOG_README.md) |
| **harscope** | **HAR** (HTTP Archive) files, CTF-oriented | pure Python (decodes bodies, JWTs, base64) | [HAR_README.md](HAR_README.md) |
| **pcapscope** | **PCAP/PCAPNG** packet captures | pure Python (dissects + follows streams) | [PCAP_README.md](PCAP_README.md) |
| **screenscope** | a **screen region** (web VM console / terminal) | its browser extension streams cropped frames; the AI reads them | [SCREEN_README.md](SCREEN_README.md) |

Two Chrome/Edge extensions ship alongside, each streaming to a localhost bridge:
- **[harscope-extension/](harscope-extension)** — captures a tab's HTTP traffic as a HAR ([docs](harscope-extension/README.md)).
- **[screenscope-extension/](screenscope-extension)** — frames a region of a web VM console and streams the image ~1×/sec for the AI to read ([docs](screenscope-extension/README.md)).

## Requirements

- **Python 3.10+**, and `pip install -r requirements.txt` (just the `mcp` package;
  harscope and pcapscope use only the standard library beyond that).
- **logsandbox only:** Windows with **WSL** installed (`wsl.exe` on PATH).

## Install & register

```bash
pip install -r requirements.txt
```

Register whichever servers you want (each is independent):

```bash
claude mcp add logsandbox -- python C:\path\to\server.py
```

```bash
claude mcp add harscope -- python C:\path\to\har_server.py
```

```bash
claude mcp add pcapscope -- python C:\path\to\pcap_server.py
```

```bash
claude mcp add screenscope -- python C:\path\to\screen_server.py
```

(Or add equivalent entries to your MCP config — see `claude_config_snippet.json`.)

## At a glance

```
logsandbox:   deploy_log → search / top / timeline / pipeline   (your patterns)
harscope:     load_har   → scan / find_flags / extract / decode  (your patterns)
pcapscope:    load_pcap  → conversations / follow / extract / search / strings
screenscope:  bridge_status → read_screen (image) / say / ask    (live screen region)
```

## Security

- **No network.** Every server only reads the local artifact. logsandbox runs
  read-only commands in a WSL sandbox against a *copy*; harscope/pcapscope only
  parse and transform bytes.
- **Untrusted input.** Logs, HARs and captures are treated as data, never executed
  or obeyed. Only analyze artifacts you're authorized to.
- **Bounded & grounded.** Output is capped; scanners skip binary/compressed data so
  they don't emit false positives.
