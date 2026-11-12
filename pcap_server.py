#!/usr/bin/env python3
"""
pcapscope — an MCP server for interpreting packet captures (.pcap / .pcapng).

Same philosophy as logsandbox and harscope: do NOT read the capture raw — a pcap
is binary and huge, and dumping it wastes context. pcapscope parses it once (pure
Python, no network, no external tools) and answers STRUCTURED, BOUNDED, AI-DRIVEN
queries: profile, packet lists, conversations, follow-a-stream, regex search over
payloads, printable strings, and protocol extraction (HTTP/DNS/creds/hosts).

You drive it. The tools take the filters, ports, regexes and stream ids YOU choose
after looking at the profile — they don't run canned checks or assume a challenge
format. Add your own commentary on what the traffic means.

Environment variables:
    PCAPSCOPE_MAX_CHARS    Max characters any tool returns (default 12000)
    PCAPSCOPE_MAX_ITEMS    Max rows/matches a listing returns (default 200)
    PCAPSCOPE_MAX_PACKETS  Max packets parsed from a file (default 300000)
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

MAX_CHARS = int(os.environ.get("PCAPSCOPE_MAX_CHARS", "12000"))
MAX_ITEMS = int(os.environ.get("PCAPSCOPE_MAX_ITEMS", "200"))
MAX_PACKETS = int(os.environ.get("PCAPSCOPE_MAX_PACKETS", "300000"))

INSTRUCTIONS = """\
pcapscope interprets packet captures (.pcap/.pcapng). It makes NO network requests
and needs no Wireshark/tshark — it parses the file itself. DO NOT open a capture
with generic file tools: it's binary and large.

YOU drive it. Look at the profile, form a hypothesis about THIS traffic, then query
with your own filters/regexes/ids. Nothing assumes a CTF or a fixed format.

Workflow:
  1. load_pcap(path) -> parses the capture, returns a neutral profile: packet count,
                        time span, link/L3/L4 protocol mix, top talkers, top ports,
                        and conversation count.
  2. Investigate by the returned pcap_id:
       conversations(pcap_id)              -> the TCP/UDP flows, each with a conv id
       follow(pcap_id, conv_id)            -> reassembled stream payload (both dirs)
       list_packets / packet               -> drill into specific packets
       search(pcap_id, pattern, ...)       -> regex across packet payloads
       strings(pcap_id, min_len, ...)      -> printable strings you choose the length of
       extract(pcap_id, kind)              -> http | dns | hosts | creds | ports | talkers
       decode(value, scheme)               -> locally decode a token you found

For many captures the fastest path is conversations() then follow() on the flow
that looks interesting, or extract('http')/extract('creds')/extract('dns').
"""

mcp = FastMCP("pcapscope", instructions=INSTRUCTIONS)

# pcap_id -> {"path", "packets": [...], "convs": {cid: {...}}, "truncated": bool}
_CAPS: dict[str, dict] = {}


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #

def _cap(text: str, limit: int = MAX_CHARS) -> str:
    if not text:
        return "(none)"
    if len(text) > limit:
        return text[:limit] + f"\n\n[... truncated to {limit} chars — narrow your query ...]"
    return text


def _require(pcap_id: str) -> dict:
    c = _CAPS.get(pcap_id)
    if not c:
        raise ValueError(f"Unknown pcap_id '{pcap_id}'. Call load_pcap(path) first.")
    return c


def _printable(data: bytes) -> str:
    """Decode bytes to text, keeping printable chars and common whitespace."""
    return data.decode("latin-1", "replace")


def _looks_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:2048]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return (printable / len(sample)) >= 0.75


# --------------------------------------------------------------------------- #
# File parsing: classic pcap + pcapng -> list of (ts, linktype, raw_bytes)
# --------------------------------------------------------------------------- #

def _parse_capture(data: bytes) -> tuple[list, bool]:
    if len(data) < 4:
        return [], False
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                 b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return _parse_classic(data)
    if magic == b"\x0a\x0d\x0d\x0a":
        return _parse_pcapng(data)
    raise ValueError("Not a pcap or pcapng file (bad magic).")


def _parse_classic(data: bytes) -> tuple[list, bool]:
    le = data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    nano = data[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    end = "<" if le else ">"
    linktype = struct.unpack(end + "I", data[20:24])[0]
    pkts, off, n = [], 24, 0
    while off + 16 <= len(data) and n < MAX_PACKETS:
        ts_sec, ts_frac, caplen, _orig = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        if off + caplen > len(data):
            break
        raw = data[off:off + caplen]
        off += caplen
        ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
        pkts.append((ts, linktype, raw))
        n += 1
    return pkts, (off + 16 <= len(data))


def _parse_pcapng(data: bytes) -> tuple[list, bool]:
    pkts, off, n = [], 0, 0
    end = "<"  # refined per section header
    if_linktypes: list[int] = []
    tsresol = 1e6
    while off + 12 <= len(data) and n < MAX_PACKETS:
        btype = struct.unpack("<I", data[off:off + 4])[0]
        # Section Header Block sets byte order.
        if btype == 0x0A0D0D0A:
            bom = data[off + 8:off + 12]
            end = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        blen = struct.unpack(end + "I", data[off + 4:off + 8])[0]
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001:  # Interface Description Block
            lt = struct.unpack(end + "H", body[0:2])[0]
            if_linktypes.append(lt)
        elif btype == 0x00000006:  # Enhanced Packet Block
            iface, th, tl, caplen, _orig = struct.unpack(end + "IIIII", body[0:20])
            ts = ((th << 32) | tl) / tsresol
            raw = body[20:20 + caplen]
            lt = if_linktypes[iface] if iface < len(if_linktypes) else 1
            pkts.append((ts, lt, raw))
            n += 1
        elif btype == 0x00000003:  # Simple Packet Block
            caplen = len(body) - 4
            raw = body[4:4 + caplen]
            lt = if_linktypes[0] if if_linktypes else 1
            pkts.append((0.0, lt, raw))
            n += 1
        elif btype == 0x00000002:  # (obsolete) Packet Block
            iface, _drops, th, tl, caplen, _orig = struct.unpack(end + "HHIIII", body[0:20])
            ts = ((th << 32) | tl) / tsresol
            raw = body[20:20 + caplen]
            lt = if_linktypes[iface] if iface < len(if_linktypes) else 1
            pkts.append((ts, lt, raw))
            n += 1
        off += blen
    return pkts, (off + 12 <= len(data))


# --------------------------------------------------------------------------- #
# Dissection: raw frame -> structured packet
# --------------------------------------------------------------------------- #

_TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
              (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]


def _flag_str(flags: int) -> str:
    return "/".join(name for bit, name in _TCP_FLAGS if flags & bit) or "-"


def _l3_from_linktype(raw: bytes, linktype: int):
    """Return (ethertype, l3_bytes) or (None, None)."""
    if linktype == 1:  # Ethernet
        if len(raw) < 14:
            return None, None
        etype = struct.unpack(">H", raw[12:14])[0]
        off = 14
        while etype in (0x8100, 0x88A8) and len(raw) >= off + 4:
            etype = struct.unpack(">H", raw[off + 2:off + 4])[0]
            off += 4
        return etype, raw[off:]
    if linktype == 113:  # Linux SLL
        if len(raw) < 16:
            return None, None
        return struct.unpack(">H", raw[14:16])[0], raw[16:]
    if linktype in (101,):  # raw IP
        if raw:
            v = raw[0] >> 4
            return (0x0800 if v == 4 else 0x86DD if v == 6 else None), raw
        return None, None
    if linktype == 0:  # BSD loopback / null
        if len(raw) < 4:
            return None, None
        fam = struct.unpack("<I", raw[:4])[0]
        return (0x0800 if fam == 2 else 0x86DD if fam in (24, 28, 30) else None), raw[4:]
    # unknown link type: best-effort treat as IP if it looks like one
    if raw and (raw[0] >> 4) in (4, 6):
        return (0x0800 if raw[0] >> 4 == 4 else 0x86DD), raw
    return None, None


def _dissect(raw: bytes, linktype: int) -> dict:
    out = {"proto": "?", "src": "", "dst": "", "sport": 0, "dport": 0,
           "flags": "", "seq": 0, "payload": b"", "info": ""}
    etype, l3 = _l3_from_linktype(raw, linktype)
    if l3 is None:
        out["proto"] = "L2"
        out["info"] = f"link-type {linktype} frame"
        return out

    if etype == 0x0806:  # ARP
        out["proto"] = "ARP"
        if len(l3) >= 28:
            op = struct.unpack(">H", l3[6:8])[0]
            sip = ".".join(str(b) for b in l3[14:18])
            tip = ".".join(str(b) for b in l3[24:28])
            out["src"], out["dst"] = sip, tip
            out["info"] = ("who-has " + tip + " tell " + sip) if op == 1 else (sip + " is-at")
        return out

    if etype == 0x0800:  # IPv4
        if len(l3) < 20:
            return out
        ihl = (l3[0] & 0x0F) * 4
        proto = l3[9]
        out["src"] = ".".join(str(b) for b in l3[12:16])
        out["dst"] = ".".join(str(b) for b in l3[16:20])
        total = struct.unpack(">H", l3[2:4])[0]
        l4 = l3[ihl: total if total else len(l3)]
    elif etype == 0x86DD:  # IPv6
        if len(l3) < 40:
            return out
        proto = l3[6]
        plen = struct.unpack(">H", l3[4:6])[0]
        try:
            out["src"] = str(ipaddress.IPv6Address(l3[8:24]))
            out["dst"] = str(ipaddress.IPv6Address(l3[24:40]))
        except ValueError:
            pass
        l4 = l3[40:40 + plen] if plen else l3[40:]
    else:
        out["proto"] = f"0x{etype:04x}" if etype else "L2"
        return out

    if proto == 6:  # TCP
        out["proto"] = "TCP"
        if len(l4) >= 20:
            sport, dport, seq = struct.unpack(">HHI", l4[:8])
            doff = (l4[12] >> 4) * 4
            out["sport"], out["dport"], out["seq"] = sport, dport, seq
            out["flags"] = _flag_str(l4[13])
            out["payload"] = l4[doff:]
            out["info"] = f"{sport}->{dport} [{out['flags']}] len={len(out['payload'])}"
    elif proto == 17:  # UDP
        out["proto"] = "UDP"
        if len(l4) >= 8:
            sport, dport, ln = struct.unpack(">HHH", l4[:6])
            out["sport"], out["dport"] = sport, dport
            out["payload"] = l4[8: ln if ln >= 8 else len(l4)]
            out["info"] = f"{sport}->{dport} len={len(out['payload'])}"
    elif proto in (1, 58):  # ICMP / ICMPv6
        out["proto"] = "ICMP" if proto == 1 else "ICMPv6"
        if len(l4) >= 2:
            out["info"] = f"type={l4[0]} code={l4[1]}"
    else:
        out["proto"] = f"ip-proto-{proto}"
    return out


# --------------------------------------------------------------------------- #
# Indexing
# --------------------------------------------------------------------------- #

def _conv_key(p: dict):
    a = (p["src"], p["sport"])
    b = (p["dst"], p["dport"])
    lo, hi = sorted([a, b])
    return (p["proto"], lo, hi)


def _index(packets_raw: list) -> tuple[list, dict]:
    packets, convs = [], {}
    conv_ids: dict = {}
    for i, (ts, lt, raw) in enumerate(packets_raw):
        d = _dissect(raw, lt)
        d["i"] = i
        d["ts"] = ts
        d["length"] = len(raw)
        packets.append(d)
        if d["proto"] in ("TCP", "UDP") and d["src"] and d["dst"]:
            key = _conv_key(d)
            if key not in conv_ids:
                cid = f"c{len(conv_ids)}"
                conv_ids[key] = cid
                convs[cid] = {"proto": key[0], "a": key[1], "b": key[2],
                              "packets": [], "bytes": 0}
            cid = conv_ids[key]
            convs[cid]["packets"].append(i)
            convs[cid]["bytes"] += len(d["payload"])
    return packets, convs


def _fmt_ts(ts: float) -> str:
    if not ts:
        return "?"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    except (OSError, ValueError, OverflowError):
        return f"{ts:.3f}"


def _ep(e) -> str:
    ip, port = e
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #

@mcp.tool()
def load_pcap(path: str) -> str:
    """
    Load and parse a .pcap/.pcapng capture. Do this FIRST — never read it raw.

    Returns a neutral profile: packet count, time span, protocol mix (L4), the top
    source/destination IPs ("talkers"), the busiest ports, and how many TCP/UDP
    conversations there are. Makes no network request and assumes no challenge format.

    Args:
        path: path to the .pcap or .pcapng file (Windows or POSIX).
    """
    try:
        with open(os.path.expanduser(path), "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return f"File not found: {path}"
    except OSError as ex:
        return f"Could not read file: {ex}"

    try:
        packets_raw, truncated = _parse_capture(data)
    except (ValueError, struct.error) as ex:
        return f"Could not parse as pcap/pcapng: {ex}"
    if not packets_raw:
        return "Parsed no packets — the file may be empty or an unsupported format."

    packets, convs = _index(packets_raw)
    pcap_id = hashlib.sha1(os.path.abspath(os.path.expanduser(path)).encode()).hexdigest()[:10]
    _CAPS[pcap_id] = {"path": path, "packets": packets, "convs": convs, "truncated": truncated}

    protos = Counter(p["proto"] for p in packets)
    talkers = Counter()
    ports = Counter()
    for p in packets:
        if p["src"]:
            talkers[p["src"]] += 1
        if p["proto"] in ("TCP", "UDP"):
            if p["dport"]:
                ports[p["dport"]] += 1
    ts_vals = [p["ts"] for p in packets if p["ts"]]
    span = f"{_fmt_ts(min(ts_vals))} → {_fmt_ts(max(ts_vals))}" if ts_vals else "(no timestamps)"

    def _top(c: Counter, n=10):
        return ", ".join(f"{k} ({v})" for k, v in c.most_common(n)) or "(none)"

    note = "\n(NOTE: packet cap reached; file truncated at parse limit)" if truncated else ""
    return (
        f"Loaded {path}\n"
        f"pcap_id: {pcap_id}   packets: {len(packets)}   conversations: {len(convs)}\n"
        f"time span: {span}{note}\n\n"
        f"protocols: {_top(protos)}\n"
        f"top talkers (src ip): {_top(talkers)}\n"
        f"busiest dst ports: {_top(ports)}\n\n"
        "Next: conversations(pcap_id) then follow() the interesting flow, or "
        "extract('http'/'dns'/'creds'), or search() with your own regex."
    )


@mcp.tool()
def list_pcaps() -> str:
    """List loaded captures with their pcap_id and path."""
    if not _CAPS:
        return "No capture loaded. Call load_pcap(path) first."
    return "pcap_id   \tpackets\tpath\n" + "\n".join(
        f"{k}\t{len(v['packets'])}\t{v['path']}" for k, v in _CAPS.items())


@mcp.tool()
def list_packets(pcap_id: str, proto: str = "", ip: str = "", port: str = "",
                 contains: str = "", max_rows: int = 100) -> str:
    """
    List packets as a compact table (idx, time, src -> dst, proto, length, info).
    Filters are yours to choose; all are optional.

    Args:
        proto:    protocol substring (TCP, UDP, ICMP, ARP, ...).
        ip:       match either endpoint IP (substring).
        port:     match either src or dst port (exact).
        contains: keep only packets whose payload contains this text (case-insensitive).
        max_rows: cap on rows.
    """
    c = _require(pcap_id)
    rows = []
    for p in c["packets"]:
        if proto and proto.lower() not in p["proto"].lower():
            continue
        if ip and ip not in p["src"] and ip not in p["dst"]:
            continue
        if port and port not in (str(p["sport"]), str(p["dport"])):
            continue
        if contains and contains.lower() not in _printable(p["payload"]).lower():
            continue
        rows.append(f'{p["i"]:>6}  {_fmt_ts(p["ts"]):<12} '
                    f'{(p["src"] or "-"):>21} -> {(p["dst"] or "-"):<21} '
                    f'{p["proto"]:<7} {p["length"]:>6}  {p["info"]}')
        if len(rows) >= min(max_rows, MAX_ITEMS):
            break
    if not rows:
        return "No packets match."
    header = f'{"idx":>6}  {"time":<12} {"src":>21}    {"dst":<21} {"proto":<7} {"len":>6}  info'
    return _cap(header + "\n" + "\n".join(rows))


@mcp.tool()
def packet(pcap_id: str, index: int, show_payload: bool = True) -> str:
    """
    Show one packet's dissection and (optionally) a payload preview. Binary payloads
    are summarized, not dumped as gibberish.
    """
    c = _require(pcap_id)
    pk = c["packets"]
    if index < 0 or index >= len(pk):
        return f"index out of range (0..{len(pk)-1})."
    p = pk[index]
    out = [f"#{p['i']}  t={_fmt_ts(p['ts'])}  {p['proto']}  len={p['length']}",
           f"  {p['src']}:{p['sport']} -> {p['dst']}:{p['dport']}  {p['info']}"]
    if show_payload and p["payload"]:
        body = p["payload"]
        if _looks_text(body):
            txt = _printable(body)
            out.append(f"  payload ({len(body)} bytes):\n" +
                       "\n".join("    " + ln for ln in txt[:1500].splitlines()))
        else:
            hexd = body[:64].hex(" ")
            out.append(f"  payload ({len(body)} bytes, binary): {hexd}"
                       + (" …" if len(body) > 64 else ""))
    return _cap("\n".join(out))


@mcp.tool()
def conversations(pcap_id: str, proto: str = "", sort: str = "bytes",
                  max_rows: int = 80) -> str:
    """
    List TCP/UDP conversations (flows), each with a conv id you pass to follow().

    Args:
        proto:    filter by TCP or UDP (optional).
        sort:     "bytes" (default), "packets", or "first" (capture order).
        max_rows: cap on rows.
    """
    c = _require(pcap_id)
    rows = list(c["convs"].items())
    if proto:
        rows = [r for r in rows if r[1]["proto"].lower() == proto.lower()]
    if sort == "packets":
        rows.sort(key=lambda r: -len(r[1]["packets"]))
    elif sort == "first":
        rows.sort(key=lambda r: r[1]["packets"][0] if r[1]["packets"] else 0)
    else:
        rows.sort(key=lambda r: -r[1]["bytes"])
    out = []
    for cid, v in rows[:min(max_rows, MAX_ITEMS)]:
        out.append(f'{cid:<5} {v["proto"]:<4} {_ep(v["a"]):>24} <-> {_ep(v["b"]):<24} '
                   f'{len(v["packets"]):>6} pkts  {v["bytes"]:>9} B')
    if not out:
        return "No conversations."
    return _cap("conv  proto  endpoint A                 endpoint B                 packets    bytes\n"
                + "\n".join(out))


@mcp.tool()
def follow(pcap_id: str, conv_id: str, direction: str = "both",
           max_chars: int = 8000) -> str:
    """
    Reassemble a conversation's payload (a "follow TCP/UDP stream"). TCP segments are
    ordered by sequence number; UDP by capture order. The single most useful tool for
    reading what was actually exchanged — credentials, commands, transferred files.

    Args:
        conv_id:   from conversations().
        direction: "both" (default), "a2b", or "b2a".
        max_chars: cap per direction.
    """
    c = _require(pcap_id)
    v = c["convs"].get(conv_id)
    if not v:
        return f"Unknown conv_id '{conv_id}'. Call conversations() first."
    a, b = v["a"], v["b"]
    dir_a, dir_b = [], []  # (seq, order, payload)
    for order, i in enumerate(v["packets"]):
        p = c["packets"][i]
        if not p["payload"]:
            continue
        key = (p["seq"], order, p["payload"])
        if (p["src"], p["sport"]) == a:
            dir_a.append(key)
        else:
            dir_b.append(key)

    def reasm(segs):
        if v["proto"] == "TCP":
            segs = sorted(segs, key=lambda s: (s[0], s[1]))
        else:
            segs = sorted(segs, key=lambda s: s[1])
        return b"".join(s[2] for s in segs)

    def render(label, data):
        if not data:
            return f"--- {label} (empty) ---"
        if _looks_text(data):
            return f"--- {label} ({len(data)} bytes) ---\n" + _printable(data)[:max_chars]
        return f"--- {label} ({len(data)} bytes, binary) ---\n" + data[:max_chars // 3].hex(" ")

    blocks = []
    if direction in ("both", "a2b"):
        blocks.append(render(f"{_ep(a)} -> {_ep(b)}", reasm(dir_a)))
    if direction in ("both", "b2a"):
        blocks.append(render(f"{_ep(b)} -> {_ep(a)}", reasm(dir_b)))
    return _cap("\n\n".join(blocks))


@mcp.tool()
def search(pcap_id: str, pattern: str, ignore_case: bool = True,
           max_results: int = 60) -> str:
    """
    Regex-search packet payloads (decoded as text) and report where it matched.
    You supply the pattern — nothing is preset.

    Args:
        pattern: Python regex, searched against each packet's payload text.
    """
    c = _require(pcap_id)
    try:
        rx = re.compile(pattern, re.I if ignore_case else 0)
    except re.error as ex:
        return f"Bad regex: {ex}"
    out, n = [], 0
    for p in c["packets"]:
        if not p["payload"]:
            continue
        txt = _printable(p["payload"])
        m = rx.search(txt)
        if m:
            s, e = m.start(), m.end()
            frag = txt[max(0, s - 60): e + 60].replace("\n", "\\n").replace("\r", "")
            out.append(f'#{p["i"]:>6} {p["proto"]} {p["src"]}:{p["sport"]}->{p["dst"]}:{p["dport"]}  …{frag}…')
            n += 1
            if n >= min(max_results, MAX_ITEMS):
                out.append("[... more; narrow the pattern ...]")
                break
    return _cap("\n".join(out)) if out else f"No payload matches for /{pattern}/."


@mcp.tool()
def strings(pcap_id: str, min_len: int = 6, proto: str = "", port: str = "",
            max_results: int = 150) -> str:
    """
    Extract printable strings from packet payloads — you choose the minimum length
    and (optionally) restrict by protocol/port. Good for spotting readable content
    inside otherwise-binary traffic without dumping it.

    Args:
        min_len:  minimum run length of printable chars (you set the threshold).
        proto/port: optional filters.
        max_results: cap on strings returned.
    """
    c = _require(pcap_id)
    rx = re.compile(rb"[ -~]{%d,}" % max(1, int(min_len)))
    out, seen = [], set()
    for p in c["packets"]:
        if proto and proto.lower() not in p["proto"].lower():
            continue
        if port and port not in (str(p["sport"]), str(p["dport"])):
            continue
        for m in rx.findall(p["payload"]):
            s = m.decode("latin-1", "replace")
            if s in seen:
                continue
            seen.add(s)
            out.append(f'#{p["i"]:>6} {s}')
            if len(out) >= min(max_results, MAX_ITEMS):
                return _cap("\n".join(out))
    return _cap("\n".join(out)) if out else "No printable strings at that length."


def _dns_name(d: bytes, off: int) -> tuple[str, int]:
    labels = []
    jumps = 0
    while off < len(d) and jumps < 20:
        ln = d[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:  # compression pointer — stop (don't chase)
            off += 2
            break
        labels.append(d[off + 1: off + 1 + ln].decode("latin-1", "replace"))
        off += 1 + ln
        jumps += 1
    return ".".join(labels), off


@mcp.tool()
def extract(pcap_id: str, kind: str, max_items: int = 150) -> str:
    """
    Pull a category of application-layer artifacts across the capture.

    kind:
        http    — HTTP request lines + Host, and response status lines
        dns     — DNS queries and their answers
        hosts   — IPs seen, with DNS name->IP mappings discovered in the capture
        creds   — HTTP Basic auth (decoded), FTP USER/PASS, and user/pass-looking
                  form fields in payloads
        ports   — busiest ports (with service guesses where obvious)
        talkers — source/destination IP pairs by volume
    """
    c = _require(pcap_id)
    kind = kind.lower().strip()
    cap = min(max_items, MAX_ITEMS)
    pk = c["packets"]
    lines: list[str] = []

    if kind == "http":
        req = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\S+) HTTP/1")
        host = re.compile(r"(?im)^Host:\s*(\S+)")
        status = re.compile(r"^HTTP/1\.[01] (\d{3})([^\r\n]*)")
        for p in pk:
            if not p["payload"]:
                continue
            t = _printable(p["payload"])
            m = req.match(t)
            if m:
                h = host.search(t)
                lines.append(f'#{p["i"]:>6} {m.group(1)} {(h.group(1)+" " if h else "")}{m.group(2)}')
                continue
            s = status.match(t)
            if s:
                lines.append(f'#{p["i"]:>6} <- HTTP {s.group(1)}{s.group(2).rstrip()}')
        return _cap("\n".join(lines[:cap])) if lines else "No HTTP request/response lines found."

    if kind == "dns":
        for p in pk:
            if not (p["proto"] == "UDP" and 53 in (p["sport"], p["dport"])):
                continue
            d = p["payload"]
            if len(d) < 12:
                continue
            try:
                qd, an = struct.unpack(">HH", d[4:8])
                off = 12
                qnames = []
                for _ in range(min(qd, 5)):
                    name, off = _dns_name(d, off)
                    off += 4  # qtype+qclass
                    qnames.append(name)
            except (struct.error, IndexError):
                continue
            tag = "query" if p["dport"] == 53 else "resp "
            if qnames:
                lines.append(f'#{p["i"]:>6} {tag} {", ".join(qnames)}'
                             + (f'  ({an} answers)' if an and tag == "resp " else ""))
        return _cap("\n".join(lines[:cap])) if lines else "No DNS traffic found."

    if kind == "hosts":
        ips = Counter()
        for p in pk:
            for x in (p["src"], p["dst"]):
                if x:
                    ips[x] += 1
        out = [f"{n:>6}  {ip}" for ip, n in ips.most_common(cap)]
        return _cap("packets  ip\n" + "\n".join(out)) if out else "No IPs found."

    if kind == "creds":
        basic = re.compile(r"(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)")
        ftp = re.compile(r"(?im)^(USER|PASS)\s+(.+)$")
        form = re.compile(r"(?i)(user(?:name)?|login|email|pass(?:word|wd)?|pwd)=([^&\s]+)")
        for p in pk:
            if not p["payload"]:
                continue
            t = _printable(p["payload"])
            for b in basic.findall(t):
                try:
                    dec = base64.b64decode(b).decode("latin-1", "replace")
                except Exception:
                    dec = "(undecodable)"
                lines.append(f'#{p["i"]:>6} HTTP Basic: {dec}')
            for verb, val in ftp.findall(t):
                lines.append(f'#{p["i"]:>6} FTP {verb} {val.strip()}')
            for field, val in form.findall(t):
                lines.append(f'#{p["i"]:>6} form {field}={val}')
        # de-dup preserving order
        seen = set()
        dedup = [l for l in lines if not (l in seen or seen.add(l))]
        return _cap("\n".join(dedup[:cap])) if dedup else "No credentials found in cleartext payloads."

    if kind == "ports":
        ports = Counter()
        for p in pk:
            if p["proto"] in ("TCP", "UDP") and p["dport"]:
                ports[(p["proto"], p["dport"])] += 1
        out = [f'{n:>6}  {proto}/{port}' for (proto, port), n in ports.most_common(cap)]
        return _cap("packets  port\n" + "\n".join(out)) if out else "No ports found."

    if kind == "talkers":
        pairs = Counter()
        for p in pk:
            if p["src"] and p["dst"]:
                pairs[(p["src"], p["dst"])] += 1
        out = [f'{n:>6}  {s} -> {d}' for (s, d), n in pairs.most_common(cap)]
        return _cap("packets  src -> dst\n" + "\n".join(out)) if out else "No talkers found."

    return ("Unknown kind. Use: http, dns, hosts, creds, ports, talkers.")


@mcp.tool()
def decode(value: str, scheme: str = "auto") -> str:
    """
    Locally decode a value you found in the capture (base64/base64url/hex/url).
    No network — pure transform.
    """
    value = value.strip()
    scheme = scheme.lower()

    def _b64(v):
        try:
            return base64.b64decode(v + "=" * (-len(v) % 4)).decode("latin-1", "replace")
        except Exception:
            return None

    def _b64u(v):
        try:
            return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)).decode("latin-1", "replace")
        except Exception:
            return None

    def _hex(v):
        t = re.sub(r"[^0-9a-fA-F]", "", v)
        if len(t) < 2 or len(t) % 2:
            return None
        try:
            return bytes.fromhex(t).decode("latin-1", "replace")
        except ValueError:
            return None

    import urllib.parse
    fns = {"base64": _b64, "base64url": _b64u, "hex": _hex,
           "url": lambda v: urllib.parse.unquote_plus(v)}
    if scheme in fns:
        r = fns[scheme](value)
        return _cap(r if r is not None else f"Could not decode as {scheme}.")
    outs = []
    for name, fn in fns.items():
        r = fn(value)
        if r and sum(c.isprintable() or c in "\r\n\t" for c in r) / max(1, len(r)) >= 0.8:
            outs.append(f"[{name}]\n{r}")
    return _cap("\n\n".join(outs)) if outs else "Nothing decoded to printable text; try an explicit scheme."


@mcp.tool()
def unload_pcap(pcap_id: str) -> str:
    """Forget a loaded capture (frees memory). The file on disk is untouched."""
    if _CAPS.pop(pcap_id, None):
        return f"Unloaded {pcap_id}."
    return f"No such pcap_id '{pcap_id}'."


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
