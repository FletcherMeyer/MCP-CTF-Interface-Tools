# pcapscope — interpret packet captures (.pcap / .pcapng)

A companion MCP server to `logsandbox` and `harscope`, for **packet captures**. It
makes **zero network requests** and needs **no Wireshark/tshark** — it parses the
capture itself in pure Python. Built so an AI can *interpret and search* a capture
through tooling instead of reading the binary raw.

## Why not read the .pcap raw?

A pcap is binary and often huge; dumping it wastes context and tells you nothing.
`pcapscope` parses it once and answers structured, bounded, **AI-driven** queries.
You look at the profile, form a hypothesis about *this* traffic, then drive the
tools with your own filters/regexes/ids — nothing assumes a CTF or a fixed format.

## Tools

| Tool | Purpose |
|------|---------|
| `load_pcap(path)` | Parse + index. Neutral profile: packets, time span, protocol mix, top talkers, busiest ports, conversation count. **Do this first.** |
| `list_pcaps()` | Show loaded captures. |
| `conversations(pcap_id, …)` | List TCP/UDP flows, each with a `conv_id`. |
| `follow(pcap_id, conv_id, …)` | **Reassemble a stream** (TCP by seq, UDP by order), both directions — read what was actually exchanged. |
| `list_packets(pcap_id, …)` | Table of packets; filter by proto/ip/port/payload-contains. |
| `packet(pcap_id, index)` | One packet's dissection + payload (binary summarized, not dumped). |
| `search(pcap_id, pattern, …)` | Regex across packet payloads — **your** pattern. |
| `strings(pcap_id, min_len, …)` | Printable strings; **you** choose the min length and filters. |
| `extract(pcap_id, kind)` | `http`, `dns`, `hosts`, `creds` (Basic/FTP/form), `ports`, `talkers`. |
| `decode(value, scheme)` | Local base64/base64url/hex/url decode of a value you found. |
| `unload_pcap(pcap_id)` | Free memory (file untouched). |

## Typical flow

```
load_pcap("C:\\ctf\\capture.pcapng")   -> pcap_id ab12cd; 4.2k packets, 310 conversations
conversations("ab12cd")                 -> c7 TCP 10.0.0.5:4444 <-> 10.0.0.9:51000, 180 KB
follow("ab12cd", "c7")                  -> reassembled stream: a shell session / file transfer
extract("ab12cd", "creds")              -> HTTP Basic / FTP USER+PASS / form user=…&pass=…
extract("ab12cd", "dns")                -> queried hostnames (exfil over DNS?)
search("ab12cd", "flag\\{|password|BEGIN .*PRIVATE KEY")
strings("ab12cd", min_len=8, port="4444")
```

## Format support

- **Classic pcap** (`.pcap`, microsecond and nanosecond) and **pcapng** (`.pcapng`,
  Enhanced/Simple/legacy Packet Blocks, multiple interfaces).
- Link types: Ethernet (incl. VLAN tags), Linux SLL, raw IP, BSD loopback.
- L3/L4: IPv4, IPv6, TCP, UDP, ICMP/ICMPv6, ARP. App-layer helpers for HTTP & DNS.

## Register with Claude Code

```bash
claude mcp add pcapscope -- python "C:\path\to\pcap_server.py"
```

Env (optional): `PCAPSCOPE_MAX_CHARS` (12000), `PCAPSCOPE_MAX_ITEMS` (200),
`PCAPSCOPE_MAX_PACKETS` (300000).

## Safety

- **No network, no external tools.** It only reads and parses the local file.
- **Untrusted input.** Captures are adversarial data; payloads are treated as data,
  never executed. Binary payloads are summarized, not dumped as gibberish.
- **Bounded output.** Every tool caps characters/rows. Only analyze captures you're
  authorized to.
