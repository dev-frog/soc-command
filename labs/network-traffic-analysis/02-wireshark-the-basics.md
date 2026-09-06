# Room 2 — Wireshark: The Basics

> **Difficulty:** Easy · **Time:** ~30 min · **Prerequisites:** Room 1
> **Capture:** `pcaps/wireshark-basics.pcap` (39 packets)
> **Tool:** Wireshark

Room 1 taught you to read one packet. This room is about *driving the tool*: the
layout, capture vs display filters, the Statistics menu that summarises a whole
capture in seconds, following streams, and colouring rules.

The capture is a short browsing session from `10.14.0.50`: a gratuitous ARP, three
DNS lookups (one fails), two HTTP conversations, and some pings.

---

## Task 1 — The interface

| Pane / menu | What it's for |
|---|---|
| **Packet list** | one row per frame; click to select |
| **Packet details** | protocol layers of the selected frame; expand each |
| **Packet bytes** | raw hex + ASCII |
| **Display filter bar** (green = valid, red = invalid, yellow = valid but risky) | filter what's *shown* |
| **Statistics** menu | capture-wide summaries |
| **Analyze ▸ Follow** | reassemble a whole conversation |
| **View ▸ Coloring Rules** | colour rows by filter |
| Status bar (bottom) | packet counts, load time, current profile |

First moves on any new pcap:
1. **View ▸ Time Display Format ▸ UTC Date and Time**.
2. **Statistics ▸ Protocol Hierarchy** — what protocols are even in here?
3. **Statistics ▸ Conversations** — who talked to whom, how much?

### Questions

1. How many packets does the status bar report for this capture?
2. What colour is the display filter bar when you type an invalid filter?
3. Which menu contains "Protocol Hierarchy"?

---

## Task 2 — Capture filters vs display filters

They are **different syntaxes** and used at different times.

| | Capture filter | Display filter |
|---|---|---|
| When | *before/during* capture — decides what's written to disk | *after* — decides what's shown |
| Syntax | BPF (`tcpdump` style) | Wireshark's own |
| Example | `host 10.14.0.80` | `ip.addr == 10.14.0.80` |
| Example | `tcp port 80` | `tcp.port == 80` |
| Example | `udp port 53` | `dns` |
| Reversible? | no — filtered-out traffic is gone | yes — just clear the bar |

For this module you always work from a saved pcap, so it is **all display
filters**. Capture filters matter when *you* run the capture (see room notes).

### Questions

1. Write the **display** filter that shows only traffic to or from `10.14.0.80`.
2. Write the **capture** filter (BPF) that would only record UDP port 53 traffic.
3. True/False: a display filter permanently removes packets from the pcap.

---

## Task 3 — Display filter essentials

Type these into the filter bar (Enter to apply, clear to reset):

| Filter | Shows |
|---|---|
| `dns` | all DNS |
| `http` | HTTP request/response lines |
| `ip.addr == 151.101.1.229` | anything to/from that IP |
| `ip.src == 10.14.0.50` | packets **from** the workstation |
| `tcp.port == 80` | HTTP by port |
| `dns.flags.rcode == 3` | DNS responses with **NXDOMAIN** (name doesn't exist) |
| `http.request` | just the requests |
| `http.response.code == 200` | just `200 OK` responses |
| `frame.len > 200` | frames bigger than 200 bytes |
| `arp` | the gratuitous ARP |

Combine with `and` / `or` / `not` (or `&&` / `||` / `!`):

```
http.request and ip.src == 10.14.0.50
dns and not ip.addr == 10.14.0.2
```

**Right-click a field ▸ Apply as Filter ▸ Selected** builds the filter for you —
the fastest way to learn field names.

### Questions

1. Apply `dns`. How many DNS packets are shown?
2. Apply `dns.flags.rcode == 3`. Which hostname got an NXDOMAIN response?
3. Apply `http.request`. How many HTTP requests are in the capture?
4. What is the display-filter field name for the HTTP response status code?
5. Apply `http.response.code == 200`. How many responses match?

---

## Task 4 — Statistics menu

### Protocol Hierarchy (`Statistics ▸ Protocol Hierarchy`)
Tree of every protocol seen with packet + byte counts and % of capture. Tells you
at a glance: "this is 60% HTTP, 20% DNS, 10% ICMP, 10% ARP".

### Conversations (`Statistics ▸ Conversations`)
One row per pair of endpoints, per layer (Ethernet / IPv4 / TCP / UDP tabs).
Columns: packets, bytes, duration, bytes A→B and B→A. Sort by **Bytes** to find
the heaviest talker. Right-click a row ▸ **Apply as Filter** to pivot into it.

### Endpoints (`Statistics ▸ Endpoints`)
One row per single address. IPv4 tab = every IP and how much it sent/received.
Tick **Resolve address** or use the **Map** button for geo (needs GeoIP DB).

### Others worth knowing
- **Statistics ▸ DNS** — every query name, response code counts.
- **Statistics ▸ HTTP ▸ Requests** — every URL requested, grouped by host.
- **Statistics ▸ Capture File Properties** — first/last packet time, duration, avg pps/bps.
- **Statistics ▸ I/O Graph** — packets/bytes over time (spot bursts, beacons).

### Questions

1. From **Protocol Hierarchy**: how many DNS packets and how many HTTP packets?
2. From **Conversations ▸ IPv4**: which remote IP exchanged the most **bytes** with `10.14.0.50`?
3. From **Statistics ▸ HTTP ▸ Requests**: how many distinct host names were requested?
4. From **Capture File Properties**: what is the capture duration (seconds, ~)?
5. From **Statistics ▸ DNS**: how many queries of type `A` were made?

---

## Task 5 — Following streams

Right-click any packet in a conversation ▸ **Follow ▸ …**

| Follow type | Use it for |
|---|---|
| **TCP Stream** | the raw bytes of a whole TCP connection, both directions |
| **HTTP Stream** | same but HTTP-aware (shows headers + body cleanly) |
| **UDP Stream** | a UDP "conversation" (e.g. one DNS Q/A) |

In the Follow window: red = client→server, blue = server→client. The dropdown
bottom-left switches direction or "Entire conversation". "Show data as" can be
ASCII / Hex Dump / Raw / etc.

Following a stream **auto-applies** `tcp.stream == N` as your display filter. Note
that number — it's how you jump straight back to that conversation later.

### Steps

1. Filter `http.request`. Click the `GET /index.html` request.
2. **Follow ▸ HTTP Stream.** Read the request headers and the HTML response.
3. Note the `tcp.stream` number now in the filter bar.
4. Clear, then filter `http` and find the `GET /logo.png` request — what content
   type comes back?

### Questions

1. What `tcp.stream` number is the `www.company-intranet.lan` conversation?
2. In that stream, what `<title>` does the returned HTML page have?
3. What `User-Agent` does the client send to `www.company-intranet.lan`?
4. What `Content-Type` does the server return for `/logo.png`?
5. Which host serves the file `/npm/jquery@3.7.1/dist/jquery.min.js`?

---

## Task 6 — Coloring rules & the Info column

**View ▸ Coloring Rules** — Wireshark ships with ~20 default rules (bad TCP = black
on red, HTTP = green, DNS = light blue, etc.). Each rule is just a display filter
plus a colour, evaluated top-down.

Add your own: **+**, name it "beacon-candidate", filter
`tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==443`, pick a colour. Now any
outbound HTTPS SYN is highlighted. This is how analysts pre-stain a capture before
they even scroll it.

Temporary version: right-click a packet ▸ **Colorize Conversation ▸ …** (no rule
saved, cleared on close).

The **Info** column is protocol-generated free text — for HTTP it's the request
line or status line, for DNS the query, for TCP the flags + seq/ack. Skim-reading
the Info column top to bottom *is* first-pass triage.

### Questions

1. What is the default coloring-rule name for checksum/retransmission problems ("Bad TCP")?
2. Coloring rules are evaluated in what order (top-to-bottom or bottom-to-top)?
3. Right-click ▸ Colorize Conversation creates a saved rule — true or false?
