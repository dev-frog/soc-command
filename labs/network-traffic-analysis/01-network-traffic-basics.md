# Room 1 — Network Traffic Basics

> **Difficulty:** Info / Easy · **Time:** ~25 min · **Prerequisites:** none
> **Capture:** `pcaps/net-basics.pcap` (20 packets)
> **Tool:** Wireshark

You cannot analyse traffic you cannot read. This room is the alphabet: what a
packet *is*, the layers it is wrapped in, and the four protocols you will see in
almost every capture — **ARP, ICMP, DNS, HTTP** — shown as one short story of a
workstation getting online and fetching a web page.

Open `pcaps/net-basics.pcap` in Wireshark now and keep it open for the whole room.

---

## Task 1 — What is a packet?

A **packet** is one unit of data moving across a network. It is built in layers,
each layer added by one part of the networking stack and stripped by its peer on
the other end. Two models describe those layers:

| OSI (7 layers) | TCP/IP (4 layers) | Example in this pcap |
|---|---|---|
| 7 Application | Application | HTTP `GET /` |
| 6 Presentation | " | (TLS would live here) |
| 5 Session | " | — |
| 4 Transport | Transport | TCP port 80, or UDP port 53 |
| 3 Network | Internet | IP `10.14.0.50 → 93.184.216.34` |
| 2 Data Link | Link | Ethernet `08:00:27:aa:bb:01` |
| 1 Physical | " | the cable / Wi-Fi |

Each layer's chunk of data has a name — collectively **PDUs** (Protocol Data Units):

| Layer | PDU name |
|---|---|
| Application | **data** / message |
| Transport (TCP) | **segment** |
| Transport (UDP) | **datagram** |
| Network | **packet** |
| Data Link | **frame** |

**Encapsulation** = wrapping: HTTP data → TCP segment → IP packet → Ethernet frame.
**De-encapsulation** = the reverse on receipt. Wireshark shows you every layer at
once in the middle "packet details" pane — expand each line.

### Questions

1. In the TCP/IP model, how many layers are there?
2. What is the PDU at the Data Link layer called?
3. What is the PDU at the Transport layer called when the protocol is TCP?
4. The process of adding headers as data moves *down* the stack is called what?

---

## Task 2 — Reading one packet in Wireshark

Click **packet 3** (the first ICMP echo request). The three panes:

- **Packet list** (top) — one row per frame: `No. | Time | Source | Destination | Protocol | Length | Info`
- **Packet details** (middle) — the layer stack for the selected frame
- **Packet bytes** (bottom) — the raw hex/ASCII

Expand the details pane for packet 3. You will see, top to bottom:

```
Frame 3: 66 bytes on wire ...
Ethernet II, Src: 08:00:27:aa:bb:01, Dst: 08:00:27:00:00:fe
Internet Protocol Version 4, Src: 10.14.0.50, Dst: 10.14.0.1
Internet Control Message Protocol
```

- The **Time** column is seconds since the first packet by default. Change it with
  **View ▸ Time Display Format ▸ UTC Date and Time** to get wall-clock time
  (`2024-09-06 12:00:00`).
- **Length** is the whole frame size on the wire, in bytes.
- Right-click any field ▸ **Apply as Column** to pin it in the packet list.

### Questions

1. What is the source MAC address of packet 3?
2. What is the destination IP address of packet 3?
3. Set the time format to UTC. What is the exact date and time of packet 1? (`YYYY-MM-DD HH:MM:SS` UTC)
4. What is the frame length, in bytes, of packet 1 (the ARP request)?

---

## Task 3 — ARP: finding the MAC behind an IP

Before `10.14.0.50` can send an IP packet to the gateway, it needs the gateway's
**MAC address**. **ARP** (Address Resolution Protocol) does that lookup, and it is
the very first thing in this capture.

Filter: `arp`

- **Packet 1** — broadcast (`Dst: ff:ff:ff:ff:ff:ff`), *"Who has 10.14.0.1? Tell 10.14.0.50"* — ARP **opcode 1** (request).
- **Packet 2** — unicast reply, *"10.14.0.1 is at 08:00:27:00:00:fe"* — ARP **opcode 2** (reply).

ARP has no IP header and no ports — it lives at layer 2 only, so it never leaves
the local segment.

### Questions

1. What is the opcode value of an ARP request?
2. What MAC address is given as the answer for `10.14.0.1`?
3. ARP operates at which OSI layer (number)?

---

## Task 4 — ICMP: is that host alive?

**ICMP** (Internet Control Message Protocol) carries diagnostics — `ping` uses it.
Packets 3–8 are a `ping` to the gateway: three **echo request** (type 8) / **echo
reply** (type 0) pairs.

Filter: `icmp`

Expand the ICMP layer on packet 3:

```
Type: 8 (Echo (ping) request)
Identifier: 0x1337
Sequence Number: 1
Data (16 bytes): abcdefghijklmnop
```

The **identifier** stays constant for one `ping` run; the **sequence number**
increments per packet. Reply matches request by identifier + sequence.

Useful filters:
- `icmp.type == 8` — requests only
- `icmp.type == 0` — replies only

### Questions

1. How many ICMP echo *requests* are in the capture?
2. What ICMP type number is an echo reply?
3. What is the ICMP identifier value (in hex) used in this ping run?
4. How many bytes of data does each echo request carry?

---

## Task 5 — DNS: name to address

Before fetching the web page, `10.14.0.50` asks the DNS resolver `10.14.0.2` for
the address of `example.com`.

Filter: `dns`

- **Packet 9** — Standard query, type **A**, `example.com`
- **Packet 10** — Standard query **response**, `example.com A 93.184.216.34`

Expand packet 10 ▸ **Answers** — the `A` record `rdata` is the IP the client will
now connect to. Both packets share the same **Transaction ID** (`0x2a2a`).

DNS here rides **UDP port 53**. Query and response are one datagram each.

### Questions

1. What record **type** does the client request for `example.com`?
2. What IP address is returned in the answer?
3. What transport protocol and port number does this DNS exchange use?
4. What is the DNS transaction ID (hex)?

---

## Task 6 — TCP handshake + HTTP: fetching the page

Now the client opens a TCP connection to `93.184.216.34:80` and makes an HTTP
request. Filter: `tcp.stream == 0` (or right-click a packet ▸ **Follow ▸ TCP Stream**).

**The 3-way handshake** (packets 11–13):

| # | Direction | Flags | Meaning |
|---|-----------|-------|---------|
| 11 | client → server | `SYN` | "I want to talk, my seq = x" |
| 12 | server → client | `SYN, ACK` | "OK, my seq = y, ack = x+1" |
| 13 | client → server | `ACK` | "Got it, ack = y+1" — connection **ESTABLISHED** |

Filter for just handshakes anywhere: `tcp.flags.syn == 1`

**The HTTP exchange:**
- **Packet 14** — `GET / HTTP/1.1`, `Host: example.com`, `User-Agent: curl/8.4.0`
- **Packet 16** — `HTTP/1.1 200 OK`, `Content-Type: text/html`, then the HTML body

Right-click packet 14 ▸ **Follow ▸ HTTP Stream** to see the full request and
response as text. Then the connection is torn down with `FIN` / `ACK`.

Filters worth knowing:
- `http` — only HTTP request/response lines
- `http.request.method == "GET"`
- `tcp.port == 80`
- `tcp.flags.fin == 1` — connection teardown

### Questions

1. In the handshake, which TCP flags are set on the second packet (packet 12)?
2. What HTTP method does the client use in packet 14?
3. What `User-Agent` string does the client send?
4. What HTTP status code and reason phrase does the server return?
5. What is the destination port of the HTTP request?
6. Which TCP flag marks the start of the connection teardown?

---

## Task 7 — Put the story together

Using only this 20-packet capture, you can narrate exactly what the workstation
did:

```
1–2    ARP     "where is the gateway?"            → 08:00:27:00:00:fe
3–8    ICMP    ping the gateway, 3x               → alive, ~30 ms
9–10   DNS     resolve example.com               → 93.184.216.34
11–13  TCP     handshake to 93.184.216.34:80     → ESTABLISHED
14–16  HTTP    GET /  →  200 OK (text/html)
17–20  TCP     FIN/ACK teardown
```

That "translate the packets back into a sentence" skill is the whole job. Every
later room is the same move on messier data.

### Questions

1. What is the first protocol (by packet) seen in the capture?
2. How many distinct IPv4 addresses appear in the capture? (Statistics ▸ Endpoints ▸ IPv4)
3. Which single packet number proves the TCP connection reached the ESTABLISHED state?
