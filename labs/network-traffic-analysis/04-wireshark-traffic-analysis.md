# Room 4 — Wireshark: Traffic Analysis

> **Difficulty:** Medium · **Time:** ~40 min · **Prerequisites:** Rooms 1–3
> **Capture:** `pcaps/traffic-analysis.pcap` (167 packets)
> **Tool:** Wireshark
> **This room is the module assessment.** Work it cold, fill in the timeline, then check the key.

You are the SOC analyst on shift. An EDR alert fired on workstation
**`10.14.0.10`** ("noisy outbound HTTPS"). You pull a 10-minute capture from the
span port. Work out **what happened, in order**, and whether this is an incident.

There are **five stages** hiding in this capture. Find them all.

---

## Task 1 — First-pass triage

Do these four things before filtering anything specific:

1. **View ▸ Time Display Format ▸ UTC Date and Time.**
2. **Statistics ▸ Capture File Properties** — start time, end time, duration.
3. **Statistics ▸ Protocol Hierarchy** — what's in here? (TCP, HTTP, DNS…)
4. **Statistics ▸ Conversations ▸ IPv4** — sort by Packets, then by Bytes. Note
   every remote IP `10.14.0.10` and `10.14.0.99` talk to.

Build a list of external IPs and what protocol each used. That list *is* your
lead list.

### Questions

1. What is the capture's total duration (to the nearest 10 seconds)?
2. How many IPv4 endpoints are in the capture? (Statistics ▸ Endpoints ▸ IPv4)
3. Which internal host is the source of the earliest packets — `10.14.0.10` or `10.14.0.99`?

---

## Task 2 — Stage 1: the port scan

Filter: `tcp.flags.syn == 1 and tcp.flags.ack == 0`

You'll see a rapid burst of `SYN` packets from **`10.14.0.99:44444`** to
**`10.14.0.10`**, one per destination port, all within a fraction of a second —
the signature of a **TCP SYN ("half-open") scan** (`nmap -sS`).

- **Closed ports** answer `RST, ACK` → filter `tcp.flags.reset == 1`.
- **Open ports** answer `SYN, ACK`, and the scanner replies `RST` (never completes
  the handshake) → filter:
  `tcp.flags.syn == 1 and tcp.flags.ack == 1 and ip.src == 10.14.0.10`

Cross-check with **Statistics ▸ Conversations ▸ TCP** — dozens of 1–2 packet
conversations from one source port is unmistakable.

### Questions

1. What is the source IP and source port of the scan?
2. How many destination ports are probed?
3. List the ports that replied `SYN, ACK` (i.e. were **open**).
4. What scan type is this (name / `nmap` flag)?
5. What is the timestamp (UTC) of the first scan packet?

---

## Task 3 — Stage 2: the web scan

The attacker found port 80 open and moved to it. Filter: `http.request and ip.src == 10.14.0.99`

Look at the **User-Agent**:

```
Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:map_codes)
```

That's the **Nikto** web scanner announcing itself. The requested paths
(`/admin/`, `/cgi-bin/test.cgi`, `/../../etc/passwd`, `/phpinfo.php`) are classic
vuln-scanner probes, and every one comes back `404`.

Filter to isolate the scanner UA:
`http.user_agent contains "Nikto"`

### Questions

1. What scanning tool is identified by the User-Agent, and what version?
2. How many HTTP requests does the scanner make?
3. What HTTP status code is returned to every scanner request?
4. Which requested path is a directory-traversal attempt?

---

## Task 4 — Stage 3: the malware download

Now switch focus to the **victim's** outbound traffic. Filter: `http.request and ip.src == 10.14.0.10`

One request stands out:

```
GET /win/update.exe HTTP/1.1
Host: cdn-updates.xyz
```

Right-click ▸ **Follow ▸ HTTP Stream**. The response is
`Content-Type: application/octet-stream` and the body starts with the bytes
`4D 5A` = **`MZ`** — the DOS/PE header magic. **This is a Windows executable.**

Pull it out: **File ▸ Export Objects ▸ HTTP ▸** select `update.exe` ▸ **Save**.
In a real investigation you would now hash it and submit to your sandbox / VT.

```bash
sha256sum update.exe          # then check the hash against threat intel
```

- Server IP: check the IP layer of the response packet.
- The download happens **after** the scan — the host was likely compromised via
  the web service, then pulled a second stage. (Note: this lab doesn't capture the
  exploit itself; the ordering + the beacon that follows is the tell.)

### Questions

1. What is the full URL (host + path) of the downloaded executable?
2. What IP address served the file?
3. What two ASCII bytes at the start of the file identify it as a PE/DOS executable?
4. What `Content-Type` header did the server send with it?
5. What is the SHA-256 of the exported file? *(export it and hash it)*

---

## Task 5 — Stage 4: C2 beaconing

Filter: `ip.dst == 185.199.108.153` — or spot it in **Conversations ▸ TCP** as a
stack of near-identical short conversations to port 443.

Characteristics of **command-and-control beaconing**:

| Trait | Here |
|---|---|
| Same destination, repeated | `10.14.0.10 → 185.199.108.153:443`, 8 times |
| Regular interval ("heartbeat") | new connection **every 60 seconds**, on the second |
| Small, near-constant payload | ~40–60 bytes each way |
| Long-lived pattern, low volume | 8 min, < 1 KB total |

Confirm the interval: filter to the beacon SYNs
(`ip.dst == 185.199.108.153 and tcp.flags.syn == 1 and tcp.flags.ack == 0`), add
the **Time (delta from previously displayed packet)** column
(`View ▸ Time Display Format ▸ Seconds Since Previous Displayed Packet`), and read
the deltas — they're all ~60.0 s.

**Statistics ▸ I/O Graph** with filter `ip.addr == 185.199.108.153` draws the
beacon as an evenly-spaced comb — the classic visual.

### Questions

1. What is the C2 IP address and destination port?
2. How many beacon connections are made?
3. What is the interval between beacons, in seconds?
4. What string appears at the start of the client's payload in each beacon? *(Follow one TCP stream)*
5. Why does port 443 here **not** necessarily mean TLS? *(look at the payload bytes)*

---

## Task 6 — Stage 5: DNS tunnelling / exfiltration

Filter: `dns`

Near the end of the capture, `10.14.0.10` fires a burst of **TXT** queries to
subdomains of **`c2.evil-corp.xyz`**:

```
mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho.c2.evil-corp.xyz   TXT?
nvqws3blorxxezjmzsw45dfoqqhk3tdn5sgs3thebqq.c2.evil-corp.xyz   TXT?
...
```

Tells of **DNS tunnelling**:
- **TXT** query type (rare for normal browsing; used to smuggle data both ways).
- Very **long, high-entropy** left-most label — looks like base32/base64.
- **Repeated queries to the same parent domain**, different subdomain each time.
- Query to the internal resolver, which recurses out — data leaves without a
  single "real" outbound connection to the attacker.

Filter just these: `dns.qry.type == 16 and dns.qry.name contains "evil-corp"`

**Statistics ▸ DNS** and **Statistics ▸ Conversations ▸ UDP** show the volume.

### Questions

1. What DNS record **type** (name and numeric value) is used for the tunnel?
2. What is the parent/base domain the subdomains belong to?
3. How many tunnelling queries are sent?
4. Why is a long random-looking subdomain label suspicious?
5. Which internal IP receives these queries (the resolver)?

---

## Task 7 — Build the incident timeline

Fill this in from your findings (UTC times from the capture):

| # | Time (UTC) | Stage | Source → Dest | Evidence (filter / packet) |
|---|-----------|-------|---------------|----------------------------|
| 1 | | Port scan | | |
| 2 | | Web scan | | |
| 3 | | Malware download | | |
| 4 | | C2 beacon (first) | | |
| 5 | | DNS tunnelling (first) | | |

Then answer:

1. Is this an incident? (yes/no + one sentence)
2. Which host do you isolate first, and why?
3. Give **three IOCs** from this capture you would push to the SIEM/blocklist.
4. Which of the five stages would a **signature IDS** (Suricata) most reliably
   catch on its own, and which needs **behavioural** analysis (Zeek / beacon
   analytics)?
5. What is the ATT&CK tactic for stage 5 (DNS tunnelling)?

---

## Task 8 — Where this goes next

- The **Suricata + Zeek** stack in [`../README.md`](../README.md) would log all
  five stages live — `ET SCAN` on stage 1–2, `ET MALWARE` / TLS-anomaly on 3–4,
  Zeek `dns.log` with long query names on 5.
- Replaying attacker traffic to practise on the live stack: [`../adversary-emulation.md`](../adversary-emulation.md).
- Turning the beacon into a durable detection (Sigma rule for long-duration
  low-byte outbound): Class 06 and [`../class-11-threat-hunting/`](../class-11-threat-hunting/).
