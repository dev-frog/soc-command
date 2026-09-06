# Room 5 — NetworkMiner

> **Difficulty:** Easy–Medium · **Time:** ~25 min · **Prerequisites:** Rooms 1–4
> **Capture:** `pcaps/networkminer.pcap` (66 packets)
> **Tool:** NetworkMiner (free edition)

Wireshark is **packet-centric** — you filter frames and reassemble by hand.
NetworkMiner is **host- and artefact-centric** — you feed it a pcap and it hands
you back *hosts, files, images, credentials, DNS records, parameters and sessions*
already carved out, sorted into tabs. It is a **passive** tool: open pcap, read
tabs, nothing is sent.

This is the same style of data as room 3 (a browsing session with a PDF download,
an image, HTTP Basic auth and an FTP login) — but you'll pull it apart a different
way.

---

## Task 1 — Load the capture

- **Windows:** run `NetworkMiner.exe`, **File ▸ Open**, pick
  `pcaps/networkminer.pcap`.
- **Linux/macOS:** `mono NetworkMiner.exe`, or the AppImage. If tabs look empty,
  check **File ▸ Open** actually parsed (status bar shows "Frames parsed").

The tab strip across the top is the whole tool: **Hosts · Files · Images ·
Messages · Credentials · Sessions · DNS · Parameters · Keywords · Anomalies**.

### Questions

1. Is NetworkMiner an active or a passive tool?
2. Which tab would you open first to see every device seen in the capture?

---

## Task 2 — Hosts tab

Every IP NetworkMiner saw, as an expandable tree node. Per host it tries to show:
MAC + **vendor** (from the OUI), **OS guess** (from TTL / TCP options / User-Agent),
open ports, hostnames, sent/received bytes, and which **frames** involve it.

Expand `10.14.0.55`:
- **Host Details** → OS guess derived from the browser User-Agent.
- **Sent packets / Received packets**, byte counts.
- Under it: the outgoing sessions.

Right-click a host ▸ **Copy ▸ IP address**, or colour-tag it.

### Questions

1. How many hosts are listed?
2. For host `10.14.0.55`, what operating system does NetworkMiner infer, and from what?
3. What are the server-side IP addresses the client connected to? (list them)
4. Which host is contacted for `telemetry.tracker-ads.net`?

---

## Task 3 — Files & Images tabs

**Files** = everything NetworkMiner reconstructed from HTTP / FTP-DATA / SMB / TFTP
/ email. Columns: filename, extension, size, source host, destination host,
protocol, timestamp, **reconstructed path on disk** (it saves every file to its
`AssembledFiles/` folder automatically), and MD5.

**Images** = the subset that are pictures, shown as thumbnails — fast way to spot
exfiltrated screenshots, defacement images, etc.

In this capture you should get:

| File | Type | From |
|---|---|---|
| `report.pdf` (or `report[1].pdf`) | application/pdf | `intranet.acme-corp.com` |
| `banner.png` | image/png | `files.acme-corp.com` |
| the two HTML pages | text/html | " |

Right-click a file ▸ **Open file** / **Open folder**. Check its MD5 against
threat intel before opening anything for real.

### Questions

1. How many files does NetworkMiner reconstruct?
2. What is the filename and file type of the document downloaded from `intranet.acme-corp.com`?
3. What appears on the **Images** tab?
4. NetworkMiner auto-saves reconstructed files — to which subfolder?
5. What MD5 hash does it report for `banner.png`?

---

## Task 4 — Credentials tab

NetworkMiner's headline feature: it parses credentials out of HTTP Basic/Digest
auth, HTTP POST forms, FTP, Telnet, IMAP, POP3, SMB/NTLM, Kerberos and more, into
one table — username, password (or hash), protocol, source/dest host, timestamp,
and the "valid?" heuristic.

You should see **two** rows:

| Protocol | Username | Password | Host |
|---|---|---|---|
| HTTP (Basic) | `ellie.myers` | `Autumn!Leaves#7` | `intranet.acme-corp.com` |
| FTP | `ftpuser` | `Pr0d-FTP-2024` | `203.0.113.77` |

For the HTTP Basic row, NetworkMiner shows both the raw base64 and the decoded
`user:pass`.

### Questions

1. How many credential sets does NetworkMiner extract?
2. What is the FTP username and password?
3. What is the HTTP Basic auth username and password, and for which host?
4. Which of these two would Wireshark's `http.authorization` filter alone **not** have caught?

---

## Task 5 — DNS, Parameters, Sessions, Keywords

### DNS tab
Every query/response: client, server, query name, type, answer, TTL. Sortable —
scan the **query name** column for odd domains (long labels, DGA-looking names,
known-bad TLDs).

### Parameters tab
Every HTTP parameter, header value, form field, User-Agent, cookie,
`Content-Type`, Referer, etc. — searchable. Great for "did anything POST a
parameter called `password`/`token`/`file`?".

### Sessions tab
One row per connection: client, server, ports, protocol, start time, duration,
frame range. This is NetworkMiner's version of **Statistics ▸ Conversations**.

### Keywords tab
**Before** loading a pcap you can add keywords (e.g. `password`, `confidential`,
`.exe`, an internal project name). NetworkMiner then flags every frame containing
them and lists the hits here with context. Add `confidential` and reload — the
PDF body matches.

### Questions

1. From the **DNS** tab: how many distinct query names were resolved?
2. Which resolved domain looks like third-party ad/tracking rather than corporate?
3. From **Sessions**: how many sessions are listed, and what protocols?
4. From **Parameters**: what `User-Agent` string did `10.14.0.55` send?
5. Add the keyword `confidential`, reload the pcap — which reconstructed file contains it?

---

## Task 6 — NetworkMiner vs Wireshark

| Task | Wireshark | NetworkMiner |
|---|---|---|
| See a specific retransmission / flag / seq number | ✅ built for it | ✗ |
| "Give me every file, credential and hostname" | manual (Export Objects, follow streams, filters) | ✅ one click per tab |
| Live capture + deep protocol dissection | ✅ | limited (Pro does more) |
| Fast IR triage of a handed-to-you pcap | slower | ✅ start here |
| Custom display filter / packet surgery | ✅ | ✗ |

**Workflow in practice:** run the pcap through NetworkMiner first to get the
inventory (hosts, files, creds, domains), *then* jump to Wireshark to examine the
specific packets that matter.

### Questions

1. Give one analysis task Wireshark can do that NetworkMiner cannot.
2. Give one task NetworkMiner does far faster than Wireshark.
3. In an IR triage workflow, which tool do you typically open first, and why?

---

## Module wrap-up

You can now: read a packet (R1), drive Wireshark and its Statistics menu (R2),
operate on packets — filters, objects, credentials, `tshark` (R3), work a
multi-stage intrusion from a capture and produce a timeline + IOCs (R4), and
triage a pcap fast with NetworkMiner (R5).

Next in the course: feed this skill into the live **Suricata/Zeek** stack
([`../README.md`](../README.md)), the **threat-hunting** lab
([`../class-11-threat-hunting/`](../class-11-threat-hunting/)), and detection
engineering (Class 06).
