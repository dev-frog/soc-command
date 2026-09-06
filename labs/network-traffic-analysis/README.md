# Module — Network Traffic Analysis

A five-room, lab-first module in the TryHackMe style. Every room is built around a
capture file you open and work through yourself — read the task, run the filter,
read the answer off the screen. No slideware.

| # | Room | You learn to | Primary pcap | Tool |
|---|------|--------------|--------------|------|
| 1 | [Network Traffic Basics](01-network-traffic-basics.md) | Read a packet: frames, the TCP/IP stack, the 3-way handshake, ARP/ICMP/DNS/HTTP, ports, PDU sizes | `pcaps/net-basics.pcap` | Wireshark |
| 2 | [Wireshark: The Basics](02-wireshark-the-basics.md) | Drive the GUI, capture/display filters, the Statistics menu, follow a stream, colour rules | `pcaps/wireshark-basics.pcap` | Wireshark |
| 3 | [Wireshark: Packet Operations](03-wireshark-packet-operations.md) | Advanced filters/operators, `contains`/`matches`, Export Objects, extract cleartext credentials, profiles, `tshark` | `pcaps/packet-operations.pcap` | Wireshark + `tshark` |
| 4 | [Wireshark: Traffic Analysis](04-wireshark-traffic-analysis.md) | Work a real incident: spot a port scan, a web scan, a malware download, C2 beaconing and DNS tunnelling | `pcaps/traffic-analysis.pcap` | Wireshark |
| 5 | [NetworkMiner](05-networkminer.md) | Passive, object-first analysis: hosts, files, images, credentials, parameters, sessions, keyword search | `pcaps/networkminer.pcap` | NetworkMiner |

Answers to every question are in **[ANSWER-KEY.md](ANSWER-KEY.md)** (instructor copy —
hand out the room files without it if you want students to work cold).

---

## Setup

### Option A — you already have Wireshark

The pcaps are committed under [`pcaps/`](pcaps/). Just open them.

- **Wireshark** — <https://www.wireshark.org/download.html> (Win/macOS/Linux). Kali:
  `sudo apt install -y wireshark tshark`
- **NetworkMiner** (room 5) — <https://www.netresec.com/?page=NetworkMiner>.
  Free edition is enough. On Linux/macOS run it under Mono: `sudo apt install -y mono-complete` then `mono NetworkMiner.exe`.

### Option B — rebuild the pcaps

```bash
cd labs/network-traffic-analysis
./setup.sh            # makes a venv, installs scapy, regenerates pcaps/
```

The captures are 100% synthetic and deterministic — a rebuild reproduces the
exact same packets, so the answer key never drifts. Nothing is ever sent on the
wire; `generate_pcaps.py` only crafts frames and writes files.

### Lab network facts (same across all rooms)

| Host | IP | Role |
|------|----|------|
| SOC workstation / capture host | `10.14.0.50` | where you're "sitting" |
| Windows workstation (compromised in room 4) | `10.14.0.10` | victim |
| Attacker box (room 4) | `10.14.0.99` | attacker |
| `Ellie-PC` (room 5) | `10.14.0.55` | user endpoint |
| Gateway | `10.14.0.1` | router |
| DNS resolver | `10.14.0.2` | internal DNS |

Capture epoch for all files: **2024-09-06 12:00:00 UTC**.

---

## How to run it as a class (≈2.5–3 h)

| Block | Time | What |
|-------|------|------|
| 0 · Frame it | 10 min | Draw the OSI/TCP-IP stack + the 3-way handshake on the board. Everything after is "find that on screen". |
| 1 · Room 1 | 25 min | `net-basics.pcap` — walk one packet field by field, then the handshake, then ARP→DNS→HTTP as a story. |
| 2 · Room 2 | 30 min | `wireshark-basics.pcap` — filters, Statistics ▸ Protocol Hierarchy / Conversations / Endpoints, Follow HTTP Stream. |
| 3 · Room 3 | 30 min | `packet-operations.pcap` — `http.request.method == "POST"`, `frame contains "PASS"`, File ▸ Export Objects ▸ HTTP, then the same in `tshark`. |
| — break — | 10 min | |
| 4 · Room 4 | 40 min | `traffic-analysis.pcap` — students find the 5 stages of the intrusion and fill in an incident timeline. This is the assessment. |
| 5 · Room 5 | 25 min | `networkminer.pcap` — same data, tool that does the carving for you. Contrast with Wireshark. |
| 6 · Debrief | 10 min | Map findings to detections (Suricata/Zeek in [`../`](../README.md)) and to the Class 09 forensics + Class 11 hunt labs. |

### Ties into the rest of the course

- Live sensors that would have caught room 4's traffic: **Suricata + Zeek** stack in [`../README.md`](../README.md).
- Generating your own malicious traffic to capture: [`../adversary-emulation.md`](../adversary-emulation.md).
- Turning a capture finding into a rule: Class 06 (detection engineering), Class 11 (`../class-11-threat-hunting/`).

---

## Rules of engagement

Only ever capture traffic on a network **you own or are authorised to monitor**.
On a shared training network, capture your own interface only. The pcaps in this
module are synthetic — the "attacker" and "C2" addresses are documentation-range
or lab addresses and point at nothing real.
