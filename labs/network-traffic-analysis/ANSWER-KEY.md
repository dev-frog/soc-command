# Answer Key — Network Traffic Analysis (instructor copy)

> Do not hand this out with the room files. All values are reproducible: rebuild
> the pcaps with `./setup.sh` and they will not change.
>
> Some GUI counts vary by ±1 across Wireshark / NetworkMiner versions (how empty
> or zero-length responses are counted, whether DNS-only hosts are listed). Where
> that happens it is noted.

---

## Room 1 — Network Traffic Basics  (`net-basics.pcap`, 20 packets)

### Task 1
1. **4**
2. **Frame**
3. **Segment**
4. **Encapsulation**

### Task 2
1. **08:00:27:aa:bb:01**
2. **10.14.0.1**
3. **2024-09-06 12:00:00** (UTC)
4. **42** bytes

### Task 3 — ARP
1. **1**
2. **08:00:27:00:00:fe**
3. Layer **2** (Data Link)

### Task 4 — ICMP
1. **3**
2. **0**
3. **0x1337**
4. **16** bytes (`abcdefghijklmnop`)

### Task 5 — DNS
1. **A** record
2. **93.184.216.34**
3. **UDP**, port **53**
4. **0x2a2a**

### Task 6 — handshake + HTTP
1. **SYN, ACK**
2. **GET**
3. **curl/8.4.0**
4. **200 OK**
5. **80**
6. **FIN**

### Task 7
1. **ARP**
2. **4** (`10.14.0.50`, `10.14.0.1`, `10.14.0.2`, `93.184.216.34`)
3. **Packet 13** (the client's `ACK` completing the 3-way handshake)

---

## Room 2 — Wireshark: The Basics  (`wireshark-basics.pcap`, 39 packets)

### Task 1
1. **39**
2. **Red**
3. **Statistics**

### Task 2
1. `ip.addr == 10.14.0.80`
2. `udp port 53`
3. **False** — a display filter only hides; the packets stay in the pcap.

### Task 3
1. **6** (3 queries + 3 responses)
2. **nosuch.company-intranet.lan**
3. **3** (`/index.html`, `/logo.png`, `/npm/jquery@3.7.1/dist/jquery.min.js`)
4. **`http.response.code`**
5. **3**

### Task 4 — Statistics
1. DNS **6**, HTTP **6** (3 requests + 3 responses)
2. **10.14.0.80** (≈1449 bytes vs ≈1245 for `151.101.1.229`)
3. **2** (`www.company-intranet.lan`, `cdn.jsdelivr.net`)
4. **≈5 seconds** (5.16 s)
5. **3**

### Task 5 — streams
1. **0** (first TCP stream in the file)
2. **Company Intranet**
3. `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36`
4. **image/png**
5. **cdn.jsdelivr.net** (151.101.1.229)

### Task 6 — coloring
1. **Bad TCP**
2. **Top-to-bottom** (first match wins)
3. **False** — "Colorize Conversation" is a temporary rule, discarded on close.

---

## Room 3 — Wireshark: Packet Operations  (`packet-operations.pcap`, 76 packets)

### Task 1 — operators
1. `http.host contains "portal"`
2. `http.user_agent matches "(?i)nikto"`
3. Any packet whose TCP source **or** destination port is 21 or 80.
4. `ip.addr != 10.14.0.90` reads as "there exists an address field ≠ 10.14.0.90",
   and every IP packet has a second address that satisfies that — so it matches
   almost everything. Correct form: `not ip.addr == 10.14.0.90`.

### Task 2 — credentials
1. **`admin:Password123!`**
2. **`S3cr3t-Winter-2024`**
3. **`PHPSESSID=b1f7c0de9a4e11ee`**
4. **`backup-svc` / `Backup#2024!`**
5. Port **51201** (from `227 … (10,14,0,90,200,1)` → 200×256+1); file
   **`backups/db-2024-09-06.sql`**

### Task 3 — Export Objects
1. **2** (`/admin/` HTML page, `q3-salaries.txt`). Some builds also list the
   zero-length `302` from `/login.php` — accept 2 or 3.
2. **`flag{http_object_export_works}`**
3. **`q3-salaries.txt`**

### Task 4 — profiles
1. Any three of: coloring rules, column layout, display-filter buttons, saved
   filters, capture/preference settings, saved decode-as entries.
2. **Bottom-right of the status bar** (right-click it to switch/create).
3. **Help ▸ About Wireshark ▸ Folders ▸ Personal configuration** (each profile is
   a sub-folder of `profiles/`).

### Task 5 — tshark
1. `tshark -r pcaps/packet-operations.pcap -Y "ftp.request" -T fields -e ftp.request.command -e ftp.request.arg`
2. The `/admin/` index page and **`q3-salaries.txt`** (exact on-disk names depend
   on the tshark version's URI-to-filename scheme).
3. **6** HTTP packets.
4. **`-z conv,tcp`**

---

## Room 4 — Wireshark: Traffic Analysis  (`traffic-analysis.pcap`, 167 packets)

### Task 1 — triage
1. **≈500 seconds** (500.15 s)
2. **5** (`10.14.0.10`, `10.14.0.99`, `10.14.0.2`, `45.9.148.37`, `185.199.108.153`)
3. **10.14.0.99** (the scan is the first thing in the capture, at 12:00:00)

### Task 2 — port scan
1. **10.14.0.99**, source port **44444**
2. **20** ports
3. **22, 80, 445**
4. **TCP SYN / half-open scan** (`nmap -sS`) — scanner sends `RST` instead of
   completing the handshake on open ports.
5. **2024-09-06 12:00:00** UTC

### Task 3 — web scan
1. **Nikto**, version **2.5.0**
2. **5** requests (`/`, `/admin/`, `/cgi-bin/test.cgi`, `/../../etc/passwd`, `/phpinfo.php`)
3. **404 Not Found**
4. **`/../../etc/passwd`**

### Task 4 — malware download
1. **`cdn-updates.xyz/win/update.exe`**
2. **45.9.148.37**
3. **`MZ`** (`4D 5A`)
4. **`application/octet-stream`**
5. SHA-256 **`58a4af1724fd884affbfeb021d170ad3c2d9d2867b8d24bc11a77fbb44aea041`**
   (MD5 `7d5e446baa8ddae01d9a2b11a11710d6`, 235 bytes) — synthetic, not real malware.

### Task 5 — C2 beaconing
1. **185.199.108.153**, port **443**
2. **8**
3. **60 seconds**
4. **`BEACON-CHECKIN-`** (followed by `000`, `001`, …)
5. Because the payload is **not a TLS handshake** — there is no `ClientHello`,
   no certificate exchange, just plaintext. A port number does not define the
   protocol; malware often uses 443 to blend in.

### Task 6 — DNS tunnelling
1. **TXT**, numeric type **16**
2. **`c2.evil-corp.xyz`**
3. **4**
4. The left-most label is long and high-entropy — it is **encoded data**
   (base32/base64), not a hostname a human or app would ever request. Normal
   subdomains are short and readable.
5. **10.14.0.2** (the internal resolver, which then recurses outbound)

### Task 7 — timeline

| # | Time (UTC) | Stage | Source → Dest | Evidence |
|---|-----------|-------|---------------|----------|
| 1 | 12:00:00 | Port scan | 10.14.0.99:44444 → 10.14.0.10 (20 ports) | `tcp.flags.syn==1 && tcp.flags.ack==0` |
| 2 | 12:00:02 | Web/Nikto scan | 10.14.0.99 → 10.14.0.10:80 | `http.user_agent contains "Nikto"` |
| 3 | 12:00:05 | Malware download | 10.14.0.10 → 45.9.148.37:80 `GET /win/update.exe` | Export Objects ▸ HTTP; body starts `MZ` |
| 4 | 12:00:10 | C2 beacon (first) | 10.14.0.10 → 185.199.108.153:443 | 8× 60 s interval, ~40 B payload |
| 5 | 12:08:15 | DNS tunnelling (first) | 10.14.0.10 → 10.14.0.2 TXT `*.c2.evil-corp.xyz` | `dns.qry.type==16 && dns.qry.name contains "evil-corp"` |

1. **Yes** — a host was scanned, then made an unsolicited executable download
   followed by regular-interval encrypted-looking beaconing and DNS-based data
   egress: textbook compromise.
2. **10.14.0.10** — it is the victim, it is actively beaconing to C2 and
   tunnelling data out; containing it stops both the C2 channel and any exfil.
3. Any three of: C2 IP **185.199.108.153**; malware host **cdn-updates.xyz** /
   **45.9.148.37**; URL **`/win/update.exe`**; file hash
   `58a4af17…aea041`; tunnelling domain **`c2.evil-corp.xyz`**; User-Agent
   `Mozilla/5.00 (Nikto/2.5.0)…`.
4. **Signature IDS** reliably catches stages 1–2 (`ET SCAN` on the SYN sweep and
   the Nikto UA). Stage 4 (beacon) and stage 5 (tunnel) need **behavioural**
   analysis — periodicity / long-connection / query-length analytics (Zeek +
   beacon detection); the individual packets look benign.
5. **Exfiltration** — *Exfiltration Over Alternative Protocol* / *Exfiltration
   Over C2 Channel* (T1048), with DNS as the channel (*Application Layer
   Protocol: DNS*, T1071.004, for the C2 side).

---

## Room 5 — NetworkMiner  (`networkminer.pcap`, 66 packets)

### Task 1
1. **Passive** (it never transmits; it only parses the pcap/interface).
2. **Hosts**

### Task 2 — Hosts
1. **4** — `10.14.0.55`, `10.14.0.2`, `203.0.113.42`, `203.0.113.77`. Some
   NetworkMiner versions also add `198.51.100.9` from the DNS answer (never
   actually contacted) → accept 4 or 5.
2. **Windows** (specifically Windows 7 / "Windows NT 6.1") — inferred from the
   HTTP **User-Agent** string.
3. **203.0.113.42** (HTTP) and **203.0.113.77** (FTP); plus `10.14.0.2` for DNS.
4. **None** — `telemetry.tracker-ads.net` was only *resolved* (DNS answer
   `198.51.100.9`); there is no connection to it in the capture. (Good trick
   question — a DNS lookup is not a connection.)

### Task 3 — Files & Images
1. **4** — the two HTML pages (`/` and `/private/`), `report.pdf`, `banner.png`
   (±1 depending on how the tool counts the HTML bodies).
2. **`report.pdf`**, type **application/pdf** (PDF document).
3. **`banner.png`** (a 1×1 PNG).
4. **`AssembledFiles/`** (under the NetworkMiner directory).
5. MD5 **`c5af1d0eb19ee8b9d16078c7a855efe5`** (68 bytes).

### Task 4 — Credentials
1. **2**
2. **`ftpuser` / `Pr0d-FTP-2024`**
3. **`ellie.myers` / `Autumn!Leaves#7`**, for host **`intranet.acme-corp.com`**
4. The **FTP** credentials — `http.authorization` is HTTP-only. (In Wireshark
   you'd need `ftp.request.command == "PASS"` for that one.)

### Task 5 — DNS / Parameters / Sessions / Keywords
1. **3** — `intranet.acme-corp.com`, `files.acme-corp.com`, `telemetry.tracker-ads.net`
2. **`telemetry.tracker-ads.net`**
3. **5 TCP sessions** — 4 HTTP (`55001`–`55004`) + 1 FTP (`55010`). NetworkMiner
   may also list the 3 DNS exchanges as UDP sessions → 5 or 8.
4. `Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0`
5. **`report.pdf`** (its body contains `ACME Q3 revenue: confidential`).

### Task 6 — comparison
1. e.g. inspect a specific retransmission / TCP flag / sequence number; write an
   arbitrary display filter; live deep-dissection; packet-level surgery.
2. e.g. "list every file / credential / hostname / image in this pcap" — one tab
   each, no manual reassembly.
3. **NetworkMiner first** — it gives you the inventory (who, what files, what
   creds, what domains) in seconds; then pivot to Wireshark for the packets that
   matter.

---

## Quick reference — every planted artefact

| pcap | Artefact | Value |
|------|----------|-------|
| net-basics | DNS answer | `example.com` → `93.184.216.34` |
| wireshark-basics | NXDOMAIN | `nosuch.company-intranet.lan` |
| packet-operations | HTTP Basic | `admin:Password123!` |
| packet-operations | HTTP form POST | `j.doe : S3cr3t-Winter-2024` |
| packet-operations | FTP | `backup-svc : Backup#2024!` |
| packet-operations | Exported file flag | `flag{http_object_export_works}` |
| traffic-analysis | Scanner | `10.14.0.99`, nmap `-sS` + Nikto/2.5.0 |
| traffic-analysis | Open ports | 22, 80, 445 |
| traffic-analysis | Malware URL | `cdn-updates.xyz/win/update.exe` @ `45.9.148.37` |
| traffic-analysis | Malware SHA-256 | `58a4af1724fd884affbfeb021d170ad3c2d9d2867b8d24bc11a77fbb44aea041` |
| traffic-analysis | C2 | `185.199.108.153:443`, 8 beacons @ 60 s, `BEACON-CHECKIN-` |
| traffic-analysis | DNS tunnel | `TXT` to `*.c2.evil-corp.xyz`, 4 queries |
| networkminer | HTTP Basic | `ellie.myers : Autumn!Leaves#7` |
| networkminer | FTP | `ftpuser : Pr0d-FTP-2024` |
| networkminer | Files | `report.pdf`, `banner.png` (md5 `c5af1d0eb19ee8b9d16078c7a855efe5`) |
