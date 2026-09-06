# Room 3 — Wireshark: Packet Operations

> **Difficulty:** Easy–Medium · **Time:** ~30 min · **Prerequisites:** Rooms 1–2
> **Capture:** `pcaps/packet-operations.pcap` (76 packets)
> **Tools:** Wireshark + `tshark`

This room is about *operating* on packets: the full display-filter operator set,
string matching with `contains` / `matches`, pulling files and credentials out of
a capture, saving a profile, and doing the same work headless with `tshark`.

The capture is a login-heavy session with **cleartext credentials in four places**
and one **downloadable file**. Your job is to get all of it out.

---

## Task 1 — Display filter operators in full

### Comparison

| Operator | Alt | Meaning |
|---|---|---|
| `==` | `eq` | equal |
| `!=` | `ne` | not equal |
| `>` `<` | `gt` `lt` | greater / less than |
| `>=` `<=` | `ge` `le` | greater-or-equal / less-or-equal |

### Logical

| Operator | Alt |
|---|---|
| `and` | `&&` |
| `or` | `\|\|` |
| `not` | `!` |
| `x in {a b c}` | set membership: `tcp.port in {80 443 8080}` |

### Existence & slicing

- `http.authorization` — matches any packet that **has** that field at all.
- `http.host contains "intranet"` — substring match on a field value.
- `frame contains "PASS"` — substring anywhere in the frame bytes.
- `http.user_agent matches "(?i)nikto"` — regex (PCRE), `(?i)` = case-insensitive.
- `eth.addr[0:3] == 08:00:27` — byte-slice (first 3 bytes = OUI).

> Gotcha: `ip.addr != 10.14.0.2` means "has an address field that isn't
> 10.14.0.2" — which is *every* packet with two addresses. To exclude a host use
> `not ip.addr == 10.14.0.2`.

### Questions

1. Write a filter for HTTP requests whose `Host` header contains the string `portal`.
2. Write a filter using `matches` for a case-insensitive regex hit on `nikto` in the User-Agent. *(no hits expected in this pcap — that's fine)*
3. What does `tcp.port in {21 80}` match?
4. Why does `ip.addr != 10.14.0.90` **not** do what a beginner expects?

---

## Task 2 — Finding cleartext credentials

Cleartext protocols (HTTP Basic auth, HTTP form POSTs, FTP, Telnet, IMAP/POP3
without TLS) put credentials on the wire in the clear. Wireshark finds them
several ways.

### 2a — HTTP Basic auth

Filter: `http.authorization`

One hit — a `GET /admin/`. Expand **Hypertext Transfer Protocol ▸ Authorization**.
Wireshark base64-decodes it for you:

```
Authorization: Basic YWRtaW46UGFzc3dvcmQxMjMh
Credentials: admin:Password123!
```

### 2b — HTTP login form (POST body)

Filter: `http.request.method == "POST"`

One hit — `POST /login.php`. Right-click ▸ **Follow ▸ HTTP Stream**. The request
body is form-encoded:

```
username=j.doe&password=S3cr3t-Winter-2024&remember=1
```

The response is `302 Found` with a `Set-Cookie: PHPSESSID=...` — the login worked.

### 2c — FTP

Filter: `ftp`

FTP commands are one per packet, plain text. Look for `USER` and `PASS`:

```
USER backup-svc
PASS Backup#2024!
```

`Statistics ▸ … ` no — for FTP use **filter `ftp.request.command == "PASS"`** to
jump straight to passwords. The data connection (file transfer) is on a separate
port negotiated by the `227 Entering Passive Mode (10,14,0,90,200,1)` reply →
port `200*256 + 1 = 51201`. Filter `tcp.port == 51201` to see the transferred SQL
dump; **Follow ▸ TCP Stream** to read it.

### 2d — The shortcut

Older Wireshark had **Tools ▸ Credentials** (auto-lists every credential it can
parse). If your build has it, run it and confirm it catches 2a + 2c. If not, the
manual filters above are the method.

### Questions

1. What username:password pair is in the HTTP Basic auth header?
2. What password is submitted in the `POST /login.php` form body?
3. What session cookie name+value does the server set after a successful login?
4. What is the FTP username and password?
5. What TCP port carries the FTP **data** transfer, and what filename is retrieved?

---

## Task 3 — Exporting files (objects) from a capture

**File ▸ Export Objects ▸ HTTP** lists every file Wireshark reassembled from HTTP
responses: packet number, hostname, content type, size, filename. Select a row ▸
**Save** (or **Save All**).

In this capture you should see:

| Host | Content Type | File |
|---|---|---|
| portal.company-intranet.lan | text/html | `/admin/` |
| portal.company-intranet.lan | text/plain | `q3-salaries.txt` |

Save `q3-salaries.txt` and open it. It contains a flag line.

Other export menus: **Export Objects ▸ FTP-DATA / SMB / TFTP / IMF (email) / DICOM**.
For protocols with no export option, **Follow ▸ TCP Stream ▸ Show data as Raw ▸
Save as** does the same job manually.

### Questions

1. How many HTTP objects does **Export Objects ▸ HTTP** list?
2. What is the content of the flag line inside `q3-salaries.txt`?
3. What `Content-Disposition` filename does the server suggest for that download?

---

## Task 4 — Profiles

A **profile** is a saved bundle of: coloring rules, display filter buttons, column
layout, preferences, saved filters. Bottom-right of the status bar shows the
current one ("Default").

**Right-click the profile name ▸ New** → make one called `soc-triage`:
- Columns: add `Source Port`, `Destination Port`, `http.host`, `http.request.uri`.
- Filter buttons (`+` at the right end of the filter bar):
  `creds` = `http.authorization or ftp.request.command in {"USER" "PASS"} or http.request.method == "POST"`
  `web` = `http.request`
  `scan` = `tcp.flags.syn == 1 and tcp.flags.ack == 0`
- Save. Switch back to Default and see it all revert.

Profiles live in the Wireshark config dir (`Help ▸ About ▸ Folders ▸ Personal
configuration`), one folder each — portable, check them into a repo, share with
the team.

### Questions

1. Name three things stored in a Wireshark profile.
2. Where on screen do you see / switch the active profile?
3. What menu path shows you the folder where profiles are stored?

---

## Task 5 — Doing it in `tshark`

`tshark` is Wireshark's CLI — same dissectors, same filters, scriptable. Run these
against the pcap:

```bash
cd labs/network-traffic-analysis

# every packet, one line each
tshark -r pcaps/packet-operations.pcap

# apply a display filter (-Y) and print chosen fields (-T fields -e ...)
tshark -r pcaps/packet-operations.pcap -Y "http.request" \
       -T fields -e frame.number -e http.request.method -e http.host -e http.request.uri

# pull the HTTP Basic auth credentials
tshark -r pcaps/packet-operations.pcap -Y "http.authorization" \
       -T fields -e http.authorization_basic

# every FTP command
tshark -r pcaps/packet-operations.pcap -Y "ftp.request" \
       -T fields -e ftp.request.command -e ftp.request.arg

# follow a stream by number
tshark -r pcaps/packet-operations.pcap -q -z follow,tcp,ascii,1

# protocol hierarchy / conversations (the Statistics menu, headless)
tshark -r pcaps/packet-operations.pcap -q -z io,phs
tshark -r pcaps/packet-operations.pcap -q -z conv,tcp

# export HTTP objects to a folder
mkdir -p /tmp/objs && tshark -r pcaps/packet-operations.pcap --export-objects http,/tmp/objs
ls /tmp/objs
```

Key flags: `-r` read file · `-Y` display filter · `-T fields -e <field>` column
output · `-q -z <stat>` run a statistic and quit · `-c N` first N packets ·
`-w out.pcap` write (with `-Y`/`-f` to slice a capture).

### Questions

1. What single `tshark` command prints only the FTP command + argument for every FTP request packet?
2. Run the `--export-objects http` command. What files land in the output folder?
3. Using `-z io,phs`, what is the total HTTP packet count reported?
4. What `-z` argument gives you the TCP conversations list?
