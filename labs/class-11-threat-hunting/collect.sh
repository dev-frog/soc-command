#!/bin/bash
# =====================================================================
# Class 11 — Threat Hunting Lab :: evidence collection
# Pulls REAL artifacts off the victim you just hacked (see ATTACK-MANUAL.md)
# into ./work/ in the exact layout hunt.sh expects, so the hunt chases
# YOUR intrusion instead of the canned scenario.
#
#   ./collect.sh          rebuild ./work from the live victim containers
#   ./collect.sh clean    remove ./work
#
# Needs the victim running:  ./victim/run.sh
# For a purely offline scenario, use ./setup.sh or ./attack.sh instead.
# =====================================================================
set -e
cd "$(dirname "$0")"
WORK="./work"
SCEN="./scenario"
DVWA="web01-dvwa"
SSHC="web01-ssh"

if [ "$1" = "clean" ]; then
  rm -rf "$WORK"; echo "[*] Removed $WORK"; exit 0
fi

docker ps --format '{{.Names}}' | grep -qx "$DVWA" || {
  echo "[!] $DVWA is not running. Start the target first:  ./victim/run.sh"
  exit 1
}

echo "[*] Rebuilding $WORK from the live victim ..."
rm -rf "$WORK"
mkdir -p "$WORK/var/www/html/uploads" "$WORK/var/log/archive" \
         "$WORK/zeek" "$WORK/opt/bin" "$WORK/dev/shm" "$WORK/tmp"

# --- 1. Web root — just the uploads dir (real: whatever you uploaded) --
#     Keep it narrow so hunt 1 (YARA) fires on your shell, not on DVWA's
#     own intentionally-vulnerable source.
docker cp "$DVWA:/var/www/html/hackable/uploads/." "$WORK/var/www/html/uploads/" 2>/dev/null || true
printf '<?php echo "SOC Command demo app"; ?>\n'      > "$WORK/var/www/html/index.php"
printf '<?php $DB_HOST = "db.internal"; ?>\n'          > "$WORK/var/www/html/config.php"

# --- 2. Logs — apache access/error + sshd auth, merged into one stream -
{
  echo "### --- apache (web01-dvwa) ---"
  docker exec "$DVWA" sh -c 'cat /var/log/apache2/*.log 2>/dev/null' || true
  docker logs "$DVWA" 2>&1 | grep -E '"(GET|POST|HEAD) ' || true
  echo "### --- sshd (web01-ssh) ---"
  docker logs "$SSHC" 2>&1 | grep -Ei 'sshd|password|authentication|accepted|failed' || true
} > "$WORK/var/log/syslog"

# --- 3. Archived + gzipped copies so hunt 2's zgrep path has depth ----
cp "$WORK/var/log/syslog" "$WORK/var/log/archive/syslog.1"
gzip -c "$WORK/var/log/syslog" > "$WORK/var/log/archive/syslog.2.gz"

# --- 4. Host persistence — pull real SUID / memory-staged files, if any
for c in "$DVWA" "$SSHC"; do
  docker exec "$c" sh -c 'find / -xdev -type f -perm -4000 2>/dev/null' \
    | sed "s|^|$c |" >> "$WORK/opt/bin/.suid_inventory" || true
done
docker cp "$DVWA:/dev/shm/."  "$WORK/dev/shm/"  2>/dev/null || true
docker cp "$DVWA:/tmp/."      "$WORK/tmp/"      2>/dev/null || true
# strip the noisy stuff docker/apache leave in /tmp so hunt 5 stays readable
find "$WORK/tmp" -type f ! -perm -111 -delete 2>/dev/null || true

# --- 5. "Given" intel + network evidence -----------------------------
#     CTI report is handed to you at shift start; conn.log comes from the
#     Zeek stack in ../ if it is running, otherwise the canned beacon.
cp "$SCEN/apt_report.txt"    "$WORK/apt_report.txt"
cp "$SCEN/malicious_ips.txt" "$WORK/malicious_ips.txt"
if [ -f ../zeek/logs/current/conn.log ]; then
  cp ../zeek/logs/current/conn.log "$WORK/zeek/conn.log"
  echo "[*] used live Zeek conn.log from ../zeek/logs/current/"
else
  cp "$SCEN/conn.log" "$WORK/zeek/conn.log"
fi

# --- 6. Make hunt 2 land: name your attacker IP as a CTI hit ----------
TOP=$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$WORK/var/log/syslog" \
        | grep -vE '^(127\.|0\.0\.0\.0)' | sort | uniq -c | sort -rn \
        | awk 'NR==1 && $1 > 3 {print $2}')
if [ -n "$TOP" ] && ! grep -qF "$TOP" "$WORK/malicious_ips.txt"; then
  echo "$TOP" >> "$WORK/malicious_ips.txt"
  echo "[*] loudest source in the logs was $TOP — added to work/malicious_ips.txt"
  echo "    (stands in for CTI naming your C2; edit that file to curate it)"
fi

cat <<EOF

[+] $WORK rebuilt from the live victim:
      uploads      : $(ls "$WORK/var/www/html/uploads" 2>/dev/null | tr '\n' ' ')
      log lines    : $(wc -l < "$WORK/var/log/syslog")
      /dev/shm     : $(ls -A "$WORK/dev/shm" 2>/dev/null | tr '\n' ' ')
      SUID found   : $(wc -l < "$WORK/opt/bin/.suid_inventory" 2>/dev/null || echo 0)

[>] Hunt it:  ./hunt.sh -s

    Notes:
      - hunts 1-2 reflect exactly what you did to the box.
      - hunts 3 (beacon) + 6 (IOC extraction) use the scenario feeds unless
        you ran the real C2 / Zeek stack — that is expected.
      - hunts 4-5 only light up if your attack actually planted a SUID binary
        or dropped an executable in /dev/shm (ATTACK-MANUAL.md stage 6).
EOF
