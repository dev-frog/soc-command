#!/bin/bash
# =====================================================================
# Class 11 lab — VICTIM host ("web01") :: one-command bring-up
# Stands up DVWA + weak-cred OpenSSH, then AUTO-CONFIGURES DVWA so it is
# hackable immediately (DB created/reset, security level = Low).
#
#   ./run.sh            bring the victim up and configure it
#   ./run.sh clean      tear it down and wipe its volume
#   ./run.sh logs       follow container logs
#
# RUN ONLY on an isolated host-only / internal lab network.
# =====================================================================
set -e
cd "$(dirname "$0")"

DC="docker compose"
$DC version >/dev/null 2>&1 || DC="docker-compose"

case "$1" in
  clean|down)
    $DC down -v
    echo "[*] victim torn down, volume wiped"
    exit 0 ;;
  logs)
    $DC logs -f
    exit 0 ;;
esac

echo "[*] Bringing up web01 (DVWA + OpenSSH) ..."
$DC up -d

echo -n "[*] waiting for DVWA to answer on :8080 "
for _ in $(seq 1 45); do
  if curl -sf -o /dev/null "http://localhost:8080/login.php"; then ok=1; break; fi
  echo -n "."; sleep 2
done
echo
[ "${ok:-0}" = 1 ] || { echo "[!] DVWA never came up — check: ./run.sh logs"; exit 1; }

# --- auto-configure DVWA (no clicking through setup.php) --------------
CJ=$(mktemp)
trap 'rm -f "$CJ"' EXIT
tok() {
  curl -s -c "$CJ" -b "$CJ" "http://localhost:8080/$1" \
    | tr '<' '\n' | grep user_token | grep -oE '[a-f0-9]{32}' | head -1
}

echo "[*] create / reset DVWA database ..."
curl -s -c "$CJ" -b "$CJ" -o /dev/null \
  --data-urlencode "create_db=Create / Reset Database" \
  --data "user_token=$(tok setup.php)" \
  "http://localhost:8080/setup.php"

echo "[*] log in as admin ..."
curl -s -c "$CJ" -b "$CJ" -o /dev/null \
  --data "username=admin&password=password&Login=Login&user_token=$(tok login.php)" \
  "http://localhost:8080/login.php"

echo "[*] set security level = Low ..."
curl -s -c "$CJ" -b "$CJ" -o /dev/null \
  --data "security=low&seclev_submit=Submit&user_token=$(tok security.php)" \
  "http://localhost:8080/security.php"

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
IP=${IP:-$(ipconfig getifaddr en0 2>/dev/null)}
IP=${IP:-<host-ip>}

cat <<EOF

[+] web01 is UP and pre-configured. Attack surface:

      DVWA   http://$IP:8080          admin / password   (DB reset, security = Low)
      SSH    ssh support@$IP -p 2222  password: support

    Upload page  :  http://$IP:8080/vulnerabilities/upload/
    Uploads land :  /var/www/html/hackable/uploads/   (SSH box sees the same dir at /uploads)

[>] 1. Hack it            — follow ATTACK-MANUAL.md  (nmap / hydra / weevely / msfvenom ...)
[>] 2. Pull real evidence — ../collect.sh            (victim logs + your uploaded shells -> ./work)
[>] 3. Hunt your intrusion — ../hunt.sh -s
[>] Reset between runs    — ./run.sh clean && ./run.sh
EOF
