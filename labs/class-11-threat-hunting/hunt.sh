#!/bin/bash
# =====================================================================
# Class 11 — Threat Hunting Lab :: guided hunt
# Runs each hunt technique with a header + expected-signal note.
# Pass -s to pause between steps (good for live classroom demo).
# =====================================================================
cd "$(dirname "$0")"
WORK="./work"
STEP=0
PAUSE=0
[ "$1" = "-s" ] && PAUSE=1

[ -d "$WORK" ] || { echo "Run ./setup.sh first."; exit 1; }

hdr() {
  STEP=$((STEP+1))
  echo
  echo "======================================================================"
  echo " HUNT $STEP — $1"
  echo " hypothesis: $2"
  echo "======================================================================"
  [ "$PAUSE" = 1 ] && read -rp "   [enter to run] " _
}
note() { echo; echo "   >> EXPECT: $1"; }

# ---------------------------------------------------------------------
hdr "Webshell primitives in the web root" \
    "An attacker dropped a PHP webshell in an uploads dir"
if command -v yara >/dev/null; then
  yara -r -m rules/hunt_webshell.yar "$WORK/var/www/html/"
else
  echo "   (yara not installed - falling back to grep)"
  grep -rnE 'eval\(base64_decode\(|passthru\(|shell_exec\(|system\(\$_GET\[' "$WORK/var/www/html/"
fi
note "match on uploads/webshell.php"

# ---------------------------------------------------------------------
hdr "Known-bad IPs across archived logs" \
    "CTI gave us a C2 IP list; did any host talk to them already?"
grep -rnF -f "$WORK/malicious_ips.txt" "$WORK/var/log/" 2>/dev/null
echo "   --- also inside gzipped logs ---"
zgrep -HnF -f "$WORK/malicious_ips.txt" "$WORK"/var/log/archive/*.gz 2>/dev/null
note "45.153.160.140 (ssh brute) and 193.169.255.78 (webshell GET) hits"

# ---------------------------------------------------------------------
hdr "Long-duration / low-byte sessions (C2 beaconing)" \
    "Loaders beacon on a fixed interval with tiny payloads"
if command -v zeek-cut >/dev/null; then
  zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes \
    < "$WORK/zeek/conn.log" | sort -k4 -nr | head -n 10
else
  echo "   (zeek-cut not installed - awk fallback)"
  awk -F'\t' '!/^#/ {printf "%-12s %-16s %-6s %10.1f %8s %8s\n",$3,$5,$6,$9,$10,$11}' \
    "$WORK/zeek/conn.log" | sort -k4 -nr | head -n 10
fi
note "3 sessions 10.0.0.5 -> 45.153.160.140:443, ~3600s each, <1KB = beacon"

# ---------------------------------------------------------------------
hdr "Anomalous SUID / SGID binaries" \
    "Privilege-escalation persistence often hides as a hidden SUID file"
find "$WORK" -type f -perm -04000 -exec ls -l {} + 2>/dev/null
note "opt/bin/.helper  (hidden, SUID root, shell copy)"

# ---------------------------------------------------------------------
hdr "Executables staged in memory-backed dirs" \
    "/dev/shm and /tmp are classic fileless staging spots"
find "$WORK/dev/shm" "$WORK/tmp" -type f -perm -111 2>/dev/null -exec ls -l {} +
note "dev/shm/.u  (executable downloader script)"

# ---------------------------------------------------------------------
hdr "Extract IOCs from the CTI report" \
    "Turn an unstructured bulletin into a machine-readable indicator set"
if command -v ioc-parser >/dev/null; then
  ioc-parser -f "$WORK/apt_report.txt" -o json
else
  echo "   (ioc-parser not installed - regex fallback)"
  echo "   IPv4:";   grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$WORK/apt_report.txt" | sort -u
  echo "   SHA256:"; grep -oE '\b[a-fA-F0-9]{64}\b' "$WORK/apt_report.txt" | sort -u
  echo "   MD5:";    grep -oiE '\b[a-f0-9]{32}\b' "$WORK/apt_report.txt" | sort -u
  echo "   Domains:";grep -oE '[a-z0-9.-]+\[\.\][a-z]{2,}' "$WORK/apt_report.txt" | sed 's/\[\.\]/./g' | sort -u
  echo "   CVEs:";   grep -oE 'CVE-[0-9]{4}-[0-9]{4,7}' "$WORK/apt_report.txt" | sort -u
fi
note "4 IPs, 2 domains, 1 MD5, 1 SHA256, 2 CVEs"

echo
echo "======================================================================"
echo " NEXT: enrich the extracted IOCs with live threat intel:"
echo "   vt ip 45.153.160.140"
echo "   python3 -c \"from OTXv2 import OTXv2; ...\"      # AlienVault OTX pulses"
echo "   pymisp search value=45.153.160.140              # your MISP instance"
echo " THEN: convert the confirmed pattern to a SIEM rule (Sigma) and ship it."
echo "======================================================================"
