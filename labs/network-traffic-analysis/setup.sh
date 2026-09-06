#!/bin/bash
# =====================================================================
# Network Traffic Analysis module :: pcap (re)builder
# Makes a local venv, installs scapy, regenerates pcaps/ deterministically.
# The committed pcaps are already usable - you only need this to rebuild
# them or to tweak generate_pcaps.py.
# =====================================================================
#   ./setup.sh            build/refresh pcaps
#   ./setup.sh clean       remove the venv (keeps pcaps)
# =====================================================================
set -e
cd "$(dirname "$0")"
VENV=".venv"

if [ "$1" = "clean" ]; then
  rm -rf "$VENV"
  echo "[*] removed $VENV"
  exit 0
fi

if ! command -v python3 >/dev/null; then
  echo "python3 is required" >&2; exit 1
fi

if [ ! -d "$VENV" ]; then
  echo "[*] creating venv at $VENV"
  python3 -m venv "$VENV"
fi

echo "[*] installing scapy"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet scapy

echo "[*] generating pcaps"
"$VENV/bin/python" tools/generate_pcaps.py pcaps

echo
echo "[+] done. Files:"
ls -la pcaps/*.pcap
echo
echo "[>] open pcaps/net-basics.pcap in Wireshark and start with 01-network-traffic-basics.md"
echo "[>] NetworkMiner (room 5): https://www.netresec.com/?page=NetworkMiner"
