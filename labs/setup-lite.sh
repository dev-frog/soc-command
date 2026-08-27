#!/bin/bash
# SOC Network Monitoring Stack — LITE Setup Script (Kali Linux, <2GB RAM VMs)
# Suricata + Zeek + ntopng only. No Elasticsearch/Kibana, so no JVM/vm.max_map_count step needed.
#
# Usage:
#   ./setup-lite.sh          full first-time setup + start
#   ./setup-lite.sh start    start an already-set-up stack
#   ./setup-lite.sh stop     stop the stack (keeps containers/volumes, quick to resume)
set -e

COMPOSE_FILE="docker-compose.lite.yml"

docker_compose() {
  if docker info &>/dev/null; then
    docker compose -f "$COMPOSE_FILE" "$@"
  else
    sudo docker compose -f "$COMPOSE_FILE" "$@"
  fi
}

cmd="${1:-setup}"

case "$cmd" in
start)
  echo "[*] Starting lite stack..."
  docker_compose start
  echo "[*] Started. ntopng -> http://localhost:3000"
  exit 0
  ;;
stop)
  echo "[*] Stopping lite stack..."
  docker_compose stop
  echo "[*] Stopped. Run './setup-lite.sh start' to resume."
  exit 0
  ;;
setup) ;;
*)
  echo "Usage: $0 [setup|start|stop]"
  exit 1
  ;;
esac

echo "[*] Checking Docker install..."
if ! command -v docker &>/dev/null; then
  echo "[*] Installing Docker..."
  sudo apt update
  sudo apt install -y docker.io docker-compose-plugin
  sudo systemctl enable --now docker
fi

echo "[*] Creating log/rule directories..."
mkdir -p suricata/rules suricata/logs zeek/logs

echo "[*] Detecting active network interface..."
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "INTERFACE=${IFACE}" >.env
echo "[*] Using interface: ${IFACE} (edit .env to change)"

echo "[*] Downloading base Suricata rules (ET Open)..."
docker run --rm -v "$(pwd)/suricata/rules:/rules" jasonish/suricata:latest \
  suricata-update --output /rules -f || echo "Rules will auto-fetch on first container start."

echo "[*] Bringing up the lite stack..."
docker_compose up -d

echo ""
echo "=================================================="
echo " Lite stack is starting. Access points once healthy:"
echo "   ntopng  -> http://localhost:3000  (admin/admin)"
echo " Suricata alerts: tail -f suricata/logs/eve.json | jq ."
echo " Zeek logs:       zeek-cut < zeek/logs/current/conn.log"
echo ""
echo " Later: ./setup-lite.sh stop   /   ./setup-lite.sh start"
echo "=================================================="
echo ""
echo "NOTE: in VirtualBox, set this VM's network adapter to 'Bridged Adapter'"
echo "(not NAT) or these tools will only ever see the VM's own loopback-ish traffic."
