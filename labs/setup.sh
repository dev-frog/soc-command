#!/bin/bash
# SOC Network Monitoring Stack — Setup Script (Kali Linux)
#
# Usage:
#   ./setup.sh          full first-time setup + start
#   ./setup.sh start    start an already-set-up stack
#   ./setup.sh stop     stop the stack (keeps containers/volumes, quick to resume)
set -e

docker_compose() {
  if docker info &>/dev/null; then
    docker compose "$@"
  else
    sudo docker compose "$@"
  fi
}

cmd="${1:-setup}"

case "$cmd" in
start)
  echo "[*] Starting stack..."
  docker_compose start
  echo "[*] Started. Kibana -> http://localhost:5601  |  ntopng -> http://localhost:3000"
  exit 0
  ;;
stop)
  echo "[*] Stopping stack..."
  docker_compose stop
  echo "[*] Stopped. Run './setup.sh start' to resume."
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

echo "[*] Setting kernel param for Elasticsearch (vm.max_map_count)..."
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf >/dev/null

echo "[*] Detecting active network interface..."
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "INTERFACE=${IFACE}" >.env
echo "[*] Using interface: ${IFACE} (edit .env to change)"

echo "[*] Downloading base Suricata rules (ET Open)..."
docker run --rm -v "$(pwd)/suricata/rules:/rules" jasonish/suricata:latest \
  suricata-update --output /rules -f || echo "Rules will auto-fetch on first container start."

echo "[*] Bringing up the stack..."
docker_compose up -d

echo ""
echo "=================================================="
echo " Stack is starting. Access points once healthy:"
echo "   Kibana  -> http://localhost:5601"
echo "   ntopng  -> http://localhost:3000  (admin/admin)"
echo "   ES API  -> http://localhost:9200"
echo " Suricata alerts: ./suricata/logs/eve.json"
echo " Zeek logs:       ./zeek/logs/"
echo ""
echo " Later: ./setup.sh stop   /   ./setup.sh start"
echo "=================================================="
