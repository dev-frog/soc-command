# SOC Core Tools Setup & Command Guide (Kali Linux)
### Arkime, CyberChef, Elasticsearch SIEM, GVM, TheHive, Malcolm, Suricata, and Zeek

This comprehensive guide details the architecture, installation, configuration, operational CLI commands, and verification steps for 8 foundational SOC tools on **Kali Linux**.

---

## Table of Contents
1. [1. Arkime (Full Packet Capture & Traffic Indexing)](#1-arkime-full-packet-capture--traffic-indexing)
2. [2. CyberChef (The Cyber Swiss Army Knife)](#2-cyberchef-the-cyber-swiss-army-knife)
3. [3. Elasticsearch SIEM (Elastic Security Stack)](#3-elasticsearch-siem-elastic-security-stack)
4. [4. GVM (Greenbone Vulnerability Management / OpenVAS)](#4-gvm-greenbone-vulnerability-management--openvas)
5. [5. TheHive (Security Incident Response & Case Management)](#5-thehive-security-incident-response--case-management)
6. [6. Malcolm (CISA Network Traffic Analysis & Full SOC Suite)](#6-malcolm-cisa-network-traffic-analysis--full-soc-suite)
7. [7. Suricata (Signature-Based IDS/IPS Engine)](#7-suricata-signature-based-idsips-engine)
8. [8. Zeek (Network Security Monitoring & Protocol Analysis)](#8-zeek-network-security-monitoring--protocol-analysis)

---

## 1. Arkime (Full Packet Capture & Traffic Indexing)

**Role in SOC:** Large-scale, full packet capture (FPC), indexing, PCAP carving, and visual session inspection.

### Installation & Prerequisites (Kali Linux)
```bash
# 1. Install dependencies
sudo apt update && sudo apt install -y curl libpcap-dev libssl-dev libyaml-dev pkg-config

# 2. Download and install latest Arkime deb package
ARKIME_VER="5.1.0-1"
wget https://github.com/arkime/arkime/releases/download/v${ARKIME_VER}/arkime_${ARKIME_VER}.debian12_amd64.deb
sudo dpkg -i arkime_${ARKIME_VER}.debian12_amd64.deb
sudo apt-get install -f -y
```

### Initial Configuration & Initialization
```bash
# 1. Run interactive configuration script
# (Specify interface e.g. eth0, Elasticsearch URL e.g. http://localhost:9200)
sudo /opt/arkime/bin/Configure

# 2. Initialize Arkime database index in Elasticsearch / OpenSearch
sudo /opt/arkime/db/db.pl http://localhost:9200 init

# 3. Create Admin user for Web UI
sudo /opt/arkime/bin/arkime_add_user.sh admin "SOC Admin" "AdminPass123!" --admin
```

### Starting Services & Operations
```bash
# 1. Enable and start Arkime capture and viewer services
sudo systemctl enable --now arkimecapture
sudo systemctl enable --now arkimeviewer

# 2. Verify service status
sudo systemctl status arkimecapture arkimeviewer

# 3. Import existing PCAP files for indexing and visualization
sudo /opt/arkime/bin/arkime-capture -r /tmp/suspicious_traffic.pcap -t "malware_triage,incident_101"

# Web UI Access:
# URL: https://localhost:8653 (or http://localhost:8005 depending on config)
# Credentials: admin / AdminPass123!
```

---

## 2. CyberChef (The Cyber Swiss Army Knife)

**Role in SOC:** Essential Swiss Army knife for deobfuscating commands, decoding payloads (Base64, Hex, XOR, Gzip), parsing timestamps, and regex extraction.

### Option A: Run via Docker (Recommended for Web UI)
```bash
sudo apt install -y docker.io
sudo systemctl enable --now docker

# Pull and run official CyberChef container
docker run -d --name cyberchef -p 8080:8000 ghcr.io/gchq/cyberchef:latest

# Access Web UI in browser:
# http://localhost:8080
```

### Option B: CyberChef CLI for Terminal Automation
```bash
# Install Node.js & CyberChef CLI
sudo apt install -y nodejs npm
sudo npm install -g cyberchef-cli

# Example 1: Decode Base64 string from PowerShell telemetry
cyberchef-cli --recipe "From_Base64('A-Za-z0-9+/=',true,false)" --input "SUV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp"

# Example 2: Deobfuscate Hex and XOR payload
cyberchef-cli --recipe "From_Hex('Auto') XOR({'option':'Hex','string':'5A'},'Standard',false)" --input "1f 0e 06 06 15"

# Example 3: Extract URLs and IP addresses from phishing body text
cat /tmp/phishing_email.eml | cyberchef-cli --recipe "Extract_IP_addresses(true,false) Extract_URLs(true,false)"
```

---

## 3. Elasticsearch SIEM (Elastic Security Stack)

**Role in SOC:** Centralized SIEM repository, correlation engine, detection rule repository, and Kibana Security Dashboard.

### Installation & Repository Setup
```bash
# 1. Add Elastic official GPG key and APT repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# 2. Install Elasticsearch and Kibana
sudo apt update && sudo apt install -y elasticsearch kibana
```

### Service Activation & Verification
```bash
# 1. Enable and start Elasticsearch
sudo systemctl enable --now elasticsearch

# 2. Reset and capture default 'elastic' superuser password
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic

# 3. Generate enrollment token for Kibana
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

# 4. Enable and start Kibana
sudo systemctl enable --now kibana

# 5. Verify Elasticsearch Cluster Health
curl -k -u elastic:YOUR_PASSWORD https://localhost:9200/_cluster/health?pretty
```

### Shippers & Detection Engineering
```bash
# 1. Install Filebeat (log shipper for Suricata / System logs)
sudo apt install -y filebeat
sudo filebeat modules enable system suricata
sudo filebeat setup -e
sudo systemctl start filebeat

# 2. CLI EQL Detection Query against SIEM indices
curl -k -u elastic:YOUR_PASSWORD -X GET "https://localhost:9200/logs-*/_eql/search?pretty" \
  -H 'Content-Type: application/json' -d '{
  "query": "process where process.name == \"bash\" and process.args : \"-c\""
}'

# Web UI Access:
# URL: https://localhost:5601
# Security App: https://localhost:5601/app/security
```

---

## 4. GVM (Greenbone Vulnerability Management / OpenVAS)

**Role in SOC:** Enterprise-grade vulnerability assessment, CVE discovery, host compliance, and security posture scanning.

### Installation & Setup on Kali Linux
```bash
# 1. Install GVM package from Kali repositories
sudo apt update && sudo apt install -y gvm

# 2. Run automated setup (Downloads NVTs, CVEs, SCAP data, configures PostgreSQL)
# Note: This takes 10-25 minutes to synchronize feeds.
sudo gvm-setup

# 3. Check and verify setup integrity
sudo gvm-check-setup
```

### Operations & Maintenance
```bash
# 1. Start GVM services
sudo gvm-start

# 2. Set/Reset admin user password
sudo gvmd --user=admin --new-password="SecureGVMAdmin2026!"

# 3. Update Vulnerability Feeds (Manual sync)
sudo greenbone-feed-sync --type GVMD_DATA
sudo greenbone-feed-sync --type SCAP
sudo greenbone-feed-sync --type CERT

# 4. Check GVM service status
sudo gvmd --get-users
sudo systemctl status ospd-openvas gvmd notus-scanner

# 5. Stop GVM services when not in use to conserve RAM
sudo gvm-stop

# Web UI Access:
# URL: https://127.0.0.1:9392
# Credentials: admin / SecureGVMAdmin2026!
```

---

## 5. TheHive (Security Incident Response & Case Management)

**Role in SOC:** Centralized incident triage, case management, task assignment, observable tracking, and Cortex analyzer orchestration.

### Quick Docker Deployment (TheHive 5 Stack)
```bash
# 1. Create project directory
mkdir -p /opt/thehive-stack && cd /opt/thehive-stack

# 2. Create Docker Compose file
cat << 'EOF' > docker-compose.yml
version: "3"
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    container_name: thehive-es
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    volumes:
      - es_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"

  minio:
    image: minio/minio:latest
    container_name: thehive-minio
    command: server /data --console-address ":9001"
    environment:
      - MINIO_ROOT_USER=minioadmin
      - MINIO_ROOT_PASSWORD=minioadmin
    volumes:
      - minio_data:/data
    ports:
      - "9002:9000"
      - "9001:9001"

  thehive:
    image: thehiveproject/thehive:5.2
    container_name: thehive
    depends_on:
      - elasticsearch
      - minio
    ports:
      - "9000:9000"
    environment:
      - THEHIVE_SECRET=SuperSecretKeyForSessionEncryption123456789!
    volumes:
      - thehive_data:/etc/thehive/application.conf

volumes:
  es_data:
  minio_data:
  thehive_data:
EOF

# 3. Launch TheHive stack
docker-compose up -d

# 4. Verify containers are running
docker ps | grep -E 'thehive|elasticsearch|minio'

# Web UI Access:
# URL: http://localhost:9000
# Default Login: admin@thehive.local / secret
```

### CLI API Case Creation (Python / Curl)
```bash
# Create an incident case via TheHive API
curl -X POST "http://localhost:9000/api/v1/case" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious C2 Beaconing Detected",
    "description": "Host 192.168.1.50 communicating with external IP 185.220.101.5",
    "severity": 3,
    "tags": ["T1071", "Malware", "C2"]
  }'
```

---

## 6. Malcolm (CISA Network Traffic Analysis & Full SOC Suite)

**Role in SOC:** CISA & INL's premier all-in-one open-source network traffic analysis framework. Malcolm seamlessly combines **Zeek**, **Suricata**, **Arkime**, **OpenSearch Dashboards**, **Logstash**, **NetBox**, and **CyberChef** into a pre-configured Docker ecosystem.

### Prerequisites & Installation
```bash
# 1. Install prerequisites (Docker, Docker Compose, Git)
sudo apt update && sudo apt install -y docker.io docker-compose git python3 python3-pip

# 2. Increase virtual memory limits (required for OpenSearch/Elasticsearch)
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# 3. Clone Malcolm repository
git clone https://github.com/cisagov/Malcolm.git /opt/Malcolm
cd /opt/Malcolm
```

### Configuration & Startup
```bash
# 1. Run interactive configuration script
# (Guides through enabling Zeek, Suricata, Arkime, and setting passwords)
./scripts/configure

# 2. Start Malcolm stack
./scripts/start

# 3. Check status of all running Malcolm containers
./scripts/status
```

### Ingesting Traffic & Operations
```bash
# Option 1: Upload a PCAP for instant multi-tool analysis (Zeek + Suricata + Arkime)
./scripts/pcap-capture -r /tmp/malware_capture.pcap

# Option 2: Drop PCAP files into the automated watch directory
cp /tmp/sample.pcap /opt/Malcolm/pcap/

# Stopping Malcolm:
./scripts/stop

# Web UI Access:
# URL: https://localhost (Unified Malcolm Portal)
# Integrated tools available:
#  - OpenSearch Dashboards (SIEM visual analytics)
#  - Arkime (Full Packet Search & Sessions)
#  - CyberChef (Embedded)
#  - NetBox (Asset Inventory)
```

---

## 7. Suricata (Signature-Based IDS/IPS Engine)

**Role in SOC:** High-performance, multi-threaded signature-based Network Intrusion Detection/Prevention (IDS/IPS) engine.

### Installation & Configuration
```bash
# 1. Install Suricata and JQ
sudo apt update && sudo apt install -y suricata jq

# 2. Update threat rulesets (Emerging Threats Open)
sudo suricata-update

# 3. List and enable additional rule sources
sudo suricata-update list-sources
sudo suricata-update enable-source et/open
sudo suricata-update enable-source tgreen/hunting
sudo suricata-update

# 4. Test configuration syntax
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

### Running Modes & Alert Monitoring
```bash
# 1. Live Detection Mode on interface eth0 (Background daemon)
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D

# 2. Offline PCAP Inspection Mode
sudo suricata -r /tmp/suspicious.pcap -l /tmp/suricata_output/

# 3. Live Alert Stream Inspection with JQ
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | {
  timestamp: .timestamp,
  src: "\(.src_ip):\(.src_port)",
  dst: "\(.dest_ip):\(.dest_port)",
  sig_id: .alert.signature_id,
  signature: .alert.signature,
  category: .alert.category
}'

# 4. Top Triggered Signatures Analysis
cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .alert.signature' | sort | uniq -c | sort -rn | head -n 10
```

---

## 8. Zeek (Network Security Monitoring & Protocol Analysis)

**Role in SOC:** Behavioral network analysis, protocol parsing (DNS, HTTP, TLS, SSH, SMB), and rich transaction logging without payload bloat.

### Installation & Configuration
```bash
# 1. Install Zeek from Kali repositories
sudo apt update && sudo apt install -y zeek zeek-aux zeek-core

# 2. Configure network interface in node.cfg
# Edit /etc/zeek/node.cfg (or /opt/zeek/etc/node.cfg):
# interface=eth0
```

### ZeekControl Management (Production / Continuous Mode)
```bash
# 1. Check configuration syntax
sudo /opt/zeek/bin/zeekctl check || sudo zeekctl check

# 2. Deploy Zeek monitoring engine
sudo zeekctl deploy

# 3. Check live capture status
sudo zeekctl status

# 4. Stop Zeek engine
sudo zeekctl stop
```

### Standalone CLI Execution & Log Hunting (`zeek-cut`)
```bash
# 1. Analyze a PCAP file in a dedicated analysis directory
mkdir -p /tmp/zeek_analysis && cd /tmp/zeek_analysis
zeek -r /tmp/traffic.pcap local

# 2. Query Connection logs (conn.log)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service orig_bytes resp_bytes

# 3. Query DNS lookups and queries (dns.log)
cat dns.log | zeek-cut id.orig_h query answers rcode_name | head -n 25

# 4. Query HTTP requests, URIs, and User-Agents (http.log)
cat http.log | zeek-cut id.orig_h host uri user_agent status_code

# 5. Query SSL/TLS Server Names & Certificate Validation (ssl.log)
cat ssl.log | zeek-cut id.orig_h id.resp_h server_name validation_status

# 6. Query JA3 / JA3S TLS Fingerprints (for C2 client profiling)
cat ssl.log | zeek-cut id.orig_h server_name ja3 | sort -u
```

---

## Summary of Default Ports & Access Points

| Tool | Default Protocol / Port | Default Interface / URL | Default Credentials / Note |
|---|---|---|---|
| **Arkime** | HTTPS `8653` / HTTP `8005` | `https://localhost:8653` | Created via `arkime_add_user.sh` |
| **CyberChef** | HTTP `8080` / `8000` | `http://localhost:8080` | No auth / Web application |
| **Elasticsearch** | HTTPS `9200` | `https://localhost:9200` | `elastic` / generated at init |
| **Kibana (SIEM)** | HTTPS `5601` | `https://localhost:5601` | `elastic` / password |
| **GVM (OpenVAS)** | HTTPS `9392` | `https://127.0.0.1:9392` | `admin` / set via `gvmd` |
| **TheHive** | HTTP `9000` | `http://localhost:9000` | `admin@thehive.local` / `secret` |
| **Malcolm** | HTTPS `443` | `https://localhost` | Set during `./scripts/configure` |
| **Suricata** | Unix Socket / JSON log | `/var/log/suricata/eve.json` | CLI / Daemon |
| **Zeek** | CLI Logs / ZeekControl | Directory containing `.log` files | CLI / `zeek-cut` |

---
*Reference documentation compiled for Kali Linux SOC Tooling and Analysis.*
