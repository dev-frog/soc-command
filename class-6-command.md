# Module 06: SIEM Architecture, Use Cases, Detection Engineering & Alert Tuning
### Complete Step-by-Step Instructor & Classroom Lab Guide (Kali Linux)

This guide provides an exhaustive, step-by-step demonstration walkthrough for the 20 core tools of **Module 06**. Each tool includes installation steps, configuration files with copy-pasteable examples, live execution commands, expected outputs, and alert-tuning best practices designed for live classroom presentations on **Kali Linux**.

---

## Table of Contents
- [Pillar A: SIEM Core Platforms (Architecture & Ingestion Layer)](#pillar-a-siem-core-platforms-architecture--ingestion-layer)
  - [1. Wazuh Manager + Indexer + Dashboard](#1-wazuh-manager--indexer--dashboard)
  - [2. Elastic Stack (Elasticsearch, Logstash, Kibana)](#2-elastic-stack-elasticsearch-logstash-kibana)
  - [3. Graylog (Stream-Based SIEM Architecture)](#3-graylog-stream-based-siem-architecture)
  - [4. Logstash (Standalone Ingestion & Normalization Pipeline)](#4-logstash-standalone-ingestion--normalization-pipeline)
- [Pillar B: Log Shipping & Normalization (SIEM Feeds)](#pillar-b-log-shipping--normalization-siem-feeds)
  - [5. Filebeat (Modular Ingestion for Suricata & Syslog)](#5-filebeat-modular-ingestion-for-suricata--syslog)
  - [6. rsyslog (Centralized Remote Syslog Relay Forwarder)](#6-rsyslog-centralized-remote-syslog-relay-forwarder)
  - [7. syslog-ng (Advanced Parsing, Filtering & Log Normalization)](#7-syslog-ng-advanced-parsing-filtering--log-normalization)
  - [8. NXLog CE (Cross-Platform JSON Log Collector)](#8-nxlog-ce-cross-platform-json-log-collector)
- [Pillar C: Detection Engineering (Writing & Managing Use Cases)](#pillar-c-detection-engineering-writing--managing-use-cases)
  - [9. Sigma & sigma-cli (Portable Detection Rule Engineering)](#9-sigma--sigma-cli-portable-detection-rule-engineering)
  - [10. YARA (Filesystem & Memory Pattern Matching)](#10-yara-filesystem--memory-pattern-matching)
  - [11. Elastic Detection Rules CLI (MITRE ATT&CK Rule Validation)](#11-elastic-detection-rules-cli-mitre-attck-rule-validation)
  - [12. Uncoder.IO / uncoder-core (Cross-SIEM Query Translation)](#12-uncoderio--uncoder-core-cross-siem-query-translation)
  - [13. Chainsaw (Sigma-Powered Windows EVTX Hunting)](#13-chainsaw-sigma-powered-windows-evtx-hunting)
- [Pillar D: Use Case Testing & Detection Validation](#pillar-d-use-case-testing--detection-validation)
  - [14. Atomic Red Team (Discrete ATT&CK Telemetry Generation)](#14-atomic-red-team-discrete-attck-telemetry-generation)
  - [15. CALDERA (Adversary Emulation & Multi-Stage Attack Chains)](#15-caldera-adversary-emulation--multi-stage-attack-chains)
  - [16. DetectionLab (Automated SIEM Testing Harness)](#16-detectionlab-automated-siem-testing-harness)
- [Pillar E: Alert Tuning & False-Positive Reduction](#pillar-e-alert-tuning--false-positive-reduction)
  - [17. `jq` (Deep Alert Slicing & Noise Frequency Profiling)](#17-jq-deep-alert-slicing--noise-frequency-profiling)
  - [18. Wazuh Ruleset Test (`wazuh-logtest` Live Debugger)](#18-wazuh-ruleset-test-wazuh-logtest-live-debugger)
  - [19. ElastAlert2 (Thresholds, Frequency & Alert Suppression)](#19-elastalert2-thresholds-frequency--alert-suppression)
  - [20. Suricata Engine Analysis & Rule Profiling](#20-suricata-engine-analysis--rule-profiling)

---

# Pillar A: SIEM Core Platforms (Architecture & Ingestion Layer)

---

## 1. Wazuh Manager + Indexer + Dashboard

### Concept in SOC
Wazuh is an all-in-one open-source SIEM/XDR platform. It aggregates host-level telemetry (file changes, authentication, process execution), normalizes events via an internal decoder pipeline, matches events against XML-based detection rules, and stores structured alerts in an OpenSearch-based indexer.

```
+----------------+      +-------------------+      +------------------+      +-------------------+
|  Wazuh Agent   | ---> |   Wazuh Manager   | ---> |  Wazuh Indexer   | ---> |  Wazuh Dashboard  |
| (Host Logs/FIM)|      | (Decoder/Rules)   |      | (OpenSearch DB)  |      |   (Web UI: 443)   |
+----------------+      +-------------------+      +------------------+      +-------------------+
```

### Step 1: Automated Single-Node Installation on Kali Linux
```bash
# Download the official Wazuh installation script
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh

# Run all-in-one installation in unattended mode (-a flag)
sudo bash wazuh-install.sh -a
```
> **Note:** The script will output the default `admin` password and save credentials to `wazuh-passwords.txt`.

### Step 2: Verify Architecture & Component Status
```bash
# Check all three SIEM layers (Manager, Indexer, Dashboard)
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard

# Check operational engine state via Wazuh CLI controller
sudo /var/ossec/bin/wazuh-control status
```

### Step 3: Class Demonstration — Check Active Agents & Live Alert Stream
```bash
# List all registered endpoint agents
sudo /var/ossec/bin/agent_control -l

# View live SIEM alerts in JSON stream format
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq '{timestamp: .timestamp, rule_id: .rule.id, level: .rule.level, desc: .rule.description}'
```

### Expected Output
```json
{
  "timestamp": "2026-08-16T19:30:15.123+0000",
  "rule_id": "5710",
  "level": 5,
  "desc": "sshd: Attempt to login using a non-existent user"
}
```

---

## 2. Elastic Stack (Elasticsearch, Logstash, Kibana)

### Concept in SOC
The Elastic Stack represents the industry-standard modular SIEM tier:
- **Ingestion Tier:** Logstash / Beats / Elastic Agent
- **Storage & Indexing Tier:** Elasticsearch (clustered JSON document store)
- **Analytics & Detection Tier:** Kibana Security App (EQL, ES|QL, Detection Rules)

### Step 1: Add Official Elastic Repository & Install
```bash
# Add Elastic official GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg

# Add Elastic 8.x repository
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Update & install stack
sudo apt update && sudo apt install -y elasticsearch kibana logstash
```

### Step 2: Start Services & Generate Passwords
```bash
# Enable and start Elasticsearch
sudo systemctl enable --now elasticsearch

# Reset default 'elastic' superuser password
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i

# Generate Kibana enrollment token
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana

# Enable and start Kibana
sudo systemctl enable --now kibana
```

### Step 3: Class Demonstration — Test Cluster Health via REST API
```bash
# Query cluster health (shows green/yellow status, nodes count, and shards)
curl -k -u elastic:YOUR_PASSWORD https://localhost:9200/_cluster/health?pretty

# Query SIEM security indices
curl -k -u elastic:YOUR_PASSWORD https://localhost:9200/_cat/indices/.alerts*?v
```

### Expected Output
```text
{
  "cluster_name" : "elasticsearch",
  "status" : "green",
  "number_of_nodes" : 1,
  "active_primary_shards" : 18,
  "active_shards" : 18
}
```

---

## 3. Graylog (Stream-Based SIEM Architecture)

### Concept in SOC
Graylog routes logs through real-time **Streams** and **Processing Pipelines**. Instead of running heavy batch queries, Graylog evaluates rule conditions as events flow into memory, triggering instant alerts before indexing to disk.

### Step 1: Deploy Graylog 3-Tier Stack via Docker Compose
```bash
# Install Docker prerequisites
sudo apt install -y docker.io docker-compose
sudo systemctl enable --now docker

# Create deployment directory
mkdir -p /opt/graylog-lab && cd /opt/graylog-lab

# Write Docker Compose file
cat << 'EOF' > docker-compose.yml
version: '3'
services:
  mongodb:
    image: mongo:5.0
    container_name: graylog-mongo
    volumes:
      - mongo_data:/data/db

  opensearch:
    image: opensearchproject/opensearch:2.11.0
    container_name: graylog-opensearch
    environment:
      - discovery.type=single-node
      - plugins.security.disabled=true
      - "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m"
    volumes:
      - os_data:/usr/share/opensearch/data

  graylog:
    image: graylog/graylog:5.2
    container_name: graylog-server
    depends_on: [mongodb, opensearch]
    environment:
      - GRAYLOG_PASSWORD_SECRET=somepasswordpeppersecret1234567890
      - GRAYLOG_ROOT_PASSWORD_SHA2=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 # admin
      - GRAYLOG_HTTP_BIND_ADDRESS=0.0.0.0:9000
    ports:
      - "9000:9000"
      - "1514:1514/udp"
    volumes:
      - graylog_data:/usr/share/graylog/data

volumes:
  mongo_data:
  os_data:
  graylog_data:
EOF

# Start stack in background
docker-compose up -d
```

### Step 2: Class Demonstration — Ingest Test Syslog Message into Graylog
```bash
# Send test syslog packet to Graylog UDP input on port 1514
echo "<14>1 $(date -u +%Y-%m-%dT%H:%M:%SZ) kali-soc auth - - - SSH login brute-force attack detected from 198.51.100.23" | nc -u -w1 127.0.0.1 1514

# Query Graylog System Inputs API
curl -u admin:admin http://localhost:9000/api/system/inputs
```

---

## 4. Logstash (Standalone Ingestion & Normalization Pipeline)

### Concept in SOC
Logstash operates as the Extract, Transform, Load (ETL) pipeline of a SIEM:
- `input`: Ingests from Syslog, Beats, Kafka, or raw files.
- `filter`: Uses Grok and Mutate to parse unformatted log strings into structured ECS (Elastic Common Schema) JSON fields.
- `output`: Routes normalized events to Elasticsearch, cold-storage disk archives, and alerting webhooks.

### Step 1: Create a Structured Parsing Pipeline
```bash
sudo mkdir -p /etc/logstash/conf.d

cat << 'EOF' | sudo tee /etc/logstash/conf.d/soc-pipeline.conf
input {
  stdin { }
}

filter {
  grok {
    match => { "message" => "%{SYSLOGTIMESTAMP:log_time} %{HOSTNAME:src_host} %{WORD:program}: %{GREEDYDATA:log_payload}" }
  }
  mutate {
    add_field => { "soc_tier" => "Tier-1-Triage" }
  }
}

output {
  stdout { codec => rubydebug }
}
EOF
```

### Step 2: Class Demonstration — Test Pipeline Interactively
```bash
# Run Logstash in CLI interactive test mode
sudo /usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/soc-pipeline.conf
```
*Type the following log line into the terminal:*
```text
Aug 16 19:35:01 sensor-node-01 sudo: pam_unix(sudo:auth): authentication failure; logname= user=root
```

### Expected Output
```ruby
{
      "@timestamp" => 2026-08-16T19:35:01.000Z,
        "src_host" => "sensor-node-01",
         "program" => "sudo",
        "log_time" => "Aug 16 19:35:01",
     "log_payload" => "pam_unix(sudo:auth): authentication failure; logname= user=root",
        "soc_tier" => "Tier-1-Triage"
}
```

---

# Pillar B: Log Shipping & Normalization (SIEM Feeds)

---

## 5. Filebeat (Modular Ingestion for Suricata & Syslog)

### Concept in SOC
Filebeat is a lightweight agent installed on endpoints and network appliances. Its pre-built **modules** contain out-of-the-box Grok patterns and Elasticsearch index templates for standard log sources (Suricata, Zeek, Nginx, Linux System).

### Step 1: Install & Enable Modules
```bash
sudo apt install -y filebeat

# List all available detection modules
sudo filebeat modules list

# Enable system authentication logs and Suricata IDS modules
sudo filebeat modules enable system suricata
```

### Step 2: Configure Suricata EVE.json Log Path
```bash
sudo nano /etc/filebeat/modules.d/suricata.yml
```
*Ensure the file contents point to Suricata's alert log:*
```yaml
- module: suricata
  eve:
    enabled: true
    var.paths: ["/var/log/suricata/eve.json"]
```

### Step 3: Class Demonstration — Test Configuration & Stream Logs
```bash
# Test Filebeat configuration and output connectivity
sudo filebeat test config
sudo filebeat test output

# Run Filebeat in foreground debug mode to display parsed events
sudo filebeat -e -d "publish"
```

---

## 6. rsyslog (Centralized Remote Syslog Relay Forwarder)

### Concept in SOC
`rsyslog` is the standard Linux syslog daemon. In enterprise SOC architectures, it is configured as a **log collector relay** to aggregate syslog from network firewalls, switches, and Linux servers over UDP/TCP port 514, before forwarding encrypted batches to the SIEM.

### Step 1: Configure rsyslog as a Central Ingestion Listener
```bash
sudo nano /etc/rsyslog.d/10-soc-collector.conf
```
*Add the following configuration:*
```text
# Provide UDP syslog reception
module(load="imudp")
input(type="imudp" port="514")

# Provide TCP syslog reception
module(load="imtcp")
input(type="imtcp" port="514")

# Store incoming remote host logs in dedicated directories
$template RemoteHostLogs,"/var/log/remote_hosts/%HOSTNAME%/%PROGRAMNAME%.log"
*.* ?RemoteHostLogs
```

### Step 2: Class Demonstration — Restart Service & Inject Test Syslog
```bash
# Restart rsyslog service
sudo systemctl restart rsyslog

# Verify rsyslog is listening on UDP and TCP port 514
sudo ss -tulpn | grep 514

# Inject a test message using logger utility
logger -n 127.0.0.1 -P 514 -p auth.warning "TEST_AUTH_ALERT: Unauthorized root login attempt from 10.0.0.99"

# Inspect the captured log file
cat /var/log/remote_hosts/kali/logger.log
```

---

## 7. syslog-ng (Advanced Parsing, Filtering & Log Normalization)

### Concept in SOC
`syslog-ng` provides granular message routing, regex-based message filtering, and direct JSON parsing at the transport layer before writing logs to SIEM storage.

### Step 1: Install & Define Filters
```bash
sudo apt install -y syslog-ng

# Create a custom security filter configuration
cat << 'EOF' | sudo tee /etc/syslog-ng/conf.d/security-filters.conf
source s_local {
    system();
    internal();
};

filter f_auth_failures {
    message("Failed password") or message("authentication failure");
};

destination d_security_alerts {
    file("/var/log/security_incidents.log");
};

log {
    source(s_local);
    filter(f_auth_failures);
    destination(d_security_alerts);
};
EOF
```

### Step 2: Class Demonstration — Validate Syntax & Test Filter
```bash
# Check syntax of syslog-ng configuration (-s flag)
sudo syslog-ng -s

# Restart syslog-ng
sudo systemctl restart syslog-ng

# Trigger an authentication failure log to test filter
logger -p auth.err "sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 44322 ssh2"

# Verify that ONLY the security failure was routed to the incident log
cat /var/log/security_incidents.log
```

---

## 8. NXLog CE (Cross-Platform JSON Log Collector)

### Concept in SOC
NXLog Community Edition is a cross-platform log shipper widely used in hybrid SOC environments to normalize Windows Event Logs (EVTX) into structured JSON before shipping to Linux SIEM servers.

### Step 1: Install NXLog on Kali Linux
```bash
wget https://nxlog.co/downloads/nxlog-ce/nxlog-ce_3-x_ubuntu-noble_amd64.deb
sudo dpkg -i nxlog-ce_3-x_ubuntu-noble_amd64.deb || sudo apt-get install -f -y
```

### Step 2: Configure JSON Log Conversion Pipeline
```bash
cat << 'EOF' | sudo tee /etc/nxlog/nxlog.conf
User nxlog
Group nxlog

<Extension _json>
    Module xm_json
</Extension>

<Input in_syslog>
    Module im_file
    File "/var/log/auth.log"
    SavePos TRUE
</Input>

<Output out_json>
    Module om_file
    File "/var/log/auth_normalized.json"
    Exec to_json();
</Output>

<Route 1>
    Path in_syslog => out_json
</Route>
EOF
```

### Step 3: Class Demonstration — Run in Foreground Debug Mode
```bash
# Run NXLog in foreground mode (-f flag) to demonstrate live JSON conversion
sudo nxlog -f
```

---

# Pillar C: Detection Engineering (Writing & Managing Use Cases)

---

## 9. Sigma & sigma-cli (Portable Detection Rule Engineering)

### Concept in SOC
Sigma is the "YARA for log events" — a vendor-agnostic specification for writing detection rules. A detection engineer writes a detection use case once in YAML and uses `sigma-cli` to compile it to Splunk SPL, Elastic EQL, Microsoft Sentinel KQL, or QRadar AQL.

```
+--------------------------+
|  Sigma YAML Rule (Use Case)|
+--------------------------+
             |
      [ sigma-cli ]
             |
             +---> Elasticsearch Lucene / EQL
             +---> Splunk SPL
             +---> Microsoft Sentinel KQL
             +---> Wazuh XML
```

### Step 1: Install Sigma CLI & Rule Repository
```bash
pip install sigma-cli --break-system-packages
git clone https://github.com/SigmaHQ/sigma.git /tmp/sigma
```

### Step 2: Create a Custom Detection Use Case (YAML)
```bash
cat << 'EOF' > /tmp/proc_suspicious_curl.yml
title: Suspicious Curl Pipe to Shell Execution
id: 5f83b2a2-8b45-4c28-bb71-123456789abc
status: experimental
description: Detects command-line execution where curl downloads a script and immediately pipes it into bash or sh.
author: SOC Detection Engineering Team
references:
    - https://attack.mitre.org/techniques/T1059/004/
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - 'curl'
            - '|'
            - 'bash'
    condition: selection
falsepositives:
    - Legitimate software installers (e.g. Homebrew, Rustup)
level: high
tags:
    - attack.execution
    - attack.t1059.004
EOF
```

### Step 3: Class Demonstration — Convert Rule to Multiple SIEM Query Languages
```bash
# 1. Convert to Elasticsearch Query DSL (Lucene)
sigma convert -t elasticsearch-lucene -p ecs_windows /tmp/proc_suspicious_curl.yml

# 2. Convert to Splunk SPL Query
sigma convert -t splunk /tmp/proc_suspicious_curl.yml

# 3. Convert to Elasticsearch Event Query Language (EQL)
sigma convert -t elasticsearch-eql /tmp/proc_suspicious_curl.yml
```

### Expected Output
```text
(CommandLine:*curl* AND CommandLine:*|* AND CommandLine:*bash*)
```

---

## 10. YARA (Filesystem & Memory Pattern Matching)

### Concept in SOC
YARA identifies and classifies malware samples, web shells, and in-memory payloads based on textual or binary patterns. In SOC operations, YARA rules are integrated into SIEM alerts, EDR file inspection engines, and forensic triage workflows.

### Step 1: Write a Production-Grade Web Shell Detection Rule
```bash
cat << 'EOF' > /tmp/webshell_rules.yar
rule Generic_PHP_WebShell_Detection {
    meta:
        author = "SOC Detection Team"
        description = "Detects obfuscated PHP web shells and command execution backdoors"
        mitre_technique = "T1505.003"
    strings:
        $b64 = "base64_decode" nocase
        $eval = "eval(" nocase
        $sys1 = "system($_GET[" nocase
        $sys2 = "passthru($_POST[" nocase
        $cmd = "shell_exec(" nocase
    condition:
        ($eval and $b64) or $sys1 or $sys2 or $cmd
}
EOF
```

### Step 2: Class Demonstration — Create a Test Malicious File & Scan
```bash
# Create a test PHP webshell sample
echo "<?php if(isset(\$_GET['cmd'])){ system(\$_GET['cmd']); } ?>" > /tmp/backdoor_test.php

# Create a benign test file
echo "<?php echo 'Hello World'; ?>" > /tmp/benign_test.php

# Run YARA recursive scan across /tmp directory
sudo apt install -y yara
yara -r -m /tmp/webshell_rules.yar /tmp/
```

### Expected Output
```text
Generic_PHP_WebShell_Detection [author="SOC Detection Team",description="Detects obfuscated PHP web shells and command execution backdoors",mitre_technique="T1505.003"] /tmp/backdoor_test.php
```

---

## 11. Elastic Detection Rules CLI (MITRE ATT&CK Rule Validation)

### Concept in SOC
Elastic's official `detection-rules` repo provides standard TOML schema definitions for hundreds of pre-built MITRE ATT&CK rules. The CLI validates rule schema integrity and uploads rules directly into Kibana Security via REST API.

### Step 1: Clone Repository & Install Python Dependencies
```bash
git clone https://github.com/elastic/detection-rules.git /tmp/detection-rules
cd /tmp/detection-rules
pip install -r requirements.txt --break-system-packages
```

### Step 2: Class Demonstration — Validate Detection Rule Syntax
```bash
# Test rule schema validation against an official Windows TOML rule
python -m detection_rules validate-rule rules/windows/execution_powershell_download.toml

# Run unit tests across all detection rules
python -m detection_rules test
```

---

## 12. Uncoder.IO / uncoder-core (Cross-SIEM Query Translation)

### Concept in SOC
`uncoder-core` is an open-source query translation engine that converts operational hunting queries between KQL (Microsoft Sentinel), SPL (Splunk), EQL/Lucene (Elastic), and Sigma.

### Step 1: Clone & Setup Uncoder Core CLI
```bash
git clone https://github.com/UncoderIO/Uncoder_IO.git /tmp/uncoder
cd /tmp/uncoder
pip install -r requirements.txt --break-system-packages
```

### Step 2: Class Demonstration — Translate Sigma Rule to Microsoft Sentinel KQL
```bash
python uncoder-core/app/translator/tools/translate.py -q '/tmp/proc_suspicious_curl.yml' -s sigma -t microsoft-sentinel
```

---

## 13. Chainsaw (Sigma-Powered Windows EVTX Hunting)

### Concept in SOC
Chainsaw is a high-speed Rust-based standalone hunting and triage tool. It parses raw Windows Event Log files (`.evtx`) against Sigma rules and pre-built hunt logic without requiring a full SIEM infrastructure.

### Step 1: Build Chainsaw from Source on Kali Linux
```bash
sudo apt install -y cargo
git clone https://github.com/WithSecureLabs/chainsaw.git /tmp/chainsaw
cd /tmp/chainsaw && cargo build --release
```

### Step 2: Class Demonstration — Hunt in EVTX Files with Sigma Rules
```bash
# Download sample EVTX artifacts (EVTX-ATTACK-SAMPLES)
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git /tmp/evtx_samples

# Hunt across all EVTX samples using Chainsaw and Sigma rules
./target/release/chainsaw hunt /tmp/evtx_samples/ -s /tmp/sigma/rules/ --mapping mappings/sigma-event-logs-all.yml --csv --output /tmp/chainsaw_results.csv

# View top detected threats
head -n 20 /tmp/chainsaw_results.csv
```

---

# Pillar D: Use Case Testing & Detection Validation

---

## 14. Atomic Red Team (Discrete ATT&CK Telemetry Generation)

### Concept in SOC
Atomic Red Team is an open-source library of simple, scripted unit tests mapped directly to MITRE ATT&CK techniques. Detection engineers use it to safely trigger known attack behaviors and verify whether newly created SIEM rules fire.

### Step 1: Clone Atomic Red Team Repository
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git /tmp/atomic-red-team
```

### Step 2: Class Demonstration — Execute Discrete Linux ATT&CK Techniques
```bash
# Technique 1: MITRE T1082 - System Information Discovery
uname -a && cat /etc/os-release && lscpu

# Technique 2: MITRE T1087.001 - Local Account Enumeration
cat /etc/passwd | cut -d: -f1,3

# Technique 3: MITRE T1059.004 - Execution via Sh/Bash Download Cradle
bash -c "curl -s https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.004/src/echo-art-fish.sh | bash"
```

### Step 3: Verify Telemetry in SIEM
```bash
# Inspect Linux kernel audit log to confirm detection telemetry was generated
sudo ausearch -m EXECVE -ts recent | tail -n 20
```

---

## 15. CALDERA (Adversary Emulation & Multi-Stage Attack Chains)

### Concept in SOC
MITRE CALDERA is an automated adversary emulation platform. Unlike discrete unit tests, CALDERA executes multi-step attack chains (Reconnaissance $\rightarrow$ Lateral Movement $\rightarrow$ Exfiltration) to validate complex SIEM correlation rules and playbooks.

### Step 1: Install & Launch CALDERA on Kali Linux
```bash
sudo apt install -y python3-pip
git clone https://github.com/mitre/caldera.git /opt/caldera --recursive
cd /opt/caldera
pip install -r requirements.txt --break-system-packages

# Start server in insecure demonstration mode
python3 server.py --insecure
```

### Step 2: Class Demonstration — Access Web Console & Start Operation
```bash
# Open browser to access Web UI:
# URL: http://localhost:8888
# Default Credentials:
#   Red Team Operator:  red / admin
#   Blue Team Defender: blue / admin
```

---

## 16. DetectionLab (Automated SIEM Testing Harness)

### Concept in SOC
DetectionLab automates the deployment of a fully pre-wired active directory environment containing a Windows Domain Controller, Windows 10 host, Splunk/Wazuh SIEM server, and Fleet manager, specifically tailored for detection engineering.

### Step 1: Inspect Vagrant / Packer Deployment Structure
```bash
sudo apt install -y vagrant packer
git clone https://github.com/clong/DetectionLab.git /opt/DetectionLab
cd /opt/DetectionLab/Vagrant

# Check status of configured lab nodes (DC, WEF, WIN10, LOGGER)
vagrant status
```

---

# Pillar E: Alert Tuning & False-Positive Reduction

---

## 17. `jq` (Deep Alert Slicing & Noise Frequency Profiling)

### Concept in SOC
Alert fatigue is the primary failure mode of SOC operations. Detection engineers use `jq` to aggregate raw JSON alert dumps, identify high-volume false-positive rules, and discover noisy fields that require tuning.

### Step 1: Class Demonstration — Identify Top 10 Noisiest SIEM Rules
```bash
cat /var/ossec/logs/alerts/alerts.json | jq -r '.rule.id + " - " + .rule.description' | sort | uniq -c | sort -rn | head -n 10
```

### Step 2: Filter Alerts by Specific Signature & Examine Payload
```bash
# Slicing Suricata eve.json for specific signature ID
tail -f /var/log/suricata/eve.json | jq 'select(.alert.signature_id == 2010935) | {timestamp, src: .src_ip, dest: .dest_ip, proto: .proto, payload: .payload_printable}'
```

### Expected Output
```text
   1420 5710 - sshd: Attempt to login using a non-existent user
    845 5501 - PAM: Login session opened.
    312 31101 - Web server 400 error code.
```

---

## 18. Wazuh Ruleset Test (`wazuh-logtest` Live Debugger)

### Concept in SOC
`wazuh-logtest` is an interactive CLI debugger that allows detection engineers to feed raw log lines into the Wazuh analysis engine to see exactly which decoders, parent rules, child rules, and alert levels are triggered before deploying rules to production.

### Step 1: Class Demonstration — Launch Interactive Debugger
```bash
sudo /var/ossec/bin/wazuh-logtest
```

### Step 2: Paste Raw Sample Log Line into Prompt
```text
Aug 16 19:40:02 kali sshd[25412]: Failed password for invalid user hacker from 198.51.100.23 port 54321 ssh2
```

### Expected Output
```text
**Phase 1: Completed pre-decoding.
       full event: 'Aug 16 19:40:02 kali sshd[25412]: Failed password for invalid user hacker from 198.51.100.23 port 54321 ssh2'
       timestamp: 'Aug 16 19:40:02'
       hostname: 'kali'
       program_name: 'sshd'

**Phase 2: Completed decoding.
       name: 'sshd'
       dstuser: 'hacker'
       srcip: '198.51.100.23'

**Phase 3: Completed filtering (rules).
       id: '5710'
       level: '5'
       description: 'sshd: Attempt to login using a non-existent user'
       groups: '['syslog', 'sshd', 'authentication_failed']'
```

---

## 19. ElastAlert2 (Thresholds, Frequency & Alert Suppression)

### Concept in SOC
ElastAlert2 queries Elasticsearch on scheduled intervals to detect multi-event conditions (e.g. more than 5 failed logins within 2 minutes) and supports **alert suppression / timeframe deduplication** to eliminate alert floods.

### Step 1: Install ElastAlert2 & Create Index
```bash
pip install elastalert2 --break-system-packages
elastalert-create-index --host localhost --port 9200 --ssl --no-verify-certs --username elastic --password YOUR_PASS
```

### Step 2: Write a Tuned Threshold Alert Rule
```bash
cat << 'EOF' > /tmp/ssh_bruteforce_rule.yaml
name: "High Volume SSH Authentication Failures"
type: frequency
index: "logs-*"
num_events: 5
timeframe:
    minutes: 2
filter:
    - query:
          query_string:
              query: "event.action: \"logon-failed\" AND process.name: \"sshd\""

# ALERT TUNING: Suppress duplicate alerts for the same source IP for 30 minutes
realert:
    minutes: 30
query_key: "source.ip"

alert:
    - "debug"
EOF
```

### Step 3: Class Demonstration — Test Rule in Debug Mode
```bash
elastalert --config /tmp/elastalert_config.yaml --rule /tmp/ssh_bruteforce_rule.yaml --debug
```

---

## 20. Suricata Engine Analysis & Rule Profiling

### Concept in SOC
Network IDS rule bloat causes packet drops and high CPU usage. Detection engineers use Suricata's built-in rule profiling engine to measure rule execution latency (ticks) and disable high-cost or noisy signatures.

### Step 1: Run Engine Analysis & Rule Profiling
```bash
sudo suricata --engine-analysis -c /etc/suricata/suricata.yaml
```

### Step 2: Class Demonstration — Profile Top High-Cost Rules
```bash
# View top 10 most CPU-intensive rules in Suricata profiling log
cat /var/log/suricata/rule_perf.log | sort -k5 -n -r | head -n 10

# Live reload rule changes without restarting Suricata daemon
sudo suricatasc -c 'ruleset-reload-nonblocking'
```

---

## 📋 Comprehensive Class Lab Workflow Matrix

| Lab Stage | Objective | Primary Tools Used | Practical Verification Command |
|---|---|---|---|
| **1. Architecture** | Deploy ingestion, indexing, and visualization tiers | Wazuh, Elastic Stack, Graylog, Logstash | `curl -k https://localhost:9200/_cluster/health` |
| **2. Log Shipping** | Ingest Suricata EVE & Linux authentication logs | Filebeat, rsyslog, syslog-ng, NXLog | `ss -tulpn \| grep 514` |
| **3. Detection Engineering**| Write detection use case and compile to SIEM queries | Sigma, YARA, Elastic detection-rules, Chainsaw | `sigma convert -t splunk rule.yml` |
| **4. Validation** | Trigger atomic attack behaviors to verify detection | Atomic Red Team, CALDERA | `ausearch -m EXECVE -ts recent` |
| **5. Alert Tuning** | Measure noise, eliminate FPs, apply suppression | `jq`, `wazuh-logtest`, ElastAlert2, Suricata Profiling | `wazuh-logtest` |

---
*SOC Module 06: SIEM Architecture, Use Cases, Detection Engineering & Alert Tuning — Classroom Reference Guide.*