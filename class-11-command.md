# Module 11: Threat Hunting Strategy, IOC Management & Threat Intelligence Integration
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for proactive threat hunting, managing Indicators of Compromise (IOCs), querying threat intelligence APIs (MISP, AlienVault OTX, VirusTotal), and searching event logs on Kali Linux.

---

### 1. MISP Docker — Threat Sharing & IOC Management Platform
**Purpose:** Deploy and run the Malware Information Sharing Platform (MISP) for organizing and correlating IOCs.
```bash
git clone https://github.com/MISP/misp-docker.git /opt/misp-docker
cd /opt/misp-docker && cp template.env .env
sudo docker-compose up -d
# Access UI: https://localhost (admin@admin.test / admin)
```

---

### 2. PyMISP — Query MISP Threat Attributes from CLI
**Purpose:** Programmatically fetch and search attributes, domains, and hashes from MISP using Python.
```bash
pip install pymisp --break-system-packages
python3 -c "
from pymisp import PyMISP
misp = PyMISP('https://localhost', 'YOUR_MISP_KEY', ssl=False)
events = misp.search(value='185.220.101.5')
print(f'Matching MISP Events: {len(events)}')
"
```

---

### 3. AlienVault OTX Python SDK — Query Threat Pulses
**Purpose:** Fetch adversary infrastructure details and pulse intelligence directly from AlienVault OTX.
```bash
pip install OTXv2 --break-system-packages
python3 -c "
from OTXv2 import OTXv2
otx = OTXv2('YOUR_OTX_API_KEY')
data = otx.get_indicator_details_full('IPv4', '185.220.101.5')
print('Threat Pulses:', len(data.get('general', {}).get('pulse_info', {}).get('pulses', [])))
"
```

---

### 4. `vt-cli` — Fast IOC Threat Scoring
**Purpose:** Query VirusTotal database for malware hashes, domains, and IP reputation directly from terminal.
```bash
sudo apt install -y vt-cli
vt ip 185.220.101.5
vt domain evil-c2.com
```

---

### 5. `yara` (Filesystem Threat Hunting)
**Purpose:** Proactively hunt across all server disks for custom malicious behavioral strings and webshells.
```bash
cat << 'EOF' > /tmp/hunt_webshell.yar
rule Webshell_Hunter {
    strings:
        $a = "eval(base64_decode(" nocase
        $b = "passthru(" nocase
        $c = "shell_exec(" nocase
    condition: any of them
}
EOF
yara -r -m /tmp/hunt_webshell.yar /var/www/html/
```

---

### 6. `sigma-cli` — Threat Intel to SIEM Query Conversion
**Purpose:** Translate threat hunting rules from Sigma format into Elasticsearch, Splunk, and QRadar queries.
```bash
pip install sigma-cli --break-system-packages
sigma convert -t elasticsearch-lucene -p ecs_windows /tmp/sigma/rules/windows/process_creation/*.yml
```

---

### 7. `velociraptor` — Endpoint Threat Hunting & Forensics Platform
**Purpose:** Deploy Velociraptor server/agent for hunting across enterprise endpoints using VQL queries.
```bash
curl -L -O https://github.com/Velocidex/velociraptor/releases/latest/download/velociraptor-v0.72.0-linux-amd64
chmod +x velociraptor-*-linux-amd64
sudo ./velociraptor-*-linux-amd64 gui
```

---

### 8. `osqueryi` — Threat Hunting via SQL Queries
**Purpose:** Query running processes, network connections, and cron jobs across hosts like a relational database.
```bash
sudo apt install -y osquery
osqueryi "SELECT name, path, cmdline FROM processes WHERE on_disk = 0;"
osqueryi "SELECT * FROM listening_ports WHERE port > 1024;"
```

---

### 9. `grep` (IOC Batch Hunting in Log Archives)
**Purpose:** Search thousands of archived log files for a specific list of malicious IP addresses.
```bash
grep -rnF -f /tmp/malicious_ips.txt /var/log/
```

---

### 10. `find` — Hunt for Anomalous SUID/SGID Binaries
**Purpose:** Hunt for unauthorized privilege escalation binaries planted on Linux file systems.
```bash
find / -type f -perm -04000 -exec ls -l {} + 2>/dev/null
```

---

### 11. `lsof` — Hunt for Established Suspicious Outbound Sockets
**Purpose:** Identify non-standard processes communicating outbound over HTTPS or unusual high ports.
```bash
sudo lsof -iTCP -sTCP:ESTABLISHED -n -P | grep -vE 'ssh|firefox|chrome'
```

---

### 12. `ausearch` — Hunt for Suspicious Linux Execution Patterns
**Purpose:** Search kernel audit logs for suspicious execution of network shells (`nc`, `ncat`, `python -c`).
```bash
sudo ausearch -m EXECVE -c nc -ts today
```

---

### 13. `auditctl` — Deploy Active Threat Hunting Rules
**Purpose:** Inject temporary kernel audit rules to trap execution of specific sensitive directories.
```bash
sudo auditctl -w /dev/shm -p x -k dev_shm_exec
```

---

### 14. `chainsaw` — Hunt for Lateral Movement in EVTX Logs
**Purpose:** Rapidly scan Windows Event Logs (EVTX) using Sigma rules to hunt for lateral movement techniques.
```bash
./chainsaw hunt /evidence/evtx/ -s /opt/sigma/rules/windows/ --mapping mappings/sigma-event-logs-all.yml
```

---

### 15. `hayabusa` — High-Speed Windows Threat Hunting Engine
**Purpose:** Execute fast Sigma-based threat hunting on Windows event logs to produce timeline summaries.
```bash
git clone https://github.com/Yamato-Security/hayabusa.git /opt/hayabusa
cd /opt/hayabusa && cargo build --release
./target/release/hayabusa csv-timeline -d /evidence/evtx/ -o /tmp/hunting_timeline.csv
```

---

### 16. `zeek-cut` — Hunt for Long-Duration C2 Beaconing
**Purpose:** Analyze Zeek connection logs to identify long-duration, low-throughput network connections.
```bash
cat conn.log | zeek-cut id.orig_h id.resp_h duration orig_bytes resp_bytes | sort -k3 -n -r | head -n 20
```

---

### 17. `tshark` — Hunt for DNS Tunneling & High-Entropy Domains
**Purpose:** Filter and extract DNS queries from PCAPs to detect data exfiltration via DNS tunneling.
```bash
tshark -r /evidence/traffic.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -n 30
```

---

### 18. `curl` — Fetch Automated Public Blocklists
**Purpose:** Ingest public threat feeds (Emerging Threats compromised IPs) directly into firewall or SIEM lists.
```bash
curl -s https://rules.emergingthreats.net/blockrules/compromised-ips.txt | grep -v '^#' | head -n 25
```

---

### 19. `ioc-parser` — Extract Indicators from CTI Reports
**Purpose:** Extract IPs, domains, hashes, and CVEs from raw unstructured Threat Intelligence PDF and HTML reports.
```bash
pip install ioc-parser --break-system-packages
ioc-parser -f /tmp/apt_threat_report.txt -o json > /tmp/extracted_iocs.json
```

---

### 20. `curl` (URLhaus Feed Query) — Automated Malware URL Lookup
**Purpose:** Query URLhaus threat database for newly reported malware distribution endpoints.
```bash
curl -s https://urlhaus.abuse.ch/downloads/csv_recent/ | head -n 30
```

---
*SOC Command Reference - Class 11*
