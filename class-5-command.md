# MITRE ATT&CK-Based SOC Lab on Kali Linux

### 20 Tools & Commands for Security Monitoring, Event Correlation, Log Management & Detection Strategy

This lab guide lists 20 open-source tools used on Kali Linux for building a MITRE ATT&CK-aligned SOC training lab. Tools are grouped by function: network monitoring/IDS, host log collection, SIEM/correlation, threat intel & mapping, and adversary emulation (used to safely generate detectable activity for exercises). Each entry includes install and core usage commands.

---

## A. Network Security Monitoring / IDS-IPS

### 1. Suricata

Signature-based IDS/IPS/NSM engine; supports MITRE ATT&CK-tagged rulesets (ET Open, etc.).

```bash
sudo apt install suricata -y
sudo suricata-update
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
tail -f /var/log/suricata/eve.json | jq .
```

### 2. Zeek (Bro)

Protocol-aware network traffic analyzer; generates rich connection/DNS/HTTP logs used for correlation.

```bash
sudo apt install zeek -y
sudo /opt/zeek/bin/zeekctl deploy
zeek -i eth0 local
cat conn.log | zeek-cut id.orig_h id.resp_h proto
```

### 3. Snort

Classic rule-based IDS; alternative/companion to Suricata for signature detection labs.

```bash
sudo apt install snort -y
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
sudo snort -T -c /etc/snort/snort.conf   # test config
```

### 4. tcpdump

Raw packet capture for manual traffic inspection and evidence collection.

```bash
sudo tcpdump -i eth0 -w capture.pcap
sudo tcpdump -i eth0 port 445 -nn
tcpdump -r capture.pcap -A | less
```

### 5. Wireshark / tshark

GUI and CLI packet analysis for deep-dive investigation of captured traffic.

```bash
sudo apt install wireshark tshark -y
tshark -i eth0 -Y "http.request" -T fields -e ip.src -e http.host
tshark -r capture.pcap -q -z conv,tcp
```

---

## B. Host-Based Logging / Endpoint Visibility

### 6. auditd

Linux kernel audit framework; logs syscalls, file access, and privilege changes — maps to ATT&CK Linux techniques.

```bash
sudo apt install auditd audispd-plugins -y
sudo systemctl enable --now auditd
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
sudo ausearch -k passwd_changes
sudo aureport --summary
```

### 7. Sysmon for Linux

Sysinternals Sysmon ported to Linux; detailed process/network/file event logging (mirrors Windows Sysmon).

```bash
git clone https://github.com/Sysinternals/SysmonForLinux.git
cd SysmonForLinux && ./build.sh
sudo ./sysmon -accepteula -i sysmon-config.xml
sudo journalctl -f -u sysmon
```

### 8. osquery

SQL-based endpoint instrumentation; query running processes, users, network connections like a database.
```bash
sudo apt install osquery -y
osqueryi "SELECT * FROM processes WHERE name='bash';"
osqueryi "SELECT * FROM listening_ports;"
sudo systemctl start osqueryd
```

### 9. Auditbeat
Elastic Beat that ships auditd/file-integrity data directly into the ELK/Wazuh pipeline.
```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-8.13.0-amd64.deb
sudo dpkg -i auditbeat-8.13.0-amd64.deb
sudo auditbeat setup
sudo systemctl start auditbeat
```

### 10. Filebeat
Lightweight log shipper; forwards Suricata/Zeek/syslog files to Logstash/Elasticsearch/Wazuh indexer.
```bash
sudo apt install filebeat -y
sudo filebeat modules enable suricata zeek
sudo filebeat setup -e
sudo systemctl start filebeat
```

---

## C. SIEM / Log Aggregation / Event Correlation

### 11. Wazuh (manager + indexer + dashboard)
Open-source SIEM/XDR; ships with ATT&CK-tagged detection rules and a built-in correlation engine.
```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash wazuh-install.sh -a
sudo /var/ossec/bin/agent_control -l         # list agents
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

### 12. Elastic Stack (Elasticsearch + Logstash + Kibana)
General-purpose log store/search/visualization stack for building custom correlation dashboards.
```bash
sudo apt install elasticsearch logstash kibana -y
sudo systemctl enable --now elasticsearch logstash kibana
curl -X GET "localhost:9200/_cat/indices?v"
```

### 13. Graylog
Alternative centralized log management platform with stream-based correlation rules and alerting.
```bash
sudo apt install docker.io docker-compose -y
git clone https://github.com/Graylog2/docker-compose.git
cd docker-compose && sudo docker-compose up -d
# Web UI: http://localhost:9000
```

### 14. rsyslog
Standard Linux syslog daemon; central log collection point for forwarding to SIEM.
```bash
sudo apt install rsyslog -y
sudo nano /etc/rsyslog.d/50-remote.conf
# add: *.* @@siem-server-ip:514
sudo systemctl restart rsyslog
```

### 15. Splunk Free (optional, if licensed by course)
Commercial-grade SIEM with SPL query language; many programs provide a free/dev license for labs.
```bash
wget -O splunk.deb 'https://download.splunk.com/products/splunk/releases/latest/linux/splunk.deb'
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
# Web UI: http://localhost:8000
```

---

## D. Threat Intel Mapping / Detection Strategy

### 16. MITRE ATT&CK Navigator
Interactive heatmap tool to score detection coverage per technique/tactic — core deliverable for the "detection strategy" unit.
```bash
sudo apt install docker.io -y
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator/nav-app
docker build -t attack-navigator .
docker run -p 4200:4200 attack-navigator
# Access: http://localhost:4200
```

### 17. Sigma
Generic, vendor-agnostic detection rule format; write once, convert to Wazuh/Elastic/Splunk queries.
```bash
pip install sigma-cli --break-system-packages
git clone https://github.com/SigmaHQ/sigma.git
sigma convert -t splunk sigma/rules/windows/process_creation/*.yml
sigma convert -t elasticsearch-lucene rule.yml
```

### 18. MISP (Malware Info Sharing Platform)
Threat intel platform for IOC management, tagging IOCs with ATT&CK techniques, and correlation lookups.
```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker && cp template.env .env
sudo docker-compose up -d
# Web UI: https://localhost
```

---

## E. Adversary Emulation (safe log-generation for detection exercises)

### 19. Atomic Red Team
Executes individual, discrete ATT&CK techniques (by Technique ID) to safely generate detectable events.
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git

# On Windows target (PowerShell):
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Invoke-AtomicTest T1059.001   # Example: PowerShell execution
```

### 20. CALDERA
MITRE's own automated adversary emulation platform; runs full ATT&CK operation chains and reports technique IDs used.
```bash
sudo apt install python3-pip -y
git clone https://github.com/mitre/caldera.git --recursive
cd caldera && pip3 install -r requirements.txt --break-system-packages
python3 server.py --insecure
# Web UI: https://localhost:8888  (default red/blue login)
```

---

## Suggested Lab Flow Mapped to Course Topics

| Course Topic | Lab Activity | Key Tools |
|---|---|---|
| Log Management | Configure auditd/Sysmon; forward logs via Filebeat/Auditbeat to SIEM | auditd, Sysmon, Filebeat, Auditbeat |
| Security Monitoring | Deploy Suricata/Zeek on a network segment; watch live alerts | Suricata, Zeek, Snort, tcpdump |
| Event Correlation | Build SIEM rules combining login failures + process creation + egress into one alert | Wazuh, Elastic Stack, Graylog |
| Detection Strategy | Use ATT&CK Navigator to find coverage gaps; write Sigma rules for gaps | ATT&CK Navigator, Sigma, MISP |
| Exercise / Validation | Run Atomic Red Team / CALDERA techniques; locate them in SIEM; map to Navigator | Atomic Red Team, CALDERA |

---

**Note:** All 20 tools listed are open-source/free and defensive or MITRE-sanctioned adversary-emulation tools appropriate for a monitoring/detection/SOC coursework lab. Run attack simulation tools (Atomic Red Team, CALDERA) only in isolated lab environments you own or are authorized to test.