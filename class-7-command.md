# Module 07: Incident Detection, Triage, Prioritization & Case Management
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for alert triage, severity scoring, automated IOC extraction, case management, and reputation lookups on Kali Linux.

---

### 1. TheHive 5 — Security Incident Response & Case Management
**Purpose:** Deploy and operate TheHive for structured case tracking, tasks, and evidence storage.
```bash
docker run -d --name thehive -p 9000:9000 thehiveproject/thehive:latest
# Access Web UI: http://localhost:9000
```

---

### 2. TheHive API CLI — Automated Case Creation
**Purpose:** Programmatically create incident cases from CLI scripts or detection alerts.
```bash
curl -X POST "http://localhost:9000/api/v1/case" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Alert: Suspicious PowerShell Download Cradle",
    "description": "Host 192.168.1.45 executed base64 encoded download cradle.",
    "severity": 3,
    "tags": ["T1059.001", "Execution", "PowerShell"]
  }'
```

---

### 3. `vt-cli` — VirusTotal Command-Line Triage
**Purpose:** Query file hashes, IP addresses, domains, and URLs directly from the terminal for reputation scores.
```bash
sudo apt install -y vt-cli
vt init --apikey "YOUR_VT_API_KEY"
vt ip 185.220.101.5
vt file /tmp/suspicious_sample.exe
```

---

### 4. `jq` — Slicing and Filtering Raw JSON Alert Telemetry
**Purpose:** Filter and prioritize high-severity alerts from raw SIEM or IDS JSON logs.
```bash
cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert" and .alert.severity <= 2) | {timestamp, src: .src_ip, alert: .alert.signature}'
```

---

### 5. `grep` (Regex Mode) — Fast IP Address Extraction
**Purpose:** Extract unique IPv4 addresses from unformatted email bodies or log dumps for batch triage.
```bash
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /var/log/syslog | sort -u
```

---

### 6. `grep` (Hash Mode) — Fast MD5 / SHA-256 Hash Extraction
**Purpose:** Extract cryptographic file hashes from forensic notes or alert messages.
```bash
grep -oE '\b[a-fA-F0-9]{64}\b' /tmp/incident_notes.txt | sort -u   # SHA-256
grep -oE '\b[a-fA-F0-9]{32}\b' /tmp/incident_notes.txt | sort -u   # MD5
```

---

### 7. `grep` (URL Mode) — Phishing URL Extraction
**Purpose:** Extract HTTP/HTTPS URLs from raw `.eml` email files for phishing triage.
```bash
grep -oE '(https?|ftp)://[^\s/$.?#].[^\s]*' /tmp/phishing_email.eml | sort -u
```

---

### 8. `cyberchef-cli` — Deobfuscate Obscured Payloads
**Purpose:** Decode Base64, Hex, or XOR strings found in process telemetry during triage.
```bash
sudo npm install -g cyberchef-cli
cyberchef-cli --recipe "From_Base64('A-Za-z0-9+/=',true,false)" --input "SUV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp"
```

---

### 9. `sha256sum` — Instant File Hash Generation
**Purpose:** Calculate cryptographic hashes of suspicious binaries to verify against threat feeds.
```bash
sha256sum /tmp/malicious_attachment.exe
```

---

### 10. `whois` — Autonomous System Number (ASN) & Registrar Triage
**Purpose:** Query registration data and hosting provider ownership for suspicious external IP addresses.
```bash
whois 185.220.101.5 | grep -E 'OrgName|NetName|Country|CIDR'
```

---

### 11. `dig` (+short) — DNS Resolution & Reverse IP Lookup
**Purpose:** Resolve suspicious domain names and perform reverse lookups on unknown IP addresses.
```bash
dig +short A evil-c2-domain.com
dig +short -x 185.220.101.5
```

---

### 12. `ssdeep` — Fuzzy Hashing & Malware Similarity Scoring
**Purpose:** Compare suspicious files against known malware variants using Context Triggered Piecewise Hashing.
```bash
sudo apt install -y ssdeep
ssdeep -b /tmp/sample1.exe > /tmp/hashes.txt
ssdeep -m /tmp/hashes.txt /tmp/sample2.exe
```

---

### 13. `exiftool` — Document & Binary Metadata Extraction
**Purpose:** Extract author names, creation timestamps, and software versions from suspicious incident attachments.
```bash
sudo apt install -y libimage-exiftool-perl
exiftool /tmp/invoice_phishing.pdf
```

---

### 14. `pdfid` — Suspicious PDF Exploit Indicator Triage
**Purpose:** Rapidly scan PDF documents for malicious elements (e.g. `/JavaScript`, `/OpenAction`, `/Launch`).
```bash
sudo apt install -y pdfid
pdfid /tmp/suspicious_invoice.pdf
```

---

### 15. `olevba` — Office Macro Phishing Triage
**Purpose:** Extract and analyze embedded VBA macros from suspicious Word and Excel documents.
```bash
pip install oletools --break-system-packages
olevba /tmp/malicious_document.docm
```

---

### 16. `trid` — File Header & Binary Identification
**Purpose:** Identify the true file type of an unknown binary, even if an attacker renamed the file extension.
```bash
sudo apt install -y trid
trid /tmp/unknown_payload.bin
```

---

### 17. `head` / `sort` / `uniq` — Alert Volume Prioritization
**Purpose:** Calculate the frequency distribution of triggered alert rules to prioritize the most critical incidents.
```bash
cat /var/ossec/logs/alerts/alerts.json | jq -r '.rule.description' | sort | uniq -c | sort -rn | head -n 10
```

---

### 18. `uac` (Unix-like Artifacts Collector) — Live System Triage
**Purpose:** Rapidly collect live system artifacts (running processes, network sockets, active users) during initial triage.
```bash
git clone https://github.com/tclahr/uac.git /tmp/uac
cd /tmp/uac && sudo ./uac -p ir_triage /tmp/triage_output/
```

---

### 19. `curl` (AbuseIPDB API) — Automated IP Reputation Scoring
**Purpose:** Query AbuseIPDB REST API to check the abuse confidence score of an external IP address.
```bash
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=185.220.101.5" \
  -H "Key: YOUR_ABUSEIPDB_API_KEY" \
  -H "Accept: application/json" | jq '.data.abuseConfidenceScore'
```

---

### 20. `mailx` — Automated Incident Escalation Notification
**Purpose:** Send automated email alerts to on-call Tier 2 incident responders upon high-priority triage findings.
```bash
sudo apt install -y bsd-mailx
echo "Severity 1 Incident declared on Host DC-01. Case #1024 opened in TheHive." | mailx -s "URGENT: SOC Escalation" oncall@organization.com
```

---
*SOC Command Reference - Class 07*
