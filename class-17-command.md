# Module 17: SOC Automation, SOAR, AI for SOC & Threat Detection Optimization
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for running open-source SOAR (Shuffle, n8n), local LLM threat analysis (Ollama), webhook automation, and threat detection optimization on Kali Linux.

---

### 1. Shuffle SOAR — Open-Source Security Orchestration & Automation
**Purpose:** Deploy Shuffle SOAR container stack for drag-and-drop workflow automation between SIEM, TheHive, and EDR.
```bash
git clone https://github.com/Shuffle/Shuffle.git /opt/shuffle
cd /opt/shuffle && sudo docker-compose up -d
# Access UI: http://localhost:3001
```

---

### 2. n8n — Modular SOC Alerting & Workflow Automation
**Purpose:** Run n8n for lightweight event processing, alert enrichment, and automated communication webhooks.
```bash
docker run -d --name n8n -p 5678:5678 -v ~/.n8n:/home/node/.n8n n8nio/n8n
# Access UI: http://localhost:5678
```

---

### 3. Ollama — Local AI / LLM Threat Analysis Engine on Kali
**Purpose:** Run local open-source LLMs (Mistral, Llama3) on Kali Linux to analyze raw logs and provide MITRE mappings.
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama run mistral
```

---

### 4. Local AI Automated Log Triage Script (Python + Ollama)
**Purpose:** Pipe raw SIEM alerts directly into local AI to generate incident summaries and containment recommendations.
```bash
cat << 'EOF' > /tmp/soc_ai_triage.py
import subprocess, json
alert = '{"src_ip": "198.51.100.77", "rule": "Mimikatz command detected", "cmd": "sekurlsa::logonpasswords"}'
prompt = f"Analyze this SOC alert, give MITRE ATT&CK ID and 3 containment actions:\n{alert}"
res = subprocess.run(["ollama", "run", "mistral", prompt], capture_output=True, text=True)
print("=== AI TRIAGE SUMMARY ===")
print(res.stdout)
EOF
python3 /tmp/soc_ai_triage.py
```

---

### 5. `curl` — Trigger Inbound SOAR Webhooks
**Purpose:** Send simulated or real SIEM alert JSON payloads into a SOAR automation workflow.
```bash
curl -X POST "http://localhost:5678/webhook/triage-alert" \
  -H "Content-Type: application/json" \
  -d '{"ip": "185.220.101.5", "alert_type": "Brute Force SSH", "host": "srv-app-01"}'
```

---

### 6. `jq` — Transform Alert Schemas for Automation Endpoints
**Purpose:** Reformat complex SIEM JSON alerts into the clean schema required by automated ticketing APIs.
```bash
cat alert.json | jq '{title: .rule.description, ip: .data.srcip, severity: .rule.level}' > payload.json
```

---

### 7. VirusTotal Automated Python Enrichment Script
**Purpose:** Script automated file hash and IP reputation scoring inside an automated SOAR pipeline.
```bash
pip install requests --break-system-packages
python3 -c "
import requests
headers = {'x-apikey': 'YOUR_VT_API_KEY'}
res = requests.get('https://www.virustotal.com/api/v3/ip_addresses/185.220.101.5', headers=headers)
print('Malicious Votes:', res.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0))
"
```

---

### 8. AbuseIPDB Automated IP Reputation Check
**Purpose:** Automated API check to determine whether an IP address should be blocked automatically by firewall automation.
```bash
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=185.220.101.5" \
  -H "Key: YOUR_ABUSEIPDB_API_KEY" \
  -H "Accept: application/json" | jq '.data.abuseConfidenceScore'
```

---

### 9. Shodan CLI — Automated Perimeter Asset Enrichment
**Purpose:** Enrich external alerts with open ports and vulnerability data via Shodan API.
```bash
sudo apt install -y python3-shodan
shodan init YOUR_SHODAN_API_KEY
shodan host 185.220.101.5
```

---

### 10. `wazuh-integratord` — Wazuh Native SOAR Integration
**Purpose:** Enable the Wazuh integrator daemon to automatically forward alerts to Slack, PagerDuty, or Shuffle.
```bash
sudo systemctl status wazuh-integratord
```

---

### 11. `webhook` (Lightweight Go Webhook Server)
**Purpose:** Deploy a lightweight standalone HTTP webhook listener that runs bash scripts upon receiving alerts.
```bash
sudo apt install -y webhook
webhook -hooks /opt/soc-automation/hooks.json -verbose
```

---

### 12. `elastalert2` — Elasticsearch Alerting & Automation Engine
**Purpose:** Continuously query Elasticsearch indices and automatically trigger webhooks on threshold matches.
```bash
pip install elastalert2 --break-system-packages
elastalert --config /opt/elastalert/config.yaml --debug
```

---

### 13. Automated Endpoint Firewall Isolation Trigger
**Purpose:** Programmatically trigger local host isolation via iptables from an automation script.
```bash
sudo iptables -I INPUT 1 -s 185.220.101.5 -j DROP
```

---

### 14. `ansible-runner` — Programmatic Playbook Execution
**Purpose:** Run Ansible automation playbooks directly from Python SOAR workflows without CLI overhead.
```bash
pip install ansible-runner --break-system-packages
python3 -c "import ansible_runner; print('Ansible runner available')"
```

---

### 15. Redis CLI — In-Memory Message Broker for SOAR Pipelines
**Purpose:** Inspect and manage high-throughput event queues connecting SIEM ingestion to SOAR workers.
```bash
sudo apt install -y redis-tools
redis-cli ping
redis-cli llen soc_alert_queue
```

---

### 16. Celery — Distributed Task Queue Monitoring
**Purpose:** Inspect asynchronous worker task execution during high-volume alert bursts.
```bash
pip install celery --break-system-packages
celery -A tasks status
```

---

### 17. Docker Compose — Orchestrate SOAR & Automation Stacks
**Purpose:** Manage and scale multi-container automation ecosystems (TheHive, Cortex, Shuffle, n8n).
```bash
docker-compose -f /opt/shuffle/docker-compose.yml ps
```

---

### 18. `yara-python` — Automated Phishing Attachment Scanner
**Purpose:** Automatically scan email attachments against YARA rules within an automated SOAR email pipeline.
```bash
pip install yara-python --break-system-packages
python3 -c "
import yara
rules = yara.compile(source='rule test { condition: true }')
print('YARA rules loaded for automation')
"
```

---

### 19. `tldextract` — Automated Domain & Subdomain Normalization
**Purpose:** Extract root domains and TLDs from URLs in alert streams for consistent threat intel lookups.
```bash
pip install tldextract --break-system-packages
python3 -c "
import tldextract
ext = tldextract.extract('http://sub.phishing-login.evil.co.uk/auth')
print(f'Domain: {ext.domain}.{ext.suffix}')
"
```

---

### 20. `sigma-cli` (Automated Pipeline Validation)
**Purpose:** Automatically validate all newly engineered Sigma rules before committing to production SIEM.
```bash
sigma check /opt/sigma/rules/
```

---
*SOC Command Reference - Class 17*
