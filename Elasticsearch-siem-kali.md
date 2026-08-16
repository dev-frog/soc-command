# Elasticsearch SIEM on Kali Linux
### Full build guide: install, agent enrollment, detection engineering (EQL/ES|QL/Sigma), and alert tuning — using the Elastic Security (SIEM) app.

This guide walks through standing up the Elastic Stack as a SIEM on a Kali box: Elasticsearch + Kibana as the core, Elastic Agent/Fleet for log and endpoint collection, Elastic Security app for detections, and CLI tools for rule engineering and alert tuning. Commands assume Kali (Debian-based) with root/sudo access.

---

## A. Core Install (Elasticsearch + Kibana)

### 1. Add Elastic APT repo & install
Installs Elasticsearch and Kibana from Elastic's official repository (not the Kali default repos).
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update
sudo apt install elasticsearch kibana -y
```

### 2. Start services & capture enrollment info
First start of Elasticsearch prints the `elastic` superuser password and a Kibana enrollment token — save both.
```bash
sudo systemctl enable --now elasticsearch
sudo systemctl enable --now kibana
# Regenerate password/token later if missed:
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
sudo /usr/share/kibana/bin/kibana-verification-code
```

### 3. Verify cluster health
Confirms Elasticsearch is up and green/yellow before enabling Security app features.
```bash
curl -k -u elastic:YOUR_PASSWORD https://localhost:9200/_cluster/health?pretty
curl -k -u elastic:YOUR_PASSWORD https://localhost:9200/_cat/indices?v
```

### 4. Enable Elastic Security (SIEM) app
The Security app lives inside Kibana; enable it and open the detection engine setup wizard.
```bash
# In kibana.yml confirm:
xpack.security.enabled: true
# Then browse to:
https://localhost:5601/app/security/get_started
```

---

## B. Data Collection (Fleet / Elastic Agent / Beats)

### 5. Fleet Server setup
Fleet is the management layer for Elastic Agents; required for centrally deploying integrations (Suricata, Auditd, Windows, etc.).
```bash
# In Kibana UI: Management > Fleet > Settings > Add Fleet Server
# Then on the Fleet Server host:
sudo ./elastic-agent install \
  --fleet-server-es=https://localhost:9200 \
  --fleet-server-service-token=YOUR_TOKEN \
  --fleet-server-policy=fleet-server-policy
```

### 6. Elastic Agent (endpoint enrollment)
Deploys the unified agent to hosts you want monitored; pulls policy (integrations) from Fleet.
```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.13.0-linux-x86_64.tar.gz
tar xzvf elastic-agent-8.13.0-linux-x86_64.tar.gz
cd elastic-agent-8.13.0-linux-x86_64
sudo ./elastic-agent install --url=https://fleet-server:8220 --enrollment-token=YOUR_TOKEN
```

### 7. Auditbeat (Linux audit/file-integrity)
Direct-ship alternative to Fleet for auditd events and file integrity monitoring into the SIEM.
```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-8.13.0-amd64.deb
sudo dpkg -i auditbeat-8.13.0-amd64.deb
sudo auditbeat setup -e
sudo systemctl start auditbeat
```

### 8. Packetbeat (network flow data)
Ships network protocol data (DNS, HTTP, TLS) — useful for network-based SIEM use cases.
```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-8.13.0-amd64.deb
sudo dpkg -i packetbeat-8.13.0-amd64.deb
sudo packetbeat setup -e
sudo systemctl start packetbeat
```

### 9. Filebeat + Suricata module
Feeds Suricata `eve.json` alerts into Elasticsearch for network-IDS-driven SIEM use cases.
```bash
sudo apt install filebeat -y
sudo filebeat modules enable suricata
sudo filebeat setup -e
sudo systemctl start filebeat
```

---

## C. Detection Engineering (Elastic Security)

### 10. elastic-package (integration & rule dev CLI)
Official CLI for building/testing Elastic integrations and detection content locally before deploying.
```bash
curl -L -O https://github.com/elastic/elastic-package/releases/latest/download/elastic-package_Linux_x86_64.tar.gz
tar xzvf elastic-package_Linux_x86_64.tar.gz -C /usr/local/bin elastic-package
elastic-package check
elastic-package test
```

### 11. detection-rules CLI (official Elastic repo)
Write, validate, and push detection rules mapped to MITRE ATT&CK directly into Kibana Security.
```bash
git clone https://github.com/elastic/detection-rules.git
cd detection-rules
python -m detection_rules validate-rule rules/linux/execution_shell.toml
python -m detection_rules kibana upload-rule rules/linux/execution_shell.toml
```

### 12. EQL (Event Query Language) via CLI
Elastic's native sequence-matching query language for multi-stage detection logic — test queries via curl before saving as a rule.
```bash
curl -k -u elastic:PASS -X GET "https://localhost:9200/logs-*/_eql/search?pretty" \
  -H 'Content-Type: application/json' -d '{
  "query": "process where process.name == \"bash\" and process.args : \"-c\""
}'
```

### 13. ES|QL (Elasticsearch Query Language)
Newer pipe-based query language for ad hoc detection logic and correlation across indices.
```bash
curl -k -u elastic:PASS -X POST "https://localhost:9200/_query?pretty" \
  -H 'Content-Type: application/json' -d '{
  "query": "FROM logs-* | WHERE event.action==\"logon-failed\" | STATS count(*) BY user.name"
}'
```

### 14. Sigma → ES|QL/EQL conversion (sigma-cli)
Write portable Sigma rules, convert to Elastic's native query languages for import into the Security app.
```bash
pip install sigma-cli --break-system-packages
git clone https://github.com/SigmaHQ/sigma.git
sigma convert -t elasticsearch-eql -p ecs_windows sigma/rules/windows/*.yml
sigma convert -t elasticsearch-esql sigma/rules/linux/*.yml
```

---

## D. Use Case Validation (Generate Data to Detect)

### 15. Atomic Red Team
Fires individual ATT&CK techniques to produce the exact telemetry a new detection rule should catch.
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git
# PowerShell runner on Windows target:
Invoke-AtomicTest T1059.004 -TestNumbers 1   # Unix shell execution
```

### 16. CALDERA
Full attack-chain emulation to validate correlation rules spanning multiple techniques/tactics.
```bash
git clone https://github.com/mitre/caldera.git --recursive
cd caldera && pip3 install -r requirements.txt --break-system-packages
python3 server.py --insecure
```

---

## E. Alert Tuning (Reduce False Positives)

### 17. Kibana rule exceptions via API (curl)
Add exception items to a rule from the CLI to suppress known-benign matches without editing the rule logic.
```bash
curl -k -u elastic:PASS -X POST "https://localhost:5601/api/exception_lists/items" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
  "list_id": "endpoint_list", "type": "simple",
  "entries": [{"field":"process.name","operator":"included","type":"match","value":"backup.sh"}]
}'
```

### 18. jq (alert volume analysis)
Slice exported alert JSON to find your noisiest rules by count before adjusting thresholds.
```bash
curl -k -u elastic:PASS "https://localhost:9200/.alerts-security*/_search?size=1000" | \
  jq '.hits.hits[]._source.kibana.alert.rule.name' | sort | uniq -c | sort -rn
```

### 19. Elasticsearch _search aggregations (tuning threshold discovery)
Query historical event volume/baselines directly to pick sane thresholds for a new rule before enabling it.
```bash
curl -k -u elastic:PASS -X GET "https://localhost:9200/logs-*/_search?pretty" \
  -H 'Content-Type: application/json' -d '{
  "size":0,
  "aggs":{"by_user":{"terms":{"field":"user.name","size":20}}}
}'
```

### 20. Rule scheduling & risk-score tuning (Kibana API)
Adjust a rule's run interval, lookback window, and risk score via API to cut alert fatigue while keeping detection intact.
```bash
curl -k -u elastic:PASS -X PATCH "https://localhost:5601/api/detection_engine/rules" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
  "rule_id":"YOUR_RULE_ID", "interval":"10m", "risk_score":47
}'
```

---

## Suggested Build Flow

| Stage | Goal | Key Steps/Tools |
|---|---|---|
| 1. Core Stack | Elasticsearch + Kibana running, cluster healthy | elasticsearch, kibana, elasticsearch-reset-password |
| 2. Data Collection | Agents/Beats shipping host, network, and log data | Fleet, Elastic Agent, Auditbeat, Packetbeat, Filebeat |
| 3. Detection Engineering | Rules written/imported and mapped to ATT&CK | detection-rules CLI, EQL, ES|QL, Sigma |
| 4. Validation | Confirm each rule fires on the technique it targets | Atomic Red Team, CALDERA |
| 5. Alert Tuning | Reduce noise via exceptions, thresholds, scheduling | Kibana exception API, jq, _search aggregations, rule scheduling API |

---

**Note:** Replace `YOUR_PASSWORD`/`YOUR_TOKEN`/`YOUR_RULE_ID` with values generated during your own install. Run adversary-emulation steps (Atomic Red Team, CALDERA) only against systems you own or are authorized to test.