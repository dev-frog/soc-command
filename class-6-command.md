# Module 06: SIEM Architecture, Use Cases, Detection Engineering & Alert Tuning
### Open-source CLI tools for Kali Linux

This guide lists open-source, CLI-friendly tools installable on Kali Linux for the four pillars of this module: designing SIEM architecture (ingestion, indexing, storage), building and testing detection use cases, engineering detection rules in portable formats, and tuning alerts to reduce false positives while preserving true-positive coverage. Each entry includes install and core usage commands.

---

## A. SIEM Core Platforms (Architecture & Ingestion Layer)

### 1. Wazuh Manager + Indexer
Full open-source SIEM/XDR stack: agent-based collection, rule engine, indexer (OpenSearch-based storage) — good reference architecture for ingestion-to-storage design.
```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash wazuh-install.sh -a
sudo systemctl status wazuh-manager wazuh-indexer
sudo /var/ossec/bin/wazuh-control status
```

### 2. Elastic Stack (Elasticsearch, Logstash, Kibana)
Modular ingestion (Logstash/Beats) → indexing (Elasticsearch) → visualization (Kibana). Best for teaching layered SIEM architecture.
```bash
sudo apt install elasticsearch logstash kibana -y
sudo systemctl enable --now elasticsearch logstash kibana
curl -X GET "localhost:9200/_cluster/health?pretty"
sudo -u logstash /usr/share/logstash/bin/logstash -t   # test pipeline config
```

### 3. Graylog
Stream-based SIEM architecture with separate input/processing/output stages; good for use-case pipeline design.
```bash
sudo apt install docker.io docker-compose -y
git clone https://github.com/Graylog2/docker-compose.git
cd docker-compose && sudo docker-compose up -d
curl -u admin:admin http://localhost:9000/api/system/inputs
```

### 4. Logstash (standalone)
Pipeline-based data processing/normalization engine; core of the ingestion tier in custom SIEM architectures.
```bash
sudo apt install logstash -y
sudo nano /etc/logstash/conf.d/pipeline.conf
sudo /usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/pipeline.conf --config.test_and_exit
sudo systemctl start logstash
```

---

## B. Log Shipping / Normalization (Feeds the SIEM Architecture)

### 5. Filebeat
Lightweight shipper for log files (Suricata, Zeek, syslog, application logs) into the SIEM ingestion layer.
```bash
sudo apt install filebeat -y
sudo filebeat modules enable system suricata
sudo filebeat setup -e
sudo systemctl start filebeat
```

### 6. rsyslog
Central syslog relay; a common architecture choice for aggregating multi-source logs before SIEM ingestion.
```bash
sudo apt install rsyslog -y
sudo nano /etc/rsyslog.d/50-forward.conf
# add: *.* @@siem-server-ip:514
sudo systemctl restart rsyslog
```

### 7. syslog-ng
More flexible/parsing-capable syslog daemon; useful when architecture needs field extraction before storage.
```bash
sudo apt install syslog-ng -y
sudo nano /etc/syslog-ng/syslog-ng.conf
sudo syslog-ng -s   # syntax check
sudo systemctl restart syslog-ng
```

### 8. NXLog CE
Cross-platform log collector, strong for normalizing Windows event logs into JSON/syslog for SIEM ingestion.
```bash
wget https://nxlog.co/downloads/nxlog-ce/nxlog-ce_3-x_ubuntu-noble_amd64.deb
sudo dpkg -i nxlog-ce_3-x_ubuntu-noble_amd64.deb
sudo nxlog -f   # run in foreground for testing
sudo systemctl restart nxlog
```

---

## C. Detection Engineering (Writing & Managing Use Cases)

### 9. Sigma / sigma-cli
Vendor-agnostic detection-rule language; write one rule, compile it to Wazuh/Elastic/Splunk/QRadar queries — the standard detection-engineering workflow.
```bash
pip install sigma-cli --break-system-packages
git clone https://github.com/SigmaHQ/sigma.git
sigma convert -t elasticsearch-lucene -p ecs_windows rule.yml
sigma convert -t splunk rule.yml
```

### 10. YARA
Pattern-matching rule engine for file/malware-based detection use cases; integrates into SIEM/EDR pipelines.
```bash
sudo apt install yara -y
yara -r malware_rules.yar /path/to/scan/
yara -C malware_rules.yar sample.bin   # count matches
```

### 11. Elastic Detection Rules (detection-rules CLI)
Elastic's official repo/CLI for writing, testing, and validating detection-engineering rules mapped to ATT&CK.
```bash
git clone https://github.com/elastic/detection-rules.git
cd detection-rules
python -m detection_rules test
python -m detection_rules validate-rule rules/windows/example_rule.toml
```

### 12. Uncoder.IO CLI / uncoder-core
Translates detection rules between SIEM query languages (Sigma, KQL, SPL, ES|QL) for multi-platform use-case deployment.
```bash
git clone https://github.com/UncoderIO/Uncoder_IO.git
cd Uncoder_IO && pip install -r requirements.txt --break-system-packages
python uncoder-core/app/translator/tools/translate.py -q 'rule.yml' -s sigma -t splunk
```

### 13. Chainsaw
Fast Windows Event Log (EVTX) hunting/triage tool using Sigma rules — used to build and validate detections against real log samples.
```bash
git clone https://github.com/WithSecureLabs/chainsaw.git
cd chainsaw && cargo build --release
./chainsaw hunt evtx_samples/ -s sigma_rules/ --mapping mappings/sigma-event-logs-all.yml
```

---

## D. Use Case Testing / Detection Validation

### 14. Atomic Red Team
Executes discrete ATT&CK techniques to generate the exact telemetry a use case is meant to detect — used to validate new rules.
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git
# PowerShell runner on Windows target:
Invoke-AtomicTest T1003.001 -TestNumbers 1
```

### 15. CALDERA
MITRE's adversary-emulation platform; runs full attack chains to validate multi-stage correlation use cases end-to-end.
```bash
git clone https://github.com/mitre/caldera.git --recursive
cd caldera && pip3 install -r requirements.txt --break-system-packages
python3 server.py --insecure
# Web UI: https://localhost:8888
```

### 16. DetectionLab helper scripts (Vagrant/Packer based)
Spins up a pre-wired lab (domain controller, Splunk/Wazuh, Windows/Linux hosts) purpose-built for testing detection use cases.
```bash
sudo apt install vagrant packer -y
git clone https://github.com/clong/DetectionLab.git
cd DetectionLab/Vagrant && vagrant up
```

---

## E. Alert Tuning / False-Positive Reduction

### 17. jq
CLI JSON processor; essential for slicing/filtering alert JSON (e.g. Suricata eve.json, Wazuh alerts.json) to spot noisy fields during tuning.
```bash
sudo apt install jq -y
cat /var/ossec/logs/alerts/alerts.json | jq '.rule.id' | sort | uniq -c | sort -rn
tail -f eve.json | jq 'select(.alert.signature_id==2010935)'
```

### 18. Wazuh ruleset test / logtest
Built-in CLI for dry-running events against rules before deploying, to catch over-broad matches ahead of production tuning.
```bash
sudo /var/ossec/bin/wazuh-logtest
# paste a raw log line, inspect which rule ID fires and at what level
sudo /var/ossec/bin/wazuh-logtest -a   # alert-mode testing
```

### 19. Elastalert2
Rule-based alerting engine for Elasticsearch with configurable thresholds/suppression — used to tune alert frequency and grouping.
```bash
pip install elastalert2 --break-system-packages
elastalert-create-index
elastalert --config config.yaml --rule rules/high_login_failures.yaml --debug
```

### 20. Suricata --engine-analysis / rule profiling
Built-in Suricata flags to profile rule performance and identify high-noise / high-cost signatures to tune or disable.
```bash
suricata --engine-analysis -c /etc/suricata/suricata.yaml
cat /var/log/suricata/rule_perf.log | sort -k5 -n -r | head -20
sudo suricatasc -c 'ruleset-reload-nonblocking'   # reload after disabling noisy rules
```

---

## Suggested Lab Flow Mapped to Module Topics

| Module Topic | Lab Activity | Key Tools |
|---|---|---|
| SIEM Architecture | Stand up ingestion → indexing → visualization layers; diagram data flow | Wazuh, Elastic Stack, Graylog, Logstash |
| Use Cases | Define a detection use case (e.g. brute-force login); map required log sources | Filebeat, rsyslog, syslog-ng, NXLog |
| Detection Engineering | Write rule in Sigma, convert to your SIEM's query language, deploy | Sigma, YARA, Elastic detection-rules, Uncoder.IO, Chainsaw |
| Validation | Trigger the exact technique the rule targets; confirm it fires | Atomic Red Team, CALDERA, DetectionLab |
| Alert Tuning | Measure alert volume/false-positive rate; adjust thresholds, suppress noisy fields | jq, wazuh-logtest, Elastalert2, Suricata rule profiling |

---

**Note:** All tools listed are open-source and CLI-usable on Kali Linux. Run adversary-emulation tools (Atomic Red Team, CALDERA) only in isolated lab environments you own or are authorized to test.