# Module 13: SOC Metrics, KPI, KRI, Dashboards & Executive Reporting
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for calculating Mean Time to Detect (MTTD), Mean Time to Respond (MTTR), Events Per Second (EPS), false positive ratios, and building metric dashboards on Kali Linux.

---

### 1. `python3` (MTTD & MTTR Calculator)
**Purpose:** Calculate average Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) in minutes from incident JSON logs.
```bash
cat << 'EOF' > /tmp/soc_kpi_calc.py
from datetime import datetime
incidents = [
    {"id": "INC-1", "created": "2026-08-01 10:00:00", "detected": "2026-08-01 10:14:00", "resolved": "2026-08-01 11:15:00"},
    {"id": "INC-2", "created": "2026-08-02 14:00:00", "detected": "2026-08-02 14:06:00", "resolved": "2026-08-02 14:40:00"}
]
mttd = [(datetime.strptime(i["detected"], "%Y-%m-%d %H:%M:%S") - datetime.strptime(i["created"], "%Y-%m-%d %H:%M:%S")).total_seconds()/60 for i in incidents]
mttr = [(datetime.strptime(i["resolved"], "%Y-%m-%d %H:%M:%S") - datetime.strptime(i["detected"], "%Y-%m-%d %H:%M:%S")).total_seconds()/60 for i in incidents]
print(f"MTTD: {sum(mttd)/len(mttd):.2f} Minutes | MTTR: {sum(mttr)/len(mttr):.2f} Minutes")
EOF
python3 /tmp/soc_kpi_calc.py
```

---

### 2. `wc` — Events Per Second (EPS) Ingestion Rate Calculator
**Purpose:** Calculate real-time log ingestion rates (EPS) across active syslog or collector log streams.
```bash
START=$(wc -l < /var/log/syslog); sleep 10; END=$(wc -l < /var/log/syslog)
echo "Current Log Ingestion Rate: $(( (END - START) / 10 )) EPS"
```

---

### 3. `curl` (Elasticsearch Aggregation API) — Query Incident Statistics
**Purpose:** Fetch total alert count and severity breakdown from the Elasticsearch SIEM index.
```bash
curl -k -u elastic:YOUR_PASS -X GET "https://localhost:9200/.alerts-security*/_count?pretty"
```

---

### 4. `jq` — Top 10 Triggered Alert Signatures
**Purpose:** Group and rank the highest volume detection signatures to measure alert noise and tuning effectiveness.
```bash
cat /var/ossec/logs/alerts/alerts.json | jq -r '.rule.description' | sort | uniq -c | sort -rn | head -n 10
```

---

### 5. `jq` — MITRE ATT&CK Tactic Distribution Metric
**Purpose:** Calculate percentage distribution of alerts mapped across MITRE ATT&CK tactics.
```bash
cat /var/ossec/logs/alerts/alerts.json | jq -r '.rule.mitre.tactic[]?' | sort | uniq -c | sort -rn
```

---

### 6. `grafana-server` — SOC Metrics & Dashboard Visualizer
**Purpose:** Run Grafana to visualize time-series metrics, incident queues, and analyst SLA performance.
```bash
sudo apt install -y grafana
sudo systemctl enable --now grafana-server
# Access Web UI: http://localhost:3000 (admin / admin)
```

---

### 7. `awk` — Hourly Incident Distribution Profiler
**Purpose:** Extract hour-by-hour event distribution from log files to optimize SOC shift staffing.
```bash
awk '{print $3}' /var/log/auth.log | cut -d: -f1 | sort | uniq -c
```

---

### 8. `iostat` — SIEM Storage Disk I/O Metric Monitor
**Purpose:** Measure write throughput, IOPS, and disk wait times on high-volume SIEM storage partitions.
```bash
sudo apt install -y sysstat
iostat -xz 1 5
```

---

### 9. `vmstat` — System Memory & CPU Health Metric
**Purpose:** Track system memory paging, CPU user/system ratios, and interrupt rates on central SOC nodes.
```bash
vmstat 2 5
```

---

### 10. `nethogs` — Per-Process Ingestion Bandwidth Monitor
**Purpose:** Identify which log shipper process is consuming network bandwidth into the SIEM collector.
```bash
sudo apt install -y nethogs
sudo nethogs eth0
```

---

### 11. `dstat` — Real-Time Resource Correlation Tool
**Purpose:** Correlate CPU, disk, network, and system load simultaneously during high-volume security incidents.
```bash
sudo apt install -y dstat
dstat -cdngy 2
```

---

### 12. `gnuplot` — Terminal-Based Graphical Trend Charts
**Purpose:** Plot quick incident trend graphs directly within the Kali terminal console.
```bash
sudo apt install -y gnuplot
gnuplot -e "set terminal dumb; plot sin(x)"
```

---

### 13. `matplotlib` — Generate High-Resolution KPI Charts
**Purpose:** Programmatically render PNG charts for executive management reporting.
```bash
pip install matplotlib --break-system-packages
python3 -c "
import matplotlib.pyplot as plt
plt.bar(['Tier 1', 'Tier 2', 'Tier 3'], [120, 35, 8], color=['green', 'orange', 'red'])
plt.title('Incidents Resolved by Tier (Monthly)')
plt.savefig('/tmp/tier_resolution.png')
print('Chart saved.')
"
```

---

### 14. Wazuh API — Query Active Agent Connectivity Stats
**Purpose:** Programmatically retrieve agent health and connection status metrics from the Wazuh manager API.
```bash
TOKEN=$(curl -u wazuh-wui:YOUR_PASS -k -X POST https://localhost:55000/security/user/authenticate -H "Content-Type: application/json" | jq -r '.data.token')
curl -k -X GET https://localhost:55000/agents/summary/status -H "Authorization: Bearer $TOKEN" | jq .
```

---

### 15. `uptime` — Service Availability KPI
**Purpose:** Measure continuous uptime percentage of the SOC monitoring infrastructure.
```bash
uptime -p
```

---

### 16. `netstat -s` — Network Error & Packet Drop Metrics
**Purpose:** Audit packet buffer overruns, checksum errors, and socket drops on collector interfaces.
```bash
netstat -s | grep -iE 'dropped|error|overflow'
```

---

### 17. `bc` — Calculate False Positive Ratio Formula
**Purpose:** Compute False Positive Ratio percentage from total alerts and confirmed true positives.
```bash
TOTAL_ALERTS=2500
FALSE_POSITIVES=2350
echo "scale=2; ($FALSE_POSITIVES / $TOTAL_ALERTS) * 100" | bc
```

---

### 18. `column -t` — Format Tabular Metric Reports
**Purpose:** Pretty-print space-delimited metrics into aligned tables for command-line executive briefings.
```bash
printf "Metric Current_Value Target_SLA\nMTTD 12_Mins <15_Mins\nMTTR 45_Mins <60_Mins\nAvailability 99.9%% >99.5%%\n" | column -t
```

---

### 19. `date` — Normalizing Timestamps for SLA Timing
**Purpose:** Convert UTC and epoch timestamps into human-readable local time for audit reports.
```bash
date -d @1620000000 +"%Y-%m-%d %H:%M:%S"
```

---

### 20. `logrotate` — Verify Log Storage Compliance
**Purpose:** Check log rotation compliance to ensure logs are preserved without exceeding storage quotas.
```bash
sudo logrotate -v -d /etc/logrotate.d/rsyslog
```

---
*SOC Command Reference - Class 13*
