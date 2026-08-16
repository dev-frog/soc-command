# Module 19: Executive Communication, Budget Planning, Resource Management & SOC Roadmap
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for executive metric generation, budget and log capacity forecasting, chart plotting, presentation slide generation, and high-level briefing automation on Kali Linux.

---

### 1. `python3` (Executive Performance Chart Generator)
**Purpose:** Generate dual-axis bar and line charts showing total incident reduction alongside MTTD improvements for C-suite briefings.
```bash
cat << 'EOF' > /tmp/executive_chart.py
import matplotlib.pyplot as plt
months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"]
incidents = [45, 38, 52, 29, 22, 18]
mttd = [35, 30, 24, 18, 14, 11]
fig, ax1 = plt.subplots(figsize=(8, 4))
ax1.set_xlabel('Month')
ax1.set_ylabel('Total Incidents', color='tab:red')
ax1.bar(months, incidents, color='tab:red', alpha=0.6)
ax2 = ax1.twinx()
ax2.set_ylabel('MTTD (Minutes)', color='tab:blue')
ax2.plot(months, mttd, color='tab:blue', marker='o', linewidth=2)
plt.title('SOC Performance & Incident Reduction Trend (Q1-Q2)')
plt.tight_layout()
plt.savefig('/tmp/executive_report_chart.png', dpi=300)
print('Chart rendered to /tmp/executive_report_chart.png')
EOF
python3 /tmp/executive_chart.py
```

---

### 2. `pandas` — Process Monthly Incident Datasets
**Purpose:** Aggregate monthly incident data, calculate percent changes, and export executive tables to CSV.
```bash
pip install pandas --break-system-packages
python3 -c "
import pandas as pd
data = {'Month': ['Jan', 'Feb', 'Mar'], 'Incidents': [45, 38, 29], 'SLA_Met_%': [92.5, 96.0, 99.1]}
df = pd.DataFrame(data)
df.to_csv('/tmp/executive_summary.csv', index=False)
print('Summary CSV exported.')
"
```

---

### 3. `marp` — Markdown to Executive Presentation Slide Decks
**Purpose:** Compile Markdown presentation files into HTML and PDF slide decks for executive board meetings.
```bash
sudo npm install -g @marp-team/marp-cli
marp /opt/soc-roadmap/executive_presentation.md --pdf -o /tmp/SOC_Roadmap_Q3.pdf
```

---

### 4. `pandoc` (Beamer Mode) — Compile PDF Presentation Slides
**Purpose:** Transform Markdown files directly into professional LaTeX Beamer presentation slides.
```bash
sudo apt install -y pandoc
pandoc /opt/soc-roadmap/presentation.md -t beamer -o /tmp/Executive_Briefing.pdf
```

---

### 5. `wc -l` — Ingestion Volume & EPS License Cost Estimator
**Purpose:** Calculate average daily log volume to forecast SIEM license and cloud ingestion costs.
```bash
DAILY_LINES=$(wc -l < /var/log/syslog)
GB_ESTIMATE=$(echo "scale=2; ($DAILY_LINES * 250) / (1024 * 1024 * 1024)" | bc)
echo "Estimated Daily Ingestion: $GB_ESTIMATE GB/day"
```

---

### 6. `df -h` — Storage Capacity & Budget Retention Forecasting
**Purpose:** Measure storage consumption trends to project hot/cold storage expansion budgets.
```bash
df -h /var/log /var/lib/elasticsearch
```

---

### 7. `du -sh` — Cost Allocation by Department Log Source
**Purpose:** Measure disk consumption per log directory to allocate SIEM infrastructure costs to specific departments.
```bash
sudo du -sh /var/log/* | sort -hr | head -n 10
```

---

### 8. `sar` — System Activity Reporting for Long-Term Capacity Planning
**Purpose:** Analyze CPU and memory utilization trends over the past 30 days to justify server upgrade budgets.
```bash
sudo apt install -y sysstat
sar -u 1 5
```

---

### 9. `curl` — Query SIEM Dashboard Summary Statistics
**Purpose:** Fetch total alert counts directly from Elasticsearch API for executive KPI rollups.
```bash
curl -k -u elastic:YOUR_PASS -X GET "https://localhost:9200/.alerts-security*/_count" | jq .count
```

---

### 10. `jq` — Extract KPI Figures for Executive Summary
**Purpose:** Parse SIEM cluster health and alert metrics into executive bullet points.
```bash
curl -k -u elastic:YOUR_PASS "https://localhost:9200/_cluster/health" | jq '{Status: .status, Nodes: .number_of_nodes, Active_Shards: .active_shards}'
```

---

### 11. `column -t` — Format Executive Budget Projection Tables
**Purpose:** Format financial and resource allocation tables for inclusion in command-line briefings.
```bash
printf "Category 2026_Budget Projected_Cost Variance\nSIEM_Licensing \$45,000 \$42,000 -\$3,000\nStorage_HW \$20,000 \$22,500 +\$2,500\nTraining \$15,000 \$14,000 -\$1,000\n" | column -t
```

---

### 12. `libreoffice` (Headless Mode) — Convert DOCX/ODT to PDF
**Purpose:** Automate the conversion of management reports into clean PDF documents from the command line.
```bash
sudo apt install -y libreoffice
libreoffice --headless --convert-to pdf /tmp/SOC_Annual_Report.docx --outdir /tmp/
```

---

### 13. `gnuplot` — Quick Visual Trend Plotting in Terminal
**Purpose:** Render visual incident and capacity trend graphs directly in the shell.
```bash
gnuplot -e "set terminal dumb; plot [1:12] 50 - 3*x title 'Incident Rate'"
```

---

### 14. `bc` (Financial Math Engine) — Annualized Loss Expectancy (ALE)
**Purpose:** Compute Single Loss Expectancy (SLE), Annual Rate of Occurrence (ARO), and Annualized Loss Expectancy (ALE).
```bash
SLE=15000
ARO=0.4
echo "scale=2; $SLE * $ARO" | bc -l
```

---

### 15. `weasyprint` — Render Polished HTML Executive Reports into PDF
**Purpose:** Convert styled HTML/CSS performance dashboards into publication-quality PDF executive reports.
```bash
pip install weasyprint --break-system-packages
weasyprint /tmp/executive_dashboard.html /tmp/Executive_SOC_Report.pdf
```

---

### 16. `tar` — Bundle Quarterly Executive Review Archives
**Purpose:** Package all quarterly KPI charts, audit logs, and reports into an encrypted archive.
```bash
tar -czvf /tmp/Q2_Executive_Package.tar.gz /tmp/*.png /tmp/*.csv /tmp/*.pdf
```

---

### 17. `gpg` — Cryptographically Encrypt Executive Briefings
**Purpose:** Securely encrypt confidential executive roadmap and financial budget documents.
```bash
gpg -c --cipher-algo AES256 /tmp/Q2_Executive_Package.tar.gz
```

---

### 18. `mailx` — Scheduled Dispatch of Executive Briefings
**Purpose:** Dispatch scheduled weekly and monthly executive status summaries directly to C-level stakeholders.
```bash
echo "Attached is the Monthly SOC Operational Report and KPI Dashboard." | mailx -s "Monthly SOC Executive Report" -a /tmp/Executive_SOC_Report.pdf ciso@organization.com
```

---

### 19. `date` — Financial Quarter & Fiscal Year Normalization
**Purpose:** Calculate date ranges for quarterly and fiscal year budget reporting intervals.
```bash
echo "Reporting Period: $(date -d '3 months ago' +%B) to $(date +%B) $(date +%Y)"
```

---

### 20. `tree` — Visualize Executive Documentation Repository
**Purpose:** Display organizational directory structure of the executive roadmap and strategy archives.
```bash
tree /opt/soc-roadmap/ -L 2
```

---
*SOC Command Reference - Class 19*
