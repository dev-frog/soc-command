# Module 03: Building and Managing a SOC Team, Shift Management, SLA & KPI
### 20 Tools & Commands for Kali Linux (Workforce Planning Workshop)

This guide provides 20 essential commands and tools for managing SOC analyst workstations, recording terminal sessions for shift handovers, auditing remote analyst logins, monitoring uptime SLAs, and operating multi-pane consoles on Kali Linux.

---

### 1. `script` — Analyst Session Recording for Shift Handover & QA
**Purpose:** Record all terminal commands, outputs, and keystrokes during an analyst shift into a timestamped file for quality review and shift transition.
```bash
# Start recording shift session with timing data
script -a -t=2> /tmp/analyst_shift_timing.log /tmp/analyst_shift_session.log
# (Analyst carries out triage and investigation...)
exit
```

---

### 2. `scriptreplay` — Real-Time Session Playback
**Purpose:** Replay an analyst's terminal investigation in real-time for training, incident audit, or shift handover briefing.
```bash
scriptreplay /tmp/analyst_shift_timing.log /tmp/analyst_shift_session.log
```

---

### 3. `tmux` — Multi-Window SOC Monitoring Console
**Purpose:** Create a persistent terminal dashboard with split panes for simultaneous log tailing, network watching, and triage.
```bash
# Start a new persistent SOC monitoring session
tmux new -s soc-shift-monitor

# Useful keybindings in tmux:
# Ctrl+b then % : Split vertically
# Ctrl+b then " : Split horizontally
# Ctrl+b then d : Detach session (leaves running in background)
# Attach back later: tmux attach -t soc-shift-monitor
```

---

### 4. `screen` — Detachable Background Sessions for Long Jobs
**Purpose:** Run long-running scans or log collection tasks that persist even if the analyst's SSH connection drops.
```bash
screen -S long-scan-task
# To detach: Ctrl+a then d
# To reattach: screen -r long-scan-task
```

---

### 5. `last` — Shift Login & Authentication History
**Purpose:** Audit which SOC team members logged into the central analysis servers, from which IP addresses, and for how long.
```bash
last -a -F | head -n 25
```

---

### 6. `w` / `who` — Active Analyst Session Tracking
**Purpose:** Display currently logged-in analysts, their idle times, and the active commands they are executing.
```bash
w
who -u
```

---

### 7. `sudo journalctl -u ssh` — Remote Access Auditing
**Purpose:** Inspect SSH authentication logs to verify authorized analyst logins and detect unauthorized access attempts.
```bash
sudo journalctl -u ssh -S "1 hour ago" --no-pager
```

---

### 8. `htop` — Real-Time SOC Server Resource Monitor
**Purpose:** Monitor CPU, RAM, and per-process resource utilization on the SOC server.
```bash
sudo apt install -y htop
htop
```

---

### 9. `glances` — Comprehensive System Telemetry
**Purpose:** Monitor system CPU, memory, disk I/O, network traffic, and running Docker containers in a single console.
```bash
sudo apt install -y glances
glances
```

---

### 10. `faillog` — Failed Login Tracking & Account Lockouts
**Purpose:** Track failed authentication attempts across all SOC analyst user accounts.
```bash
sudo faillog -a
```

---

### 11. `chage` — Credential Expiration & Password Policy Audit
**Purpose:** Audit account expiration, maximum password age, and warning periods for SOC team member accounts.
```bash
sudo chage -l analyst_tier1
```

---

### 12. `auditctl` — Privilege Escalation Monitoring (Tier-3 / Root)
**Purpose:** Set an audit watch rule on the `/etc/sudoers` file to detect changes in analyst administrative privileges.
```bash
sudo auditctl -w /etc/sudoers -p wa -k sudoers_priv_change
sudo ausearch -k sudoers_priv_change --format text
```

---

### 13. `wall` — Emergency Broadcast Alert to All Logged-In Analysts
**Purpose:** Send an urgent incident notification message to all active terminal sessions across the SOC team.
```bash
echo "CRITICAL: P1 Ransomware Incident declared. Shift handover meeting starting in 5 mins." | sudo wall
```

---

### 14. `write` / `mesg` — Analyst-to-Analyst Direct Terminal Messaging
**Purpose:** Direct secure terminal communication between Tier 1 triage and Tier 2 incident handlers.
```bash
# Enable receiving messages:
mesg y

# Send message to another analyst logged into pts/2:
write analyst_tier2 pts/2
```

---

### 15. `crontab` — Shift Scheduled Automation Audit
**Purpose:** Verify and manage scheduled scripts for hourly log rotation, report generation, and automated health checks.
```bash
sudo crontab -l
```

---

### 16. `logrotate` — Log Retention Management for SLA Compliance
**Purpose:** Verify and force log rotation policies to guarantee logs meet compliance retention windows without filling disks.
```bash
sudo logrotate -d /etc/logrotate.conf   # Dry-run debug mode
```

---

### 17. `timedatectl` — Clock Synchronization & NTP Verification
**Purpose:** Ensure all SOC systems and analyst terminals are accurately synchronized to UTC/local time for forensic log correlation.
```bash
timedatectl status
```

---

### 18. `nc` (Netcat) — Service Port Availability & SLA Probing
**Purpose:** Rapidly verify if core SOC ingestion ports (Elasticsearch 9200, Syslog 514, Wazuh 1514) are responsive.
```bash
nc -zvw3 127.0.0.1 9200
```

---

### 19. `uptime` — System Availability & Uptime SLA Monitoring
**Purpose:** Measure continuous server uptime and 1-, 5-, and 15-minute system load averages.
```bash
uptime
```

---

### 20. `logger` — Generate Test Syslog Events for Readiness Drills
**Purpose:** Inject simulated security events into the local syslog daemon to test analyst detection and shift response times.
```bash
logger -p auth.alert "TEST_SECURITY_ALERT: Simulated unauthorized root access attempt for shift drill"
```

---
*SOC Command Reference - Class 03*
