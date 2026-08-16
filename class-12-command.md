# Module 12: Security Controls: EDR, XDR, Firewall, WAF, IDS/IPS, SOAR & SIEM Integration
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for configuring defensive security controls: host firewalls (`nftables`/`iptables`), automated intrusion prevention (`fail2ban`), EDR agents (Wazuh), AppArmor profiles, and network security engines on Kali Linux.

---

### 1. `nftables` — Next-Gen Stateful Host Firewall
**Purpose:** Configure stateful packet filtering, drop invalid traffic, and allow only authorized SOC management connections.
```bash
sudo apt install -y nftables
sudo systemctl enable --now nftables
sudo nft add table inet filter
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
sudo nft add rule inet filter input ct state established,related accept
sudo nft add rule inet filter input iif lo accept
sudo nft add rule inet filter input tcp dport 22 accept
```

---

### 2. `iptables` — Netfilter Packet Filter & Rate Limiting
**Purpose:** Rate-limit SSH brute force attempts at the packet level.
```bash
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --rttl --name SSH -j DROP
```

---

### 3. `fail2ban-client` — Automated Intrusion Prevention
**Purpose:** Automatically ban IP addresses exceeding failure thresholds on SSH, HTTP, or custom SIEM log triggers.
```bash
sudo apt install -y fail2ban
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd banip 198.51.100.50
```

---

### 4. `suricata` (Inline IPS Mode) — Active Packet Dropping
**Purpose:** Run Suricata with NFQueue in inline mode to actively drop packets matching exploit signatures.
```bash
sudo suricata -q 0 -c /etc/suricata/suricata.yaml -D
```

---

### 5. `suricata-update` — Signature Feed Management
**Purpose:** Manage and update intrusion prevention rule sources and verify syntax before loading.
```bash
sudo suricata-update
sudo suricata-update list-sources
```

---

### 6. `zeek` — Behavioral Network Security Monitoring
**Purpose:** Deploy Zeek for protocol decoding and extracting connection metadata without signature dependencies.
```bash
sudo zeek -i eth0 local
```

---

### 7. `wazuh-agent` — Endpoint Detection & Response (EDR) Agent
**Purpose:** Enroll and control the Wazuh EDR agent on endpoints for process monitoring, file integrity, and vulnerability detection.
```bash
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent
```

---

### 8. `wazuh-control` — SIEM & XDR Manager Control
**Purpose:** Check operational health of Wazuh SIEM/XDR manager, rule engine, and database modules.
```bash
sudo /var/ossec/bin/wazuh-control status
```

---

### 9. Wazuh Active Response — Automated EDR Remediation
**Purpose:** Trigger automated host containment scripts to block an attacker IP upon rule trigger.
```bash
sudo /var/ossec/active-response/bin/firewall-drop.sh add - 198.51.100.50 1620000000 01
```

---

### 10. `auditd` — Kernel-Level System Call Auditing
**Purpose:** Audit sensitive system calls (`execve`, `ptrace`, `setuid`) for EDR behavioral correlation.
```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -k process_execution
```

---

### 11. `osqueryd` — Continuous Endpoint SQL Daemon
**Purpose:** Run osquery daemon to schedule continuous endpoint telemetry queries and ship to SIEM.
```bash
sudo systemctl enable --now osqueryd
```

---

### 12. `filebeat` — Security Telemetry Log Shipper
**Purpose:** Ship Suricata, Zeek, and Linux authentication logs directly into Elasticsearch / OpenSearch pipelines.
```bash
sudo apt install -y filebeat
sudo filebeat modules enable suricata system
sudo systemctl start filebeat
```

---

### 13. `packetbeat` — Real-Time Network Packet Shipper
**Purpose:** Capture and ship protocol transactions (DNS, HTTP, TLS) from host interfaces to SIEM.
```bash
sudo apt install -y packetbeat
sudo systemctl start packetbeat
```

---

### 14. `auditbeat` — Linux Audit Framework & FIM Shipper
**Purpose:** Monitor file integrity changes on critical system binaries and ship kernel audit events.
```bash
sudo apt install -y auditbeat
sudo auditbeat setup -e
sudo systemctl start auditbeat
```

---

### 15. `snort` — Rule-Based Network Intrusion Detection
**Purpose:** Run Snort IDS to inspect incoming network packets against custom Snort rules.
```bash
sudo apt install -y snort
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

---

### 16. `clamd` — Endpoint Antivirus Daemon
**Purpose:** Run real-time background antivirus scanning daemon for incoming files and attachments.
```bash
sudo apt install -y clamav-daemon
sudo systemctl enable --now clamav-daemon
```

---

### 17. `apparmor_status` — Mandatory Access Control Status
**Purpose:** Verify which security profiles (enforce, complain) are active on applications to prevent privilege escalation.
```bash
sudo apparmor_status
```

---

### 18. `aa-enforce` — Enforce Application Confinement Profiles
**Purpose:** Force an application profile (e.g. Apache or Nginx) into strict enforcement mode to prevent sandbox escapes.
```bash
sudo aa-enforce /etc/apparmor.d/usr.sbin.apache2
```

---

### 19. `sysctl` — Kernel Networking Hardening
**Purpose:** Harden the Linux kernel network stack against IP spoofing, SYN flood attacks, and ICMP redirects.
```bash
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
```

---

### 20. `modsecurity` — Web Application Firewall (WAF) Rule Verification
**Purpose:** Inspect and test ModSecurity Core Rule Set (CRS) configurations on web reverse proxies.
```bash
sudo apache2ctl -M | grep security
```

---
*SOC Command Reference - Class 12*
