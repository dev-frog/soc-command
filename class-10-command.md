# Module 10: Vulnerability Management, Risk Assessment & Patch Management
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for vulnerability scanning, CVE verification, web app security assessments, container auditing, and patch simulation on Kali Linux.

---

### 1. `gvm-setup` — Initialize OpenVAS Vulnerability Scanner
**Purpose:** Download Network Vulnerability Tests (NVTs), SCAP feeds, and configure the PostgreSQL vulnerability database.
```bash
sudo apt update && sudo apt install -y gvm
sudo gvm-setup
```

---

### 2. `gvm-start` / `gvm-stop` — Manage OpenVAS Daemons
**Purpose:** Start or stop the Greenbone Vulnerability Management scanner daemons and web portal.
```bash
sudo gvm-start
# Access at: https://127.0.0.1:9392
sudo gvm-stop
```

---

### 3. `gvmd` — OpenVAS Administrator & User Management
**Purpose:** Reset administrator credentials and query registered user accounts for the scanner.
```bash
sudo gvmd --user=admin --new-password="SecurePassword2026!"
sudo gvmd --get-users
```

---

### 4. `greenbone-feed-sync` — Synchronize Vulnerability Feeds
**Purpose:** Update latest vulnerability signatures, CVE mappings, and CERT advisory feeds.
```bash
sudo greenbone-feed-sync --type GVMD_DATA
sudo greenbone-feed-sync --type SCAP
sudo greenbone-feed-sync --type CERT
```

---

### 5. `nuclei` — Fast Template-Based Vulnerability Scanner
**Purpose:** Scan targets against thousands of community-curated vulnerability templates for zero-days and critical CVEs.
```bash
sudo apt install -y nuclei
nuclei -update-templates
nuclei -u https://target.organization.local -severity critical,high -o /tmp/nuclei_vulns.txt
```

---

### 6. `nikto` — Web Server Vulnerability & Misconfiguration Scanner
**Purpose:** Scan web servers for outdated software versions, dangerous default files, and missing security headers.
```bash
nikto -h http://192.168.1.50 -p 80,443 -C all -Format htm -output /tmp/nikto_report.html
```

---

### 7. `lynis` — Linux Host Security & Hardening Audit
**Purpose:** Audit Linux operating system configurations, file permissions, and generate a system hardening score.
```bash
sudo apt install -y lynis
sudo lynis audit system --quick --report-file /tmp/lynis_report.dat
```

---

### 8. `trivy` (Filesystem Mode) — Scan Codebase & Application Dependencies
**Purpose:** Scan application source code and software packages for known CVEs and vulnerable libraries.
```bash
sudo apt install -y trivy
trivy fs /opt/soc-app/ --severity HIGH,CRITICAL
```

---

### 9. `trivy` (Image Mode) — Container Image Vulnerability Scanner
**Purpose:** Inspect Docker container images for outdated packages and vulnerable base OS layers.
```bash
trivy image nginx:1.20
```

---

### 10. `searchsploit` — Exploit-DB Offline CVE Query Tool
**Purpose:** Query offline Exploit Database for public proof-of-concept exploits matching discovered CVEs.
```bash
sudo apt install -y exploitdb
searchsploit --cve CVE-2021-44228
searchsploit "Apache 2.4.49"
```

---

### 11. `nmap` (Vulnerability Scripts) — Targeted Service Vulnerability Scan
**Purpose:** Execute Nmap Vulnerability Engine scripts against open ports on target servers.
```bash
nmap -sV --script vuln -p 80,443,445 192.168.1.50 -oN /tmp/nmap_vuln_scan.txt
```

---

### 12. `testssl.sh` — SSL/TLS Cryptographic Vulnerability Audit
**Purpose:** Test for critical cryptographic vulnerabilities such as Heartbleed, POODLE, ROBOT, and DROWN.
```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /tmp/testssl
/tmp/testssl/testssl.sh --vulnerable https://target.organization.local
```

---

### 13. `sslyze` — Fast SSL/TLS Configuration Analyzer
**Purpose:** Analyze supported cipher suites, certificate expiration dates, and insecure renegotiation settings.
```bash
sudo apt install -y sslyze
sslyze target.organization.local:443
```

---

### 14. `wpscan` — WordPress CMS Vulnerability Scanner
**Purpose:** Scan WordPress web assets for vulnerable core versions, plugins, and themes.
```bash
sudo apt install -y wpscan
wpscan --url https://blog.organization.local --enumerate vp,vt,u --api-token "YOUR_WPSCAN_TOKEN"
```

---

### 15. `debsecan` — Debian / Kali Package Security Analyzer
**Purpose:** Evaluate currently installed packages against the Debian Security Advisory vulnerability database.
```bash
sudo apt install -y debsecan
debsecan --suite=bookworm --only-fixed
```

---

### 16. `apt-get` (Simulation Mode) — Patch Availability Simulation
**Purpose:** Simulate package upgrades to identify available security patches without altering system state.
```bash
sudo apt update
apt-get --just-print upgrade | grep -i security
```

---

### 17. `unattended-upgrades` — Automated Security Patch Deployment
**Purpose:** Configure automated background installation of critical security patches on Linux servers.
```bash
sudo apt install -y unattended-upgrades
sudo unattended-upgrade --dry-run --debug
```

---

### 18. `checkov` — Infrastructure as Code (IaC) Vulnerability Audit
**Purpose:** Scan Terraform, Dockerfiles, and Kubernetes manifests for security flaws before deployment.
```bash
pip install checkov --break-system-packages
checkov -d /opt/infrastructure-code/
```

---

### 19. `grype` — Software Composition Analysis & Vulnerability Scanner
**Purpose:** Fast vulnerability scanning for container images and filesystem directories.
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
grype dir:/opt/target_application/
```

---

### 20. `chkrootkit` — Check System for Known Rootkits & Vulnerable Binaries
**Purpose:** Verify local host binaries against known rootkit signatures and modified system calls.
```bash
sudo apt install -y chkrootkit
sudo chkrootkit
```

---
*SOC Command Reference - Class 10*
