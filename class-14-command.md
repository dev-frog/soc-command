# Module 14: Compliance & Regulatory Frameworks (ISO 27001, NIST CSF, PCI DSS, CIS)
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for automated compliance auditing, Security Configuration Assessment (SCA), CIS Benchmarks, OpenSCAP evaluation, and cryptographic compliance checks on Kali Linux.

---

### 1. `oscap` — OpenSCAP Automated Compliance Evaluation
**Purpose:** Execute standardized XCCDF security profile audits against Linux systems and generate interactive HTML reports.
```bash
sudo apt install -y libopenscap8 ssg-debian ssg-debderived
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  --results /tmp/cis_results.xml \
  --report /tmp/cis_compliance_report.html \
  /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml
```

---

### 2. `lynis` (Compliance Mode) — ISO 27001 & PCI-DSS Auditing
**Purpose:** Run automated system hardening and regulatory compliance audits against PCI-DSS and ISO 27001 standards.
```bash
sudo apt install -y lynis
sudo lynis audit system --compliance ISO27001,PCI-DSS --report-file /tmp/lynis_compliance.dat
```

---

### 3. `testssl.sh` — PCI-DSS SSL/TLS Cryptographic Compliance
**Purpose:** Verify that HTTPS services meet PCI-DSS 4.0 requirements (no SSLv3, TLS 1.0, or TLS 1.1).
```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /tmp/testssl
/tmp/testssl/testssl.sh --pci https://target.organization.local
```

---

### 4. `sslyze` — SSL/TLS Protocol & Cipher Suite Compliance Audit
**Purpose:** Verify that servers enforce forward secrecy (ECDHE/DHE) and strong encryption ciphers for compliance.
```bash
sudo apt install -y sslyze
sslyze --regular target.organization.local:443
```

---

### 5. `checkov` — Infrastructure as Code (IaC) Compliance Scanner
**Purpose:** Audit Terraform templates, Kubernetes manifests, and Dockerfiles for CIS & NIST CSF compliance.
```bash
pip install checkov --break-system-packages
checkov -d /opt/infrastructure_code/ --framework terraform
```

---

### 6. `trivy` (Compliance Flag) — Container Compliance Audit
**Purpose:** Audit container images against specific CIS and NSA/CISA compliance profiles.
```bash
sudo apt install -y trivy
trivy image --compliance docker-cis nginx:latest
```

---

### 7. Wazuh SCA — Security Configuration Assessment
**Purpose:** Review host Security Configuration Assessment (SCA) results for CIS benchmark score on the Wazuh agent.
```bash
sudo cat /var/ossec/logs/ossec.log | grep -i "sca"
```

---

### 8. `debsecan` — Package Security Vulnerability Compliance
**Purpose:** Audit all installed operating system packages against the Debian Security Advisory (DSA) database.
```bash
sudo apt install -y debsecan
debsecan --suite=bookworm --only-fixed
```

---

### 9. `rkhunter` — File Integrity & System Binary Verification
**Purpose:** Verify hashes of system binaries against known-good operating system package databases.
```bash
sudo apt install -y rkhunter
sudo rkhunter --check --skip-keypress --report-warnings-only
```

---

### 10. `auditctl` — Verify Required Compliance Kernel Audit Rules
**Purpose:** Confirm that mandatory compliance auditing rules (file changes, privilege escalations) are actively loaded.
```bash
sudo auditctl -l
```

---

### 11. `aureport` (Authentication Report) — Access Control Audit
**Purpose:** Generate compliance summary reports of all user logins, authentication failures, and credential changes.
```bash
sudo aureport --auth --summary
```

---

### 12. `aureport` (System Call Report) — System Integrity Audit
**Purpose:** Generate summary reports of sensitive system calls executed on the monitored host.
```bash
sudo aureport --syscall --summary
```

---

### 13. `find` — Audit SUID/SGID Permissions (Least Privilege)
**Purpose:** Identify all SUID/SGID binaries on the host to verify compliance with the principle of least privilege.
```bash
find / -perm -4000 -type f -exec ls -ld {} + 2>/dev/null
```

---

### 14. `chage` — Password Policy & Aging Compliance Audit
**Purpose:** Verify that user accounts comply with mandatory maximum password age and minimum length regulations.
```bash
for user in $(cut -f1 -d: /etc/passwd); do echo "User: $user"; sudo chage -l $user 2>/dev/null | grep -i "password expires"; done
```

---

### 15. `umask` — Default File Creation Mask Verification
**Purpose:** Verify default umask is configured to `027` or stricter per CIS Benchmark recommendations.
```bash
umask
```

---

### 16. `ss` — Verify Authorized Network Listening Services
**Purpose:** Verify that only strictly authorized, documented services are listening on network interfaces.
```bash
ss -tulpn | grep LISTEN
```

---

### 17. `aide` — Advanced Intrusion Detection Environment (FIM)
**Purpose:** Initialize and check baseline file integrity database for PCI-DSS section 11.5 requirements.
```bash
sudo apt install -y aide
sudo aideinit
sudo aide --check
```

---

### 18. `docker-bench-security` — CIS Docker Benchmark Audit
**Purpose:** Audit Docker daemon configuration, container images, and host security against the CIS Docker Benchmark.
```bash
git clone https://github.com/docker/docker-bench-security.git /tmp/docker-bench
cd /tmp/docker-bench && sudo sh docker-bench-security.sh
```

---

### 19. `gitleaks` — Secret Leakage & GDPR Compliance Audit
**Purpose:** Audit git repositories to ensure sensitive personal data (PII), private keys, and API tokens are not exposed.
```bash
sudo apt install -y gitleaks
gitleaks detect --source /opt/company-repo/ --verbose
```

---

### 20. `df -h` / Partition Separation Audit (CIS Requirement)
**Purpose:** Verify that `/var`, `/tmp`, and `/var/log` reside on separate partitions to prevent denial-of-service compliance failures.
```bash
df -h | grep -E 'Filesystem|/tmp|/var'
```

---
*SOC Command Reference - Class 14*
