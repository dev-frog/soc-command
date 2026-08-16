# Module 18: SOC Auditing, Vendor Management, Third-Party Risk & Security Operations Review
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for auditing cloud security postures, Active Directory trust boundaries (BloodHound), third-party web configurations, vendor SSL certificates, and secret leakage on Kali Linux.

---

### 1. `prowler` — Cloud Security Posture Assessment (AWS / Azure / GCP)
**Purpose:** Audit cloud accounts against CIS Cloud Benchmarks, GDPR, and SOC 2 security compliance controls.
```bash
pip install prowler --break-system-packages
prowler aws --compliance cis_2.0_aws
```

---

### 2. `scoutsuite` — Multi-Cloud Security Auditing Framework
**Purpose:** Perform automated security posture audits of cloud environments and generate an interactive HTML risk report.
```bash
pip install scoutsuite --break-system-packages
scout aws --report-dir /tmp/scout_report/
```

---

### 3. `bloodhound-python` — Active Directory Risk & Posture Ingestion
**Purpose:** Extract users, groups, permissions, and domain trust relationships from Active Directory for risk auditing.
```bash
sudo apt install -y bloodhound-python
bloodhound-python -u 'AuditUser' -p 'Password123' -d corporate.local -ns 192.168.1.10 -c All -o /tmp/ad_audit/
```

---

### 4. `bloodhound` & Neo4j — Visualize Domain Attack Paths & Trust Abuse
**Purpose:** Launch Neo4j database and BloodHound GUI to identify shortest attack paths to Domain Admins.
```bash
sudo apt install -y bloodhound neo4j
sudo systemctl start neo4j
bloodhound &
```

---

### 5. `testssl.sh` — Audit Vendor Web Application Cryptography
**Purpose:** Audit third-party integration endpoints for deprecated SSL/TLS protocols and weak ciphers.
```bash
/tmp/testssl/testssl.sh --full https://vendor-portal.partner.com
```

---

### 6. `sslyze` — Fast Third-Party Endpoint SSL/TLS Audit
**Purpose:** Verify certificate chains, OCSP stapling, and TLS 1.3 support on vendor-managed interfaces.
```bash
sslyze vendor-api.partner.com:443
```

---

### 7. `trufflehog` — Audit Repositories for Leaked Vendor Credentials
**Purpose:** Scan vendor integrations and git repositories for exposed API keys, private certificates, and credentials.
```bash
trufflehog git https://github.com/partner-org/integration-app.git
```

---

### 8. `gitleaks` — Static Secret Scanner
**Purpose:** Detect unencrypted passwords and tokens committed to source code repositories.
```bash
gitleaks detect --source /opt/third-party-code/ --report-path /tmp/leaks.json
```

---

### 9. `enum4linux-ng` — Audit Third-Party SMB & Domain Trust Posture
**Purpose:** Enumerate SMB configurations, anonymous shares, and user enumeration policies on partner servers.
```bash
enum4linux-ng -A 192.168.10.25 -oJ /tmp/vendor_smb_audit.json
```

---

### 10. `nmap` (SSL Certificate Script) — Audit Vendor Certificate Expiry
**Purpose:** Check validity periods and subject alternative names (SANs) on vendor-facing certificates.
```bash
nmap -p 443 --script ssl-cert 192.168.1.0/24 -oN /tmp/vendor_certs.txt
```

---

### 11. `nikto` — Audit Vendor Web Portals for Common Flaws
**Purpose:** Check vendor-hosted web portals for dangerous HTTP methods, missing security headers, and known flaws.
```bash
nikto -h https://vendor-app.partner.com -p 443 -output /tmp/vendor_web_audit.html
```

---

### 12. `checkov` — Audit Vendor Infrastructure as Code (IaC)
**Purpose:** Audit Terraform, Helm charts, and Kubernetes YAML supplied by third-party software vendors.
```bash
checkov -d /opt/vendor-deployment/
```

---

### 13. `trivy` — Audit Third-Party Docker Containers
**Purpose:** Scan container images supplied by external vendors before deploying into production clusters.
```bash
trivy image vendor-registry.io/app:v1.4
```

---

### 14. `whois` — Verify Vendor Domain Ownership & ASN Reputation
**Purpose:** Verify registrant details and IP ownership for third-party cloud infrastructure.
```bash
whois vendor-portal.com | grep -E 'Registrant|Admin Email|OrgName'
```

---

### 15. `dig` — Audit Vendor Email Security Records (SPF / DKIM / DMARC)
**Purpose:** Verify that third-party vendors sending emails on your behalf implement strict DMARC enforcement.
```bash
dig +short TXT partner.com | grep "v=spf1"
dig +short TXT _dmarc.partner.com
```

---

### 16. `nuclei` — Scan Vendor Portals for Known CVEs
**Purpose:** Rapidly scan third-party vendor interfaces for critical known vulnerabilities.
```bash
nuclei -u https://vendor-portal.partner.com -severity critical,high
```

---

### 17. `snmpwalk` — Audit SNMP Security on Third-Party Appliances
**Purpose:** Test for default SNMP community strings (`public`, `private`) on vendor-supplied network hardware.
```bash
snmpwalk -v 2c -c public 192.168.1.254 1.3.6.1.2.1.1.1.0
```

---

### 18. `rpcinfo` — Audit Exposed RPC Services on Partner Links
**Purpose:** Ensure insecure RPC and NFS services are not exposed over site-to-site partner VPN links.
```bash
rpcinfo -p 192.168.10.50
```

---

### 19. `smbclient` — Audit Accessible Vendor Network Shares
**Purpose:** List accessible network shares across third-party VPN interconnects to ensure least-privilege isolation.
```bash
smbclient -N -L //192.168.10.50
```

---

### 20. `hashcat` — Benchmark Password Hashing Strength for Audits
**Purpose:** Test password hash cracking resistance to determine compliance of authentication databases with policy.
```bash
hashcat -b -m 1000
```

---
*SOC Command Reference - Class 18*
