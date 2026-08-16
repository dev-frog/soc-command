# Module 02: SOC Strategy, Operating Models, Service Catalog & SOC Maturity Model
### 20 Tools & Commands for Kali Linux (SOC Capability Assessment)

This guide provides 20 essential commands and tools for asset inventorying, identifying open services, assessing organizational capabilities, and profiling attack surfaces on Kali Linux.

---

### 1. `nmap` (Full Service Cataloging & OS Fingerprinting)
**Purpose:** Scan all 65,535 TCP ports to discover running software versions, listening services, and operating system types.
```bash
nmap -sS -sV -O -p- --open -T4 192.168.1.50 -oA /tmp/service_catalog_report
```

---

### 2. `amass` — External Attack Surface Mapping
**Purpose:** In-depth open-source asset discovery and external organizational attack surface inventorying.
```bash
sudo apt install -y amass
amass enum -d target.organization.com -o /tmp/attack_surface_domains.txt
```

---

### 3. `sublist3r` — Subdomain Enumeration for Asset Inventory
**Purpose:** Fast enumeration of subdomains across multiple public search engines and SSL certificate transparency logs.
```bash
sudo apt install -y sublist3r
sublist3r -d target.organization.com -o /tmp/subdomains.txt
```

---

### 4. `whatweb` — Web Application Technology Profiler
**Purpose:** Detect Content Management Systems (CMS), frameworks, web servers, embedded analytics, and JavaScript libraries.
```bash
sudo apt install -y whatweb
whatweb -v -a 3 https://target.organization.com
```

---

### 5. `wafw00f` — Web Application Firewall (WAF) Discovery
**Purpose:** Determine if an organizational web asset is protected by a WAF (Cloudflare, AWS WAF, Imperva, ModSecurity).
```bash
sudo apt install -y wafw00f
wafw00f https://target.organization.com
```

---

### 6. `snmpwalk` — SNMP Infrastructure Profiling
**Purpose:** Query network switches, routers, and firewalls via SNMP to extract system descriptions and interface statistics.
```bash
sudo apt install -y snmp
snmpwalk -v 2c -c public 192.168.1.1 1.3.6.1.2.1.1
```

---

### 7. `ss` — Host Listener & Socket Inventory
**Purpose:** Audit all internal listening TCP/UDP sockets and identify running process IDs on internal servers.
```bash
ss -tulpn
```

---

### 8. `lsof` — Open Network Files & Process Inspection
**Purpose:** List all active network connections and matching executing processes.
```bash
sudo lsof -i -P -n | grep LISTEN
```

---

### 9. `dnsenum` — DNS Server Capability & Zone Transfer Audit
**Purpose:** Enumerate DNS records (A, MX, NS, TXT) and test for vulnerable misconfigured DNS zone transfers (AXFR).
```bash
dnsenum target.organization.com
```

---

### 10. `theHarvester` — Organizational OSINT Attack Surface Profiling
**Purpose:** Gather public emails, employee names, subdomains, and IP ranges from public data sources.
```bash
sudo apt install -y theharvester
theHarvester -d target.organization.com -b all -l 200
```

---

### 11. `recon-ng` — Modular Reconnaissance Framework
**Purpose:** Structured intelligence gathering and asset capability profiling in an interactive console.
```bash
sudo apt install -y recon-ng
recon-ng
```

---

### 12. `enum4linux-ng` — Windows & SMB Domain Service Profiling
**Purpose:** Extract domain users, shares, password policies, and OS versions from Windows and Samba domain controllers.
```bash
sudo apt install -y enum4linux-ng
enum4linux-ng -A 192.168.1.10 -oJ /tmp/smb_service_inventory.json
```

---

### 13. `nikto` — Web Server Baseline & Header Assessment
**Purpose:** Scan web servers for outdated server versions, missing security headers, and dangerous default files.
```bash
nikto -h http://192.168.1.50 -p 80,443 -Format htm -output /tmp/nikto_baseline.html
```

---

### 14. `sslscan` — SSL/TLS Protocol & Cipher Capability Assessment
**Purpose:** Audit supported SSL/TLS protocols (TLS 1.0, 1.1, 1.2, 1.3) and weak cryptographic cipher suites.
```bash
sudo apt install -y sslscan
sslscan https://target.organization.com
```

---

### 15. `cisco-torch` — Network Infrastructure Device Fingerprinting
**Purpose:** Scan and fingerprint Cisco routers, switches, and network appliances via Telnet, SSH, SNMP, and HTTP.
```bash
cisco-torch -A 192.168.1.1
```

---

### 16. `onesixtyone` — High-Speed SNMP Scanner
**Purpose:** Fast scanning of entire IP blocks to identify SNMP-enabled assets and active community strings.
```bash
sudo apt install -y onesixtyone
onesixtyone 192.168.1.0/24 public
```

---

### 17. `rpcinfo` — RPC Service Capability Discovery
**Purpose:** Query internal Linux/UNIX servers for registered RPC programs (NFS, mountd, portmapper).
```bash
rpcinfo -p 192.168.1.50
```

---

### 18. `smbclient` — SMB Share Visibility & Capability Probe
**Purpose:** List available network shares on file servers to assess storage visibility.
```bash
smbclient -N -L //192.168.1.10
```

---

### 19. `dig` (Trace Mode) — Authoritative DNS Path Discovery
**Purpose:** Trace DNS queries from root nameservers down to authoritative nameservers to understand DNS architecture.
```bash
dig +trace target.organization.com
```

---

### 20. `jq` — JSON Service Catalog Normalizer
**Purpose:** Parse Nmap or masscan JSON output into a clean tabular service catalog for SOC maturity assessment.
```bash
cat /tmp/smb_service_inventory.json | jq '.shares[] | {name: .name, comment: .comment}'
```

---
*SOC Command Reference - Class 02*
