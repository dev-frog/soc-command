# Module 08: Incident Response Framework (NIST), Playbooks & Tabletop Exercise
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for executing the NIST SP 800-61r2 incident response lifecycle: containment, process termination, network socket severing, memory acquisition, and tabletop exercises on Kali Linux.

---

### 1. `iptables` — Emergency Host Network Containment
**Purpose:** Isolate a compromised Linux machine from the network while maintaining SSH access from the SOC analyst station.
```bash
sudo iptables -F
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -A INPUT -s 192.168.1.100 -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -d 192.168.1.100 -p tcp --sport 22 -j ACCEPT
```

---

### 2. `nftables` — Modern Stateful Containment Ruleset
**Purpose:** Apply instant stateful containment rules to block all traffic except established analyst management sessions.
```bash
sudo nft add table inet lockdown
sudo nft add chain inet lockdown inbound { type filter hook input priority 0 \; policy drop \; }
sudo nft add rule inet lockdown inbound ip saddr 192.168.1.100 accept
```

---

### 3. `ss -K` — Sever Active Malicious C2 TCP Connections
**Purpose:** Immediately terminate an active TCP socket connected to an adversary Command & Control (C2) server.
```bash
sudo ss -K dst 198.51.100.23 dport = 4444
```

---

### 4. `ps auxf` — Hierarchical Process Tree Inspection
**Purpose:** View running processes in a tree structure to identify malicious child processes spawned by web servers or shells.
```bash
ps auxf | grep -E 'apache|nginx|bash|python|nc'
```

---

### 5. `lsof` — Inspect Open Sockets & Memory Mappings for Suspicious PID
**Purpose:** Identify all files, sockets, and loaded libraries associated with a suspicious process ID (e.g. PID 1337).
```bash
sudo lsof -p 1337
```

---

### 6. `kill` / `pkill` — Eradicate Malicious Processes
**Purpose:** Forcefully terminate adversary processes and background malware workers.
```bash
sudo kill -9 1337
sudo pkill -f "malicious_payload.py"
```

---

### 7. `fuser` — Kill Processes Accessing a Compromised Port or File
**Purpose:** Identify and kill all processes locking a specific network port or filesystem path.
```bash
sudo fuser -k 4444/tcp
```

---

### 8. `LiME` (Linux Memory Extractor) — Live Volatile RAM Capture
**Purpose:** Compile and load the LiME kernel module to dump complete physical RAM to disk or network for analysis.
```bash
git clone https://github.com/504ensicsLabs/LiME.git /tmp/lime
cd /tmp/lime/src && make
sudo insmod lime-$(uname -r).ko "path=/evidence/ram_dump.lime format=raw"
```

---

### 9. `volatility3` — Memory Forensics: Process Tree Analysis
**Purpose:** Analyze physical memory dumps from Windows/Linux targets to detect hidden processes and injected threads.
```bash
python3 /opt/volatility3/vol.py -f /evidence/memdump.raw windows.pstree
```

---

### 10. `volatility3` — Memory Forensics: Code Injection Detection
**Purpose:** Scan memory pages for unmapped executable code indicating process hollowing or injection.
```bash
python3 /opt/volatility3/vol.py -f /evidence/memdump.raw windows.malfind
```

---

### 11. `volatility3` — Memory Forensics: Network Socket Scan
**Purpose:** Reconstruct active and closed network connections present in memory at the time of capture.
```bash
python3 /opt/volatility3/vol.py -f /evidence/memdump.raw windows.netscan
```

---

### 12. `dd` / `dc3dd` — Disk Evidence Snapshot & Preservation
**Purpose:** Create a bit-for-bit physical disk copy of the compromised system while generating SHA-256 validation hashes.
```bash
sudo dc3dd if=/dev/sda of=/evidence/compromised_host_disk.raw hash=sha256 log=/evidence/imaging_log.txt
```

---

### 13. `lsattr` / `chattr` — Detect & Remove Immutable Rootkit Flags
**Purpose:** Discover and clear immutable file system attributes placed by malware to prevent deletion.
```bash
lsattr /tmp/
sudo chattr -i /tmp/.malicious_rootkit
```

---

### 14. `find` — Identify Files Created or Modified in Last 24 Hours
**Purpose:** Rapidly locate all newly created binaries or modified configuration files during the attack window.
```bash
sudo find /etc /var/www /tmp /bin -type f -mtime -1 -ls
```

---

### 15. `crontab` — Investigate User & System Scheduled Persistence
**Purpose:** Audit scheduled cron jobs across all users to detect persistent adversary trigger mechanisms.
```bash
for user in $(cut -f1 -d: /etc/passwd); do echo "=== $user ==="; sudo crontab -u $user -l 2>/dev/null; done
```

---

### 16. `systemctl` — Investigate Malicious Startup Services
**Purpose:** Enumerate all enabled systemd service units to detect persistence via rogue background services.
```bash
systemctl list-unit-files --type=service --state=enabled
```

---

### 17. `rkhunter` — Rootkit & Trojan Backdoor Scanner
**Purpose:** Perform automated checks for known Linux rootkits, hidden files, and modified system binaries.
```bash
sudo apt install -y rkhunter
sudo rkhunter --update
sudo rkhunter --check --skip-keypress
```

---

### 18. `tar` (Preservation Mode) — Evidence Package Creation
**Purpose:** Package critical log files and artifacts preserving file permissions, timestamps, and directory structures.
```bash
sudo tar -cvzpf /evidence/incident_evidence_$(date +%F).tar.gz /var/log /etc/passwd /tmp
```

---

### 19. `ansible-playbook` — Automated Incident Containment Playbook
**Purpose:** Execute an automated containment runbook across multiple compromised hosts simultaneously.
```bash
ansible-playbook -i /opt/inventory.ini /opt/playbooks/isolate_host.yml --extra-vars "target=web-server-01"
```

---

### 20. `sha256sum` — Chain of Custody Cryptographic Verification
**Purpose:** Verify and document cryptographic integrity of all collected evidence artifacts.
```bash
sha256sum /evidence/* > /evidence/checksums.sha256
sha256sum -c /evidence/checksums.sha256
```

---
*SOC Command Reference - Class 08*
