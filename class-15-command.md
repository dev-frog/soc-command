# Module 15: Business Continuity, Disaster Recovery & Cyber Crisis Management
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for encrypted backups (Restic), disaster recovery synchronization (rsync), database recovery, network failover testing, and cyber crisis management on Kali Linux.

---

### 1. `restic` (Init & Backup) — Encrypted Immutable SIEM Backups
**Purpose:** Initialize an encrypted, deduplicated repository and snapshot critical SIEM and IDS configuration directories.
```bash
sudo apt install -y restic
# Initialize backup repo
restic init --repo /backup/soc_dr_repo
# Create snapshot of configs and rules
sudo restic -r /backup/soc_dr_repo backup /etc/suricata /etc/elasticsearch /var/ossec/etc
```

---

### 2. `restic` (Verification & Integrity Check)
**Purpose:** Cryptographically verify the integrity and completeness of disaster recovery backup snapshots.
```bash
sudo restic -r /backup/soc_dr_repo check
sudo restic -r /backup/soc_dr_repo snapshots
```

---

### 3. `restic` (Restore) — Disaster Recovery Data Restoration
**Purpose:** Restore configuration and detection rule snapshots to a replacement node during disaster recovery.
```bash
sudo restic -r /backup/soc_dr_repo restore latest --target /tmp/dr_restore/
```

---

### 4. `rsync` — Secure Offsite DR Synchronization
**Purpose:** Mirror forensic evidence and SIEM configuration archives to an offsite disaster recovery site over SSH.
```bash
rsync -avzhe ssh --delete --progress /evidence/ soc-dr@192.168.10.50:/remote_dr_storage/evidence/
```

---

### 5. `borgbackup` — Deduplicated Disaster Recovery Archiving
**Purpose:** Create compressed and authenticated offsite disaster recovery backup archives.
```bash
sudo apt install -y borgbackup
borg init --encryption=repokey /backup/borg_soc_repo
borg create /backup/borg_soc_repo::monday_backup /var/log /etc
```

---

### 6. `tar` (Gzip Archive Mode) — Fast SOC Configuration Bundling
**Purpose:** Create timestamped configuration archives before major system updates or during crisis preparation.
```bash
sudo tar -czvf /backup/soc_config_$(date +%Y%m%d).tar.gz /etc/suricata /etc/zeek /etc/rsyslog.conf
```

---

### 7. `gpg` — Cryptographic Encryption of Offsite Backups
**Purpose:** Encrypt critical incident archives with AES-256 before transferring to third-party cloud storage.
```bash
gpg -c --cipher-algo AES256 /backup/soc_config_$(date +%Y%m%d).tar.gz
```

---

### 8. `systemctl` (Service State Audit) — Health Check Core SOC Daemons
**Purpose:** Verify operational status of all core monitoring daemons during crisis recovery.
```bash
systemctl is-active elasticsearch kibana suricata wazuh-manager
```

---

### 9. `nc` (Netcat) — DR Network Link & Port Probing
**Purpose:** Verify network connectivity and routing to the secondary disaster recovery site gateway.
```bash
nc -zvw3 192.168.10.50 22
```

---

### 10. `ip route replace` — Emergency Default Gateway Failover
**Purpose:** Manually reroute SOC outbound monitoring traffic to a secondary backup ISP link during an outage.
```bash
sudo ip route replace default via 192.168.1.254 dev eth1
```

---

### 11. `pg_dump` — Relational Database Backup (GVM / TheHive)
**Purpose:** Export SQL database dumps of case management and vulnerability databases for offline DR storage.
```bash
sudo -u postgres pg_dump gvmd > /backup/gvmd_db_$(date +%F).sql
```

---

### 12. `sha256sum` (Integrity Verification)
**Purpose:** Validate cryptographic checksums of restored disaster recovery image files.
```bash
sha256sum -c /backup/checksums.sha256
```

---

### 13. `dd` (Disaster Recovery Disk Cloning)
**Purpose:** Clone physical disks directly to secondary recovery drives during catastrophic hardware failures.
```bash
sudo dd if=/dev/sda of=/dev/sdc bs=64K conv=noerror,sync status=progress
```

---

### 14. `journalctl` — Failure Diagnostics During Recovery
**Purpose:** Review system logs to identify startup crashes and dependency failures on restored services.
```bash
sudo journalctl -xeu wazuh-manager --no-pager
```

---

### 15. `curl` (Service Health Endpoint Check)
**Purpose:** Automated health check probing of web-based SIEM and case management dashboards.
```bash
curl -f -k https://localhost:9200/_cluster/health || echo "Elasticsearch Cluster DOWN!"
```

---

### 16. `watch` — Real-Time Recovery Progress Monitor
**Purpose:** Continuously monitor the recovery and startup status of restored Docker containers.
```bash
watch -n 2 'docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"'
```

---

### 17. `df -h` — Storage Capacity Verification on DR Nodes
**Purpose:** Verify disk space availability before uncompressing large log archives during disaster recovery.
```bash
df -h /backup /var/log /var/ossec
```

---

### 18. `fsck` — Filesystem Consistency Check & Repair
**Purpose:** Check and repair corrupted filesystem partitions following sudden power outages or system crashes.
```bash
sudo fsck -f -y /dev/sdb1
```

---

### 19. `crontab` — Schedule Automated Daily DR Backup Verification
**Purpose:** Schedule automated daily integrity checks of all disaster recovery repositories.
```bash
echo "0 2 * * * root restic -r /backup/soc_dr_repo check" | sudo tee -a /etc/crontab
```

---

### 20. `mailx` — Broadcast Crisis Communication Notifications
**Purpose:** Send automated status updates to executive crisis management teams during outage restoration.
```bash
echo "Disaster Recovery Drill Completed: Secondary SIEM Cluster restored in 42 minutes." | mailx -s "CRISIS_UPDATE: Recovery Successful" crisis-team@organization.com
```

---
*SOC Command Reference - Class 15*
