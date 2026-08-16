# Module 09: Digital Forensics Overview, Evidence Handling & Malware Investigation
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for forensic imaging, dead-box artifact analysis, file system inspection (The Sleuth Kit/Autopsy), static binary triage, and malware investigation on Kali Linux.

---

### 1. `dc3dd` — Forensic Disk Imaging with Verification Hashing
**Purpose:** Create bit-stream forensic images with on-the-fly SHA-256 calculation and comprehensive log files.
```bash
sudo apt install -y dc3dd
sudo dc3dd if=/dev/sdb of=/evidence/evidence_disk.dd hash=sha256 log=/evidence/imaging_log.txt
```

---

### 2. `dcfldd` — Enhanced Forensic Copying & Split Imaging
**Purpose:** Create forensic images with live status updates and split output files for storage management.
```bash
sudo apt install -y dcfldd
sudo dcfldd if=/dev/sdb of=/evidence/disk_image.raw hash=sha256 split=4G
```

---

### 3. `autopsy` — Digital Forensics Web Graphical Interface
**Purpose:** Launch the Autopsy forensic suite for timeline analysis, keyword search, and artifact extraction.
```bash
sudo apt install -y autopsy
sudo autopsy
# Open browser to access GUI: http://localhost:9999/autopsy
```

---

### 4. `mmls` (Sleuth Kit) — Display Partition Layout
**Purpose:** Inspect partition tables and sector offset values of an acquired raw disk image.
```bash
sudo apt install -y sleuthkit
mmls /evidence/evidence_disk.dd
```

---

### 5. `fls` (Sleuth Kit) — List Deleted & Active Files
**Purpose:** Enumerate active and deleted directory contents within a specific partition offset (e.g. offset 2048).
```bash
fls -r -d -p -o 2048 /evidence/evidence_disk.dd
```

---

### 6. `icat` (Sleuth Kit) — Inode File Content Carving
**Purpose:** Extract raw file contents directly from a specified inode number (e.g. deleted inode 14205).
```bash
icat -o 2048 /evidence/evidence_disk.dd 14205 > /tmp/recovered_file.bin
```

---

### 7. `fsstat` (Sleuth Kit) — File System Details & Metadata
**Purpose:** Display file system metadata, cluster sizes, block ranges, and volume serial numbers.
```bash
fsstat -o 2048 /evidence/evidence_disk.dd
```

---

### 8. `srch_strings` — Forensic String Extraction with Byte Offsets
**Purpose:** Extract ASCII and Unicode strings from raw images while preserving exact byte offset positions.
```bash
srch_strings -a -td /evidence/evidence_disk.dd > /evidence/all_strings.txt
```

---

### 9. `file` — Binary Header & Architecture Verification
**Purpose:** Determine the actual MIME type and architecture (e.g. ELF 64-bit, PE32+) based on magic bytes.
```bash
file /tmp/suspicious_sample.bin
```

---

### 10. `strings` — Extract Readable Text from Malicious Binaries
**Purpose:** Extract URLs, IP addresses, function names, and hardcoded C2 strings from binaries.
```bash
strings -a -n 8 /tmp/suspicious_sample.bin | head -n 30
```

---

### 11. `binwalk` — Firmware & Archive Extraction
**Purpose:** Scan binaries for embedded files, compressed archives, and executable payloads.
```bash
sudo apt install -y binwalk
binwalk -e -M /tmp/firmware_or_binary.bin
```

---

### 12. `ghidra` — Disassembler & Decompiler Suite
**Purpose:** Perform static reverse engineering and decompilation of compiled x86/x64 binaries.
```bash
sudo apt install -y ghidra
ghidra &
```

---

### 13. `readelf` — ELF Binary Section & Symbol Analysis
**Purpose:** Inspect headers, sections, dependencies, and symbols in suspicious Linux executables.
```bash
readelf -h -S -d /tmp/linux_malware
```

---

### 14. `objdump` — Disassemble Executable Assembly Code
**Purpose:** Disassemble executable `.text` sections into x86/x64 assembly instructions.
```bash
objdump -d -M intel /tmp/linux_malware | head -n 50
```

---

### 15. `yara` — Pattern Matching for Malware Families
**Purpose:** Scan files and directories against signature rules to identify specific malware variants.
```bash
sudo apt install -y yara
yara -r -m /usr/share/yara/rules/malware.yar /tmp/evidence/
```

---

### 16. `clamscan` — Antivirus Engine Scanning
**Purpose:** Rapidly scan a directory of captured artifacts against ClamAV's open-source malware signature database.
```bash
sudo apt install -y clamav
sudo freshclam
clamscan -r --bell -i /tmp/evidence/
```

---

### 17. `exiftool` — Extract Detailed File Metadata & Timestamps
**Purpose:** Extract author names, software tools used, camera metadata, and timestamps from files.
```bash
sudo apt install -y libimage-exiftool-perl
exiftool -all /tmp/phishing_attachment.docx
```

---

### 18. `mraptor` — Office Malicious Macro Triager
**Purpose:** Quickly evaluate whether an MS Office macro contains suspicious auto-executing malicious code.
```bash
pip install oletools --break-system-packages
mraptor /tmp/malicious_document.docm
```

---

### 19. `bulk_extractor` — High-Speed Digital Artifact Feature Extraction
**Purpose:** Extract credit card numbers, email addresses, URLs, and network packets from unallocated disk space.
```bash
sudo apt install -y bulk_extractor
bulk_extractor -o /evidence/bulk_output/ /evidence/evidence_disk.dd
```

---

### 20. `volatility3` — Volatile Memory Triage
**Purpose:** Extract command-line histories, loaded DLLs, and dumped processes from RAM.
```bash
python3 /opt/volatility3/vol.py -f /evidence/memdump.raw windows.cmdline
```

---
*SOC Command Reference - Class 09*
