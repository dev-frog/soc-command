# Security Operations Training Guide

## Module 1: Basic Linux System & Log Investigation

Before running security tools, analysts must know how to inspect files, search logs, and check system status.

### 1. `uname` — View System Information

**Purpose:** Displays kernel and architecture details.

```bash
uname -a
```

**Flag Breakdown:**
- `-a` (All): Prints system name, hostname, kernel release, and hardware architecture.

---

### 2. `grep` — Search Patterns in Log Files

**Purpose:** Filters text files to find specific words, IPs, or error messages.

```bash
grep -i "failed" /var/log/auth.log
```

**Flag Breakdown:**
- `-i` (Ignore Case): Searches for "failed", "FAILED", or "Failed".
- `/var/log/auth.log`: The default Linux authentication log file.

---

### 3. `tail` — Monitor Log Files in Real Time

**Purpose:** Views the newest entries in a log file as they are written.

```bash
tail -f -n 20 /var/log/syslog
```

**Flag Breakdown:**
- `-f` (Follow): Keeps the file open and streams live updates.
- `-n 20` (Number): Shows the last 20 lines of the log file.

---

### 4. `netstat` / `ss` — Inspect Network Connections

**Purpose:** Lists active network sockets and listening ports to spot potential backdoor connections.

```bash
ss -tulpn
```

**Flag Breakdown:**
- `-t` (TCP): Shows TCP sockets.
- `-u` (UDP): Shows UDP sockets.
- `-l` (Listening): Shows only ports currently waiting for connections.
- `-p` (Processes): Displays the Process ID (PID) using the port.
- `-n` (Numeric): Displays IP addresses and port numbers instead of resolving names.

---

## Module 2: Network Reconnaissance & Threat Profiling

Use these tools to identify target systems, active services, and threat infrastructure.

### 5. `ping` — Verify Host Reachability

**Purpose:** Sends ICMP Echo Request messages to test if a host is online.

```bash
ping -c 4 8.8.8.8
```

**Flag Breakdown:**
- `-c 4` (Count): Stops after sending 4 packets.

---

### 6. `whois` — Query Domain & IP Ownership

**Purpose:** Retrieves registration details and infrastructure owners for external IPs.

```bash
whois 185.220.101.5
```

---

### 7. `dig` — Perform DNS Lookups

**Purpose:** Queries Domain Name System (DNS) servers to reveal underlying infrastructure records.

```bash
dig +short A example.com
```

**Flag Breakdown:**
- `+short`: Returns only the IP address instead of verbose headers.
- `A`: Specifies the IPv4 address record type.

---

### 8. `nmap` — Port Scanner & Service Identifier

**Purpose:** Scans targets to discover open ports, running services, and operating systems.

```bash
nmap -sV -p 22,80,443 -T4 192.168.1.1
```

**Flag Breakdown:**
- `-sV` (Service Version): Detects software versions running on open ports.
- `-p 22,80,443` (Ports): Limits scanning strictly to SSH, HTTP, and HTTPS.
- `-T4` (Timing): Sets speed template to aggressive for faster local scans.

---

## Module 3: Gathering Threat Intelligence & Parsing IOCs

Shows how analysts ingest technical Indicators of Compromise (IOCs) directly from public intelligence feeds.

### 9. `curl` — Fetch Web Data & Interact with Threat APIs

**Purpose:** Transfer data to or from a server using protocols like HTTP/HTTPS.

```bash
curl -s https://rules.emergingthreats.net/blockrules/compromised-ips.txt | head -n 10
```

**Flag Breakdown:**
- `-s` (Silent): Hides progress bars and error output.
- `| head -n 10`: Pipes the output to display only the top 10 IP addresses.

---

### 10. `jq` — Parse JSON Threat Intelligence Data

**Purpose:** Processes raw JSON output from security APIs into readable formats.

```bash
echo '{"ip": "1.1.1.1", "reputation": "malicious", "score": 95}' | jq '.ip, .score'
```

**Flag Breakdown:**
- `'.ip, .score'`: Filters out all key-value pairs except the specific fields requested.

---

## Module 4: Simulating Adversary TTPs (MITRE ATT&CK Mapping)

Demonstrates basic offensive techniques mapped to MITRE ATT&CK tactics to show what generates telemetry in a SOC.

### 11. System Information Discovery (MITRE T1082)

**Purpose:** Simulates an attacker collecting basic system and domain context after gaining access.

```bash
id && hostname && lsb_release -a
```

**Explanation:**
- `id`: Prints current user ID and group permissions (checks for admin privileges).
- `hostname`: Identifies the compromised system's machine name.
- `lsb_release -a`: Identifies Linux distribution details.

---

### 12. Local Group Discovery (MITRE T1069.001)

**Purpose:** Shows how threat actors enumerate local admin accounts.

```bash
getent group sudo
```

**Explanation:** Checks `/etc/group` database to display all users assigned elevated root/sudo privileges.

---

### 13. Defense Evasion: File Deletion (MITRE T1070.004)

**Purpose:** Simulates clearing local files to hide malicious activities.

```bash
touch /tmp/malicious_payload.sh
rm -f /tmp/malicious_payload.sh
```

**Flag Breakdown:**
- `-f` (Force): Suppresses confirmation prompts and ignores nonexistent files.

---

### 14. Automated Scripting Execution (MITRE T1059.004)

**Purpose:** Executes automated commands using native Bash scripts.

```bash
bash -c 'for ip in 192.168.1.{1..5}; do ping -c 1 -W 1 $ip; done'
```

**Flag Breakdown:**
- `bash -c`: Runs the enclosed string commands inside a new shell process.
- `-W 1`: Sets a 1-second timeout for ping responses to perform rapid host discovery.

---

## Lab Setup: MITRE ATT&CK Navigator & Threat Intelligence Tooling

### 1. Prerequisites – System Setup

Update your system and install essential packages:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget vim build-essential python3 python3-pip python3-venv
```

Install Docker (required for ATT&CK Navigator and other containerised tools):

```bash
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker --now
sudo usermod -aG docker $USER
newgrp docker          # or log out and back in
docker --version       # verify installation
```

---

### 2. Install MITRE ATT&CK Navigator (Local Deployment)

**Option A – Docker (recommended)**

```bash
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator
docker build -t attack-navigator .
docker run -d --name attack-navigator -p 4200:4200 attack-navigator
```

Access the Navigator at `http://localhost:4200` in your browser.

**Option B – Pre-built Docker Image (faster)**

```bash
docker run -d --name navigator -p 4200:4200 bodane/attack-navigator:latest
```

**Option C – Native Node.js Installation**

```bash
sudo apt install -y nodejs npm
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator
npm install
npm run build:prod
npm start
```

Again, open `http://localhost:4200`.

---

### 3. Comparative Analysis: Load Sample Layers

Download example ATT&CK layers (JSON) from the MITRE repository:

```bash
cd ~/attack-navigator
wget https://raw.githubusercontent.com/mitre-attack/attack-navigator/master/layers/samples/Bear_APT.json
wget https://raw.githubusercontent.com/mitre-attack/attack-navigator/master/layers/samples/APT29.json
```

In the Navigator web interface:

1. Click **"Create New Layer"** → **"Load from URL"**.
2. Paste the raw URL of a sample (e.g., the Bear_APT.json URL above).
3. Load another layer (e.g., APT29) and use the **"Layer Operations"** tab to perform addition, subtraction, or intersection between layers.

---

### 4. Threat Intelligence with STIX & TAXII

Install the Python libraries for STIX 2 and TAXII 2:

```bash
pip3 install stix2 taxii2-client
```

**Download and Query ATT&CK STIX Data**

Create a Python script to fetch the Enterprise ATT&CK STIX bundle and list techniques:

```bash
cat > attack_stix_query.py << 'EOF'
import requests
from stix2 import FileSystemSource, Filter

# Download the STIX bundle
url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
response = requests.get(url)
with open("enterprise-attack.json", "wb") as f:
    f.write(response.content)

# Query attack-pattern objects
fs = FileSystemSource("./")
filters = Filter("type", "=", "attack-pattern")
techniques = fs.query(filters)

for tech in list(techniques)[:10]:
    print(f"{tech.id}: {tech.name}")
EOF

python3 attack_stix_query.py
```

**TAXII Discovery (using Cabby)**

Install the Cabby client:

```bash
sudo apt install -y cabby   # or pip3 install cabby
cabby taxii-discovery --path https://cti-taxii.mitre.org/taxii/
```

---

### 5. Detection Coverage & Ransomware Mapping

**Create a Custom Coverage Layer**

In the Navigator web UI:

1. Click **"Create New Layer"** and choose **"Enterprise ATT&CK"**.
2. Click on individual technique cells and assign a score:
   - `0` = no coverage
   - `1` = partial
   - `2` = good
   - `3` = full
3. Add comments describing your detection methods.
4. Export the layer as JSON (use the **"Export"** button).

**Generate a Coverage Layer via Script (CLI)**

```bash
cat > generate_coverage.py << 'EOF'
import json

layer = {
    "name": "My SOC Detection Coverage",
    "versions": {"attack": "16"},
    "domain": "enterprise-attack",
    "description": "Current detection coverage mapping",
    "techniques": [
        {"techniqueID": "T1059", "score": 2, "comment": "PowerShell logging enabled"},
        {"techniqueID": "T1046", "score": 1, "comment": "Partial network scan detection"},
        {"techniqueID": "T1078", "score": 0, "comment": "No coverage for valid accounts"}
    ],
    "gradient": {"colors": ["#ffffff", "#ff6666", "#ffcc00", "#66cc66"]}
}

with open("coverage_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
print("Coverage layer saved to coverage_layer.json")
EOF

python3 generate_coverage.py
```

Then import `coverage_layer.json` into the Navigator via **"Load from file"**.

---

### 6. Practical Case Study: Mapping Ransomware Campaigns

Create a JSON file with common ransomware TTPs:

```bash
mkdir -p ~/ransomware_analysis
cd ~/ransomware_analysis

cat > ransomware_ttp.json << 'EOF'
{
  "name": "Ransomware Campaign TTPs",
  "description": "Common ransomware techniques mapped to MITRE ATT&CK",
  "techniques": [
    {"techniqueID": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    {"techniqueID": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    {"techniqueID": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    {"techniqueID": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    {"techniqueID": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
    {"techniqueID": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"}
  ]
}
EOF
```

Load this file into the Navigator as a new layer to visualise the ransomware TTPs.

---

### 7. Hands-On Gap Analysis Exercise

Perform a gap analysis by comparing an attacker profile with your defence coverage.

**Step 1 – Create a Threat Profile (Attacker TTPs)**

```bash
cat > threat_profile.json << 'EOF'
{
  "name": "APT29 Threat Profile",
  "techniques": [
    {"techniqueID": "T1059.001", "score": 3},
    {"techniqueID": "T1046", "score": 2},
    {"techniqueID": "T1078", "score": 3},
    {"techniqueID": "T1021", "score": 2},
    {"techniqueID": "T1003", "score": 3}
  ]
}
EOF
```

**Step 2 – Create a Defence Coverage Layer**

```bash
cat > defense_coverage.json << 'EOF'
{
  "name": "Current Defense Coverage",
  "techniques": [
    {"techniqueID": "T1059.001", "score": 1},
    {"techniqueID": "T1046", "score": 2},
    {"techniqueID": "T1078", "score": 0},
    {"techniqueID": "T1021", "score": 1},
    {"techniqueID": "T1003", "score": 0}
  ]
}
EOF
```

**Step 3 – Perform the Gap Analysis in Navigator**

1. Load both layers (`threat_profile.json` and `defense_coverage.json`) into the Navigator.
2. Use **"Layer Operations"** → **"Subtract"** (threat profile minus defence coverage).

The resulting layer highlights the techniques where you have no or insufficient coverage — i.e., your gaps.

---

### 8. Advanced Navigator Features

- **Layer Operations:** Combine multiple layers using addition, subtraction, intersection, or score-based operations.
- **Export options:** Save your layers as JSON, SVG (vector graphic), or Excel spreadsheet for reporting.
- **Comments & annotations:** Add detailed notes to each technique to document detection logic or mitigation status.

---

### 9. Verification – Check All Tools

Run this quick check to confirm everything is installed and running:

```bash
echo "=== MITRE ATT&CK Navigator ==="
docker ps | grep navigator || echo "Navigator not running"

echo "=== Python STIX2 Library ==="
pip3 list | grep stix2 || echo "stix2 not installed"

echo "=== Docker Status ==="
docker --version

echo "=== Kali Version ==="
cat /etc/os-release | grep PRETTY_NAME
```