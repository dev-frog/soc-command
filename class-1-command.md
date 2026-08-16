# Module 01: Introduction to Cyber Security Operations & SOC Architecture Overview
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for understanding SOC architecture, sensor placement, network perimeter monitoring, host discovery, and interface verification on Kali Linux.

---

### 1. `ip` — Network Interface & Promiscuous Sniffing Configuration
**Purpose:** Inspect network interfaces and enable promiscuous mode for SPAN/TAP packet capture sensors.
```bash
# View all network interfaces and operational states
ip addr show

# Enable promiscuous mode on eth0 (captures all frames on mirrored SPAN port)
sudo ip link set eth0 promisc on

# Verify promiscuous mode is active
ip link show eth0 | grep PROMISC
```

---

### 2. `ethtool` — Network Adapter & Link Speed Inspection
**Purpose:** Check hardware driver, physical link speed, duplex mode, and offload settings on SOC capture cards.
```bash
sudo apt install -y ethtool
sudo ethtool eth0
```

---

### 3. `arp-scan` — Layer-2 Local Subnet Sweep
**Purpose:** Rapidly scan local network segment using ARP requests to discover all active devices and MAC addresses.
```bash
sudo apt install -y arp-scan
sudo arp-scan --interface=eth0 --localnet
```

---

### 4. `netdiscover` — Passive & Active ARP Discovery
**Purpose:** Discover live hosts passively without sending probe packets, ideal for stealthy SOC sensor deployment.
```bash
sudo apt install -y netdiscover
# Passive listening mode:
sudo netdiscover -i eth0 -p
```

---

### 5. `nmap` (Ping Sweep) — ICMP Subnet Asset Discovery
**Purpose:** Perform fast ICMP ping sweeps to inventory live hosts across a monitored network block.
```bash
nmap -sn 192.168.1.0/24 -oN /tmp/subnet_hosts.txt
```

---

### 6. `masscan` — High-Speed Perimeter Port Scanner
**Purpose:** Scan large IP ranges at extremely high packet rates to map external SOC monitoring surfaces.
```bash
sudo apt install -y masscan
sudo masscan 192.168.1.0/24 -p22,80,443,3389,8080 --rate=1000 -oG /tmp/masscan_assets.txt
```

---

### 7. `fping` — Parallel Multi-Host Reachability Check
**Purpose:** Rapidly test reachability of hundreds of hosts simultaneously from the command line.
```bash
sudo apt install -y fping
fping -a -g 192.168.1.1 192.168.1.254 2>/dev/null
```

---

### 8. `mtr` — Interactive Network Route & Latency Diagnostics
**Purpose:** Combine ping and traceroute to analyze network hops and packet loss between sensors and SIEM collectors.
```bash
sudo apt install -y mtr
mtr -rw -c 10 192.168.1.1
```

---

### 9. `tcpdump` — Raw Packet Sniffing Validation
**Purpose:** Verify that a TAP/SPAN port is actively receiving traffic on the SOC sensor.
```bash
sudo tcpdump -i eth0 -nn -c 20
```

---

### 10. `tshark` — Terminal Protocol Analyzer
**Purpose:** Command-line packet analyzer to inspect top network protocols arriving at the sensor.
```bash
sudo apt install -y tshark
tshark -i eth0 -a duration:10 -q -z io,phs
```

---

### 11. `hping3` — Network Packet Generator & Firewall Testing
**Purpose:** Craft custom TCP/UDP/ICMP packets to test whether SOC perimeter firewalls and IDS sensors trigger correctly.
```bash
sudo apt install -y hping3
sudo hping3 -S -p 80 -c 4 192.168.1.1
```

---

### 12. `iperf3` — Network Bandwidth & Throughput Testing
**Purpose:** Measure bandwidth capacity between remote log forwarders and central SIEM collector servers.
```bash
sudo apt install -y iperf3
# On SIEM collector server: iperf3 -s
# On SOC sensor/agent:
iperf3 -c 192.168.1.10 -t 10
```

---

### 13. `bmon` — Real-Time Bandwidth Monitor
**Purpose:** Visual console monitor showing live bandwidth utilization and packet rates on capture interfaces.
```bash
sudo apt install -y bmon
bmon -p eth0
```

---

### 14. `iptables` — Firewall Packet Counter & Policy Inspection
**Purpose:** View host firewall rules and check packet/byte counters on incoming SOC traffic.
```bash
sudo iptables -L -n -v --line-numbers
```

---

### 15. `ip route` — Kernel Routing Table Inspection
**Purpose:** Display and verify routing paths for multi-homed SOC sensor appliances.
```bash
ip route show
```

---

### 16. `hostnamectl` — Sensor System & Architecture Verification
**Purpose:** Check operating system, kernel version, and hardware architecture of the SOC node.
```bash
hostnamectl status
```

---

### 17. `dmidecode` — Hardware & Memory Inventory
**Purpose:** Inspect hardware specifications (RAM, CPU cores, BIOS) of physical SOC sensor hardware.
```bash
sudo dmidecode -t memory | grep -E 'Size|Type|Speed'
```

---

### 18. `lsmod` — Inspect Kernel Packet Capture Modules
**Purpose:** Check loaded kernel modules (such as AF_PACKET or PF_RING) used for high-speed packet capture.
```bash
lsmod | grep -E 'packet|tun|tap'
```

---

### 19. `sysctl` — Kernel Network Buffer Tuning
**Purpose:** Tune Linux kernel receive buffers to prevent packet drops on high-throughput SOC sensor interfaces.
```bash
# View current maximum receive buffer size
sysctl net.core.rmem_max

# Increase buffer size for high-speed capture
sudo sysctl -w net.core.rmem_max=16777216
```

---

### 20. `nload` — Visual Network Traffic Monitor
**Purpose:** Real-time visual graph display of incoming and outgoing traffic on the SOC monitoring sensor.
```bash
sudo apt install -y nload
nload eth0
```

---
*SOC Command Reference - Class 01*
