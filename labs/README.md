# SOC Network Monitoring — Docker Stack (Kali Linux)

## What's included by default

| Container       | Purpose                                                  | Access                           |
| --------------- | -------------------------------------------------------- | -------------------------------- |
| `suricata`      | Signature-based IDS — flags known-bad traffic            | logs: `./suricata/logs/eve.json` |
| `zeek`          | Protocol-level traffic analyzer — conn/dns/http/ssl logs | logs: `./zeek/logs/`             |
| `ntopng`        | Real-time bandwidth/flow dashboard                       | `http://localhost:3000`          |
| `elasticsearch` | Stores all shipped logs                                  | `http://localhost:9200`          |
| `kibana`        | Search/visualize/dashboard the logs                      | `http://localhost:5601`          |
| `filebeat`      | Ships Suricata + Zeek logs into Elasticsearch            | —                                |

`suricata`, `zeek`, and `ntopng` run with `network_mode: host` and `NET_ADMIN`/`NET_RAW` capabilities so they can actually see live traffic on your NIC (Docker's default bridge network won't show you the host's real traffic).

## Quick start

```bash
# 1. Get the files onto your Kali box, then:
cd soc-docker-lab
chmod +x setup.sh
./setup.sh
```

The script auto-detects your active interface, installs Docker if missing, fixes the Elasticsearch `vm.max_map_count` kernel setting, pulls base Suricata rules, and brings the stack up.

To target a specific interface manually, edit `.env`:

```
INTERFACE=eth0
```

then:

```bash
docker compose up -d
```

## Check it's working

```bash
docker compose ps
docker compose logs -f suricata
tail -f suricata/logs/eve.json | jq .
tail -f zeek/logs/current/conn.log
```

---

## Full list of open-source tools you can add for monitoring

### Network traffic capture / IDS-IPS (drop-in Docker alternatives or additions)

| Tool                         | Docker image          | What it adds                                                       |
| ---------------------------- | --------------------- | ------------------------------------------------------------------ |
| **Suricata**                 | `jasonish/suricata`   | Signature IDS/IPS (included above)                                 |
| **Zeek**                     | `zeek/zeek`           | Protocol/flow-level logging (included above)                       |
| **Snort**                    | `linton/docker-snort` | Alternative signature IDS                                          |
| **ntopng**                   | `ntop/ntopng`         | Live bandwidth/flow dashboard (included above)                     |
| **Arkime (formerly Moloch)** | `themoloch/moloch`    | Full packet capture + search UI, great for deep-dive investigation |
| **p0f**                      | build from source     | Passive OS/traffic fingerprinting                                  |

### Host/endpoint visibility (run as agents on monitored hosts, not the Docker host itself)

| Tool                 | Notes                                                 |
| -------------------- | ----------------------------------------------------- |
| **Wazuh agent**      | Ships host logs/FIM/rootkit checks to a Wazuh manager |
| **auditd**           | Linux syscall auditing                                |
| **osquery**          | SQL-queryable endpoint state                          |
| **Sysmon for Linux** | Deep process/network/file event logging               |

### SIEM / correlation (can replace or sit alongside Elastic in this stack)

| Tool        | Docker                                                                               | Notes                                                 |
| ----------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| **Wazuh**   | official `wazuh-docker` repo (`git clone https://github.com/wazuh/wazuh-docker.git`) | Full SIEM/XDR with built-in MITRE ATT&CK-tagged rules |
| **Graylog** | `graylog/graylog`                                                                    | Stream-based log management alternative to ELK        |
| **TheHive** | `thehiveproject/thehive`                                                             | Case management / incident response tracking          |

### Detection engineering / alert tuning (CLI, run inside or alongside containers)

| Tool                  | Purpose                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| **Sigma / sigma-cli** | Portable detection rules → convert to Elastic/Wazuh/Splunk queries      |
| **YARA**              | File/malware pattern matching                                           |
| **jq**                | Slice/filter JSON alerts (`eve.json`, Elasticsearch results) for tuning |
| **Elastalert2**       | Threshold-based alerting on top of Elasticsearch data                   |

### Threat intel / IOC enrichment

| Tool       | Docker                        | Notes                                                     |
| ---------- | ----------------------------- | --------------------------------------------------------- |
| **MISP**   | `misp-docker` (official repo) | IOC sharing/tagging platform                              |
| **Cortex** | `thehiveproject/cortex`       | Automated IOC enrichment (VirusTotal, etc. via analyzers) |

### Adversary emulation (to generate traffic worth detecting — run in isolated lab only)

| Tool                | Notes                                                                                                     |
| ------------------- | --------------------------------------------------------------------------------------------------------- |
| **Atomic Red Team** | Fires individual ATT&CK techniques                                                                        |
| **CALDERA**         | `git clone https://github.com/mitre/caldera.git` — full attack-chain emulation, has its own Docker option |

---

## Adding Wazuh instead of / alongside Elastic

For a full SIEM (not just log storage), swap in Wazuh's official docker-compose:

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node
docker compose up -d
```

This gives you Manager + Indexer + Dashboard pre-wired, and you can still point `filebeat` at it instead of raw Elasticsearch by changing the `output.elasticsearch.hosts` value in `filebeat.yml`.

## Low-RAM setup (VirtualBox, <2GB RAM)

The full stack above needs ~2.8GB+ RAM once Elasticsearch, Kibana, and the IDS/monitoring containers are all running — it will not run reliably in a VirtualBox VM capped under 2GB (Elasticsearch's JVM heap alone is `-Xmx1g`, and the container needs more than that to stay up). For low-RAM student VMs, use the lite variant instead: `suricata` + `zeek` + `ntopng` only, no Elasticsearch/Kibana/filebeat (~450–600MB total).

```bash
chmod +x setup-lite.sh
./setup-lite.sh
```

Students read alerts/logs directly instead of through Kibana:

```bash
tail -f suricata/logs/eve.json | jq .
zeek-cut < zeek/logs/current/conn.log
```

ntopng's web dashboard (`http://localhost:3000`) still works the same as in the full stack.

**VirtualBox network setting matters here**: set the VM's network adapter to **Bridged Adapter**, not the default NAT — `network_mode: host` needs a real interface with real traffic on it, and NAT won't give it that. If you want the VM to see traffic beyond its own (e.g. other devices on the LAN segment), also enable **Promiscuous Mode → Allow All** under the adapter's advanced settings.

If you can give the VM more RAM instead, prefer that — 4GB+ lets you run the full stack (`docker-compose.yml`) with Kibana's search/visualization layer, which is a better learning experience than raw log tailing.

## Notes

- `network_mode: host` only works on Linux (this is fine for Kali) — not on Docker Desktop for Mac/Windows.
- Elasticsearch needs ~2GB+ RAM free; if the container keeps restarting, check `docker compose logs elasticsearch`.
- Only monitor traffic on networks/interfaces you own or are authorized to observe.
