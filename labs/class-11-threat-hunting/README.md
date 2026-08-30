# Class 11 Lab — Threat Hunting, IOC Management & Threat Intel Integration

A small, self-contained hunt scenario you can run and **demo live** on Kali.
It stages a fake "compromised web host" under `./work/` and walks through six
hunt techniques, each tied to a hypothesis, ending with the pivot to threat
intel enrichment and detection engineering.

> Nothing here touches the real system. All artifacts live under `./work/`.
> `webshell.php` is an inert lab sample — it only exists so hunts have a target.

---

## Files

| Path | Purpose |
|------|---------|
| `setup.sh` | Builds the scenario tree under `./work/` (static — artifacts pre-placed) |
| `attack.sh` | Builds the same tree by *emulating the intrusion* stage by stage, each tagged with its MITRE ATT&CK technique (`--live` also fires real lab-scoped noise) |
| `ATTACK-MANUAL.md` | Do the intrusion **for real** with Kali tools (`nmap`, `hydra`, `weevely`, `msfvenom`, Sliver…) against the victim in `victim/` |
| `victim/docker-compose.yml` | Deliberately soft target — DVWA + weak-cred OpenSSH — for the manual walkthrough |
| `hunt.sh` | Guided hunt — runs all six techniques with headers (`-s` to pause between steps) |
| `rules/hunt_webshell.yar` | YARA rule for PHP webshell primitives |
| `scenario/` | Raw source data (webshell, IOC list, CTI report, Zeek `conn.log`, syslog) |

---

## The scenario

CTI bulletin **"TIN MAGPIE"** (`scenario/apt_report.txt`) reports an invoice-phishing
loader with long-interval HTTPS beaconing. You are handed the report at shift
start and asked to hunt your estate for any sign of it. The lab host turns out to
be dirty: an uploaded webshell, SSH brute force + webshell hits from the C2 list,
a beaconing session, a hidden SUID shell, and a downloader staged in `/dev/shm`.

---

## Quick start

```bash
cd labs/class-11-threat-hunting
chmod +x setup.sh attack.sh hunt.sh

# --- pick ONE way to stage the scenario ---
./setup.sh          # A: static build (fast)
./attack.sh         # B: watch the 8-stage intrusion happen (ATT&CK-tagged)
./attack.sh --live  # B+: also scan localhost / GET testmyids.com / DNS / beacon

# --- then hunt it ---
./hunt.sh           # run the whole hunt
./hunt.sh -s        # pause before each step (classroom pace)

./setup.sh clean    # tear down ./work  (or ./attack.sh clean)
```

**Three ways to run it:**
- `setup.sh` — static build, when you only want the hunt.
- `attack.sh` — scripted 8-stage intrusion into `./work/` (offline, ATT&CK-tagged) so students see the compromise before hunting it.
- `ATTACK-MANUAL.md` — the real thing: stand up `victim/` (DVWA + weak SSH) and run the intrusion by hand with Kali tools, then pull the victim's logs and hunt them.

All three leave a huntable `./work/` (the manual one via `scp` of victim evidence).
For attacking the *network* monitoring stack (Suricata/Zeek) with live traffic,
see [`../adversary-emulation.md`](../adversary-emulation.md).

### Optional tools (the script falls back to `grep`/`awk`/regex if missing)

```bash
sudo apt install -y yara
pip install ioc-parser --break-system-packages
sudo apt install -y zeek        # provides zeek-cut
```

---

## How to present it (≈45–50 min)

### 0 · Before class (2 min)
- `./setup.sh` and one dry `./hunt.sh` run so tool installs / fallbacks are settled.
- Open `scenario/apt_report.txt` in one pane — this is the "intel that started the hunt".
- Have a second terminal ready for the enrichment pivot at the end.

### 1 · Frame the hunt (5 min)
Draw the loop on the board and keep pointing back to it:

```
 hypothesis  ->  data source  ->  analysis  ->  finding  ->  NEW DETECTION
      ^                                                             |
      +-------------------------- feedback --------------------------+
```

Key point: hunting is **hypothesis-driven**. Every hunt below starts from a
sentence ("an attacker dropped a webshell…"), not from a tool.

### 1b · (optional) Show the attack first (5 min) — run `./attack.sh`
Run it once so the class sees how web01 got compromised — 8 stages, each with its
ATT&CK ID and the sensor that *should* catch it. This primes every hypothesis in
the hunt: they're not guessing, they're chasing something they just watched happen.
Then reset with `./attack.sh clean` and rebuild silently before the hunt, or just
leave `./work/` in place (the hunt runs against it either way).

### 2 · Walk the six hunts (25 min) — run `./hunt.sh -s`

| # | Hunt | Hypothesis | What they should see |
|---|------|-----------|----------------------|
| 1 | Webshell primitives (YARA) | Attacker left a webshell in an uploads dir | Match on `uploads/webshell.php` |
| 2 | Known-bad IPs in logs (`grep -rF -f`, `zgrep`) | The C2 IPs already appear in our logs | `45.153.160.140` brute force, `193.169.255.78` webshell GETs |
| 3 | Beaconing (`zeek-cut` on `conn.log`) | Loader beacons on a fixed interval, tiny payloads | 3× `10.0.0.5 -> 45.153.160.140:443`, ~3600 s, <1 KB |
| 4 | Anomalous SUID (`find -perm -04000`) | Persistence hiding as a SUID binary | hidden `opt/bin/.helper`, SUID root |
| 5 | Exec in `/dev/shm` (`find -perm -111`) | Fileless staging in memory-backed dirs | `dev/shm/.u` downloader |
| 6 | IOC extraction (`ioc-parser`) | Turn the bulletin into a usable indicator set | 4 IPs, 2 domains, 2 hashes, 2 CVEs |

For each: read the hypothesis aloud → run the step → point at the exact line in
the output that confirms/denies it → note it in a "findings" list on screen.

### 3 · Pivot to threat intel (8 min)
Take the IOCs from hunt 6 and enrich them. Needs internet / free API keys —
if you have none, show screenshots and run just the URLhaus/ET feeds which are open:

```bash
# open feeds, no key needed
curl -s https://urlhaus.abuse.ch/downloads/csv_recent/ | head -n 20
curl -s https://rules.emergingthreats.net/blockrules/compromised-ips.txt | grep -v '^#' | head

# keyed enrichment (VirusTotal / OTX / your MISP)
vt ip 45.153.160.140
python3 -c "from OTXv2 import OTXv2; otx=OTXv2('KEY'); \
print(len(otx.get_indicator_details_full('IPv4','45.153.160.140')['general']['pulse_info']['pulses']))"
```

Talking point: **IOC lifecycle** — source, confidence, first/last seen, expiry.
An IP that was C2 last year may be a CDN today. This is why MISP exists: to track
that context, not just the string.

### 4 · Close the loop — turn a finding into a detection (5 min)
The beacon in hunt 3 is the durable pattern (IPs rotate, behaviour doesn't).
Show the hand-off to Class 06 detection engineering:

```bash
# sketch a Sigma rule for "long-duration low-byte outbound ssl"
sigma convert -t elasticsearch-lucene beacon_longconn.yml
```

End on the rule: **every hunt should exit as either a new detection or a
documented "nothing here, checked on <date>".**

---

## Instructor answer key (findings)

| Host | Finding | Evidence |
|------|---------|----------|
| web01 | Webshell uploaded | `uploads/webshell.php` (YARA `Class11_Generic_PHP_Webshell`) |
| web01 | SSH brute force | syslog: `Failed password ... from 45.153.160.140` |
| web01 | Webshell interaction | nginx: `GET /uploads/webshell.php?c=... from 193.169.255.78` |
| web01 | Post-exploitation download | cron: `curl ... http://5.42.92.211/win/update.hta` |
| 10.0.0.5 | C2 beaconing | `conn.log`: 3× 1 h SSL sessions to `45.153.160.140`, ~500 B each |
| web01 | SUID persistence | `opt/bin/.helper` — hidden, `-rwsr-xr-x root` |
| web01 | Fileless staging | `/dev/shm/.u` — executable downloader |

---

## Stretch goals

- Stand up **MISP** (`git clone https://github.com/MISP/misp-docker`) and load the
  extracted IOCs as an event; query them back with **PyMISP**.
- Add the C2 IP list to a **Suricata** ruleset and replay `scenario/` traffic.
- Run the same IP sweep with **osquery** / **Velociraptor** VQL instead of `grep`.
- Write the beacon Sigma rule for real and validate it against `conn.log`.
