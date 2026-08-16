Wazuh Manager + Indexer — Detailed Breakdown
What it is

Wazuh is a free, open-source SIEM/XDR platform (forked from OSSEC in 2015). It's built as three cooperating components, not one binary:

Component	Role
Wazuh Manager	Brain of the system — receives agent data, applies detection rules, generates alerts, manages agent config
Wazuh Indexer	Storage/search layer — a fork of OpenSearch (Elasticsearch-compatible), stores and indexes all alerts/events
Wazuh Dashboard	Web UI (Kibana-fork) for visualization, alert triage, and management

The -a flag in the install script deploys all three on a single node — the standard setup for a lab/training environment.

Command-by-command breakdown
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh

Downloads Wazuh's official all-in-one installer script (bash). -s = silent (no progress bar), -O = save with the remote filename.

sudo bash wazuh-install.sh -a

Runs the installer in all-in-one mode. This does a lot under the hood:

Adds the Wazuh APT repo and GPG key
Installs and configures the Manager, Indexer, and Dashboard
Generates TLS certificates for inter-component communication
Sets up the admin and kibanaserver/dashboard users
Prints the admin password at the end — copy it immediately, it's not shown again by default

Takes 5–15 min depending on hardware. Needs minimum ~4GB RAM to run comfortably (Indexer is JVM-based and memory-hungry).

sudo systemctl status wazuh-manager wazuh-indexer

Checks both services are active (running). If either is failed, check:

bash
sudo journalctl -u wazuh-manager -n 50 --no-pager
sudo journalctl -u wazuh-indexer -n 50 --no-pager

Common indexer failure cause on lab VMs: insufficient vm.max_map_count. Fix:

bash
sudo sysctl -w vm.max_map_count=262144
sudo /var/ossec/bin/wazuh-control status

Wazuh-specific control binary (legacy OSSEC naming — /var/ossec/ is still the manager's home directory). Shows internal daemon status, not just the systemd unit:

wazuh-agentlessd not running...
wazuh-analysisd is running...
wazuh-execd is running...
wazuh-modulesd is running...
wazuh-monitord is running...
wazuh-remoted is running...
wazuh-syscheckd is running...
wazuh-clusterd not running...
wazuh-db is running...
wazuh-authd is running...

wazuh-analysisd is the rule engine (this is what "correlates" events). wazuh-remoted is what listens for agent traffic on port 1514.

Key paths & ports to know
Item	Location/Port
Manager config	/var/ossec/etc/ossec.conf
Detection rules	/var/ossec/ruleset/rules/ (built-in), /var/ossec/etc/rules/local_rules.xml (custom)
Decoders	/var/ossec/ruleset/decoders/
Raw alert log	/var/ossec/logs/alerts/alerts.json
Agent enrollment	port 1515 (registration), 1514 (data, TCP/UDP)
Indexer API	port 9200
Dashboard (web UI)	port 443 (https://<ip>)
Useful follow-up commands
bash
# List enrolled agents
sudo /var/ossec/bin/agent_control -l

# Manually add an agent
sudo /var/ossec/bin/manage_agents

# Restart manager after editing rules/config
sudo systemctl restart wazuh-manager

# Test a custom rule against a sample log line
sudo /var/ossec/bin/wazuh-logtest

# Tail live alerts
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq .
Why it's a good "architecture" teaching example

It cleanly demonstrates the standard SIEM three-tier model: collection (agents) → processing/correlation (manager/analysisd) → storage & search (indexer) → visualization (dashboard) — the same pattern you'd map onto Elastic Stack (Beats → Logstash → Elasticsearch → Kibana) or Splunk (forwarders → indexers → search head).

Want me to go through the other 19 tools from that list the same way, or focus on a specific one next (e.g. Sigma or Suricata rule profiling)?