# Module 16: SOC Governance, Policies, Standard Operating Procedures (SOP), Playbooks & Runbooks
### 20 Tools & Commands for Kali Linux

This guide provides 20 essential commands and tools for managing Playbook-as-Code (Git), automated containment runbooks (Ansible), documentation compilation (Pandoc), linting, and policy version control on Kali Linux.

---

### 1. `git` — Version Control for SOPs & Detection Playbooks
**Purpose:** Maintain a strict version history and audit trail of all SOC playbooks, detection rules, and operational procedures.
```bash
git init /opt/soc-playbooks
cd /opt/soc-playbooks
git add . && git commit -m "feat: Add Phishing Incident Response Playbook v2.1"
```

---

### 2. `ansible-playbook` — Execute Standardized Containment Runbook
**Purpose:** Automate the execution of standardized incident containment procedures across endpoints.
```bash
sudo apt install -y ansible
cat << 'EOF' > /tmp/isolate_runbook.yml
---
- name: Contain Malicious Endpoint SOP
  hosts: localhost
  tasks:
    - name: Block malicious C2 IP on local firewall
      iptables:
        chain: INPUT
        source: "{{ c2_ip }}"
        jump: DROP
      become: true
    - name: Lock compromised user account
      user:
        name: "{{ user }}"
        password_lock: yes
      become: true
EOF
ansible-playbook /tmp/isolate_runbook.yml --extra-vars "c2_ip=198.51.100.23 user=compromised_account"
```

---

### 3. `pandoc` — Compile Markdown Playbooks into Official PDF Documents
**Purpose:** Compile Markdown SOP files into formatted PDF documents with cover pages and tables of contents.
```bash
sudo apt install -y pandoc weasyprint
pandoc /Users/frog/code/github/frog/soc-command/kali-soc-master-commands.md -o /tmp/SOC_Master_Playbook.pdf --pdf-engine=weasyprint
```

---

### 4. `shellcheck` — Static Analysis & Linting for Runbook Scripts
**Purpose:** Audit bash automation scripts and incident response helper scripts for syntax errors and edge cases.
```bash
sudo apt install -y shellcheck
shellcheck /opt/soc-playbooks/scripts/containment_helper.sh
```

---

### 5. `yamllint` — Linting Sigma Rules & Ansible Playbooks
**Purpose:** Verify YAML syntax and indentation standards across all detection engineering rules and playbooks.
```bash
sudo apt install -y yamllint
yamllint /opt/soc-playbooks/ansible/
```

---

### 6. `markdownlint` — Style & Format Verification for SOP Documentation
**Purpose:** Enforce consistent formatting, header hierarchy, and link validity in markdown documentation.
```bash
sudo npm install -g markdownlint-cli
markdownlint /opt/soc-playbooks/docs/*.md
```

---

### 7. `tree` — Visualize Playbook Repository Architecture
**Purpose:** Generate a clean directory layout diagram of the SOC standard operating procedure repository.
```bash
sudo apt install -y tree
tree /opt/soc-playbooks/ -L 3
```

---

### 8. `diff` — Compare Policy & Playbook Revisions
**Purpose:** Review exact changes between two playbook versions during policy reviews.
```bash
diff -u /opt/playbooks/v1/ransomware_sop.md /opt/playbooks/v2/ransomware_sop.md
```

---

### 9. `visudo -c` — Syntax Validation for SOC Privilege Policies
**Purpose:** Verify sudoers configuration syntax to prevent locking administrators out of SOC nodes.
```bash
sudo visudo -c
```

---

### 10. `pre-commit` — Enforce Automated Quality Checks on Commits
**Purpose:** Run automatic linting and security scans before allowing commits to the SOC playbook repository.
```bash
pip install pre-commit --break-system-packages
pre-commit run --all-files
```

---

### 11. `jq` — Validate JSON Configuration Schemas
**Purpose:** Verify that JSON-based playbook configurations, API payload templates, and schemas are valid.
```bash
cat /opt/soc-playbooks/schemas/incident_schema.json | jq . > /dev/null && echo "JSON Valid"
```

---

### 12. `gpg --sign` — Cryptographically Sign Approved Policies
**Purpose:** Apply digital signatures to approved SOP documents to guarantee authenticity and prevent tampering.
```bash
gpg --armor --detach-sign /opt/soc-playbooks/policies/SOC_Charter_v1.0.pdf
```

---

### 13. `sha256sum` — Policy Baseline Checksum Generation
**Purpose:** Create cryptographic checksum baselines of all authorized SOC policy documents.
```bash
sha256sum /opt/soc-playbooks/policies/*.pdf > /opt/soc-playbooks/policies/baseline.sha256
```

---

### 14. `tar` — Versioned SOP Release Packaging
**Purpose:** Package approved playbook releases for distribution across multiple SOC shifts and environments.
```bash
tar -czvf /tmp/soc_sop_release_v2.0.tar.gz /opt/soc-playbooks/docs/
```

---

### 15. `grep` — Search Policy Repositories for Specific Procedures
**Purpose:** Search hundreds of Markdown runbooks for specific keywords or containment steps.
```bash
grep -rn "containment" /opt/soc-playbooks/
```

---

### 16. `chmod` / `chown` — Enforce Strict Access Control on SOPs
**Purpose:** Restrict playbook write permissions to SOC Leadership while granting read access to Level 1/2 analysts.
```bash
sudo chown -R root:soc-analysts /opt/soc-playbooks/
sudo chmod -R 750 /opt/soc-playbooks/
```

---

### 17. `envsubst` — Template Variables in Automated Playbooks
**Purpose:** Substitute environmental variables (IPs, domain names, API keys) into playbook templates.
```bash
export C2_IP="185.220.101.5"
envsubst < /opt/soc-playbooks/templates/block_template.conf > /tmp/active_block.conf
```

---

### 18. `make` — Automate Playbook Build & Validation
**Purpose:** Execute Makefile commands to test, lint, and build all SOC documentation in one command.
```bash
make test && make build-pdf
```

---

### 19. `wc -l` — Document Metric & Completeness Tracking
**Purpose:** Track line count and documentation metrics across standard operating procedure guides.
```bash
wc -l /opt/soc-playbooks/docs/*.md
```

---

### 20. `git log` — Governance & Policy Audit Trail
**Purpose:** Generate an audit report of who modified each standard operating procedure and when.
```bash
git log --pretty=format:"%h - %an, %ar : %s" -n 15
```

---
*SOC Command Reference - Class 16*
