# SOC Metric Catalogue — Class 13

Every metric the dashboard uses. Format for each:

> **Formula** · **Data source** (column in the lab CSVs) · **Target/Threshold** ·
> **Decision it drives** · **How it gets gamed → counter-metric**

Rule of thumb: **never report a single number** — report the trend and the target
next to it. And for any duration that has a long tail (dwell time), **report the
median, not the mean** — one 3-week slow-burn case drags the average into
uselessness.

---

## 1. Volume / operational

### Alert volume
- **Formula:** count of rows in `alerts.csv` per period.
- **Source:** `alerts.csv` → `alert_id`, `timestamp`, `month`.
- **Target:** no absolute target; watch the **trend** and the **per-analyst** load.
- **Drives:** staffing, tuning priorities, tooling spend.
- **Gaming:** raising alert thresholds to cut the number → real detections lost. **Counter-metric:** true-positive yield, detection coverage.

### Events per second (EPS) / ingest volume
- **Formula:** log lines ingested ÷ seconds (see `class-13-command.md` #2).
- **Source:** SIEM platform (not in the lab CSVs — discussed only).
- **Target:** within licensed capacity; alert if sustained > 80% of licence.
- **Drives:** SIEM licence renewal, storage budget (Class 19).

### Incidents opened
- **Formula:** count of rows in `incidents.csv` per period.
- **Source:** `incidents.csv` → `incident_id`, `month`.
- **Target:** trend; a spike is a signal (campaign), not automatically bad.
- **Drives:** IR capacity, whether to invoke major-incident process.

### Alerts per analyst per shift
- **Formula:** alerts handled ÷ analyst-shifts in period.
- **Source:** `alerts.csv` → `analyst`, `shift`.
- **Target:** organisation-specific ceiling (e.g. < 40/analyst/shift for quality triage).
- **Drives:** burnout risk, shift rebalancing, automation business case.

---

## 2. Speed (the "mean time to…" family)

All computed from the incident timeline in `incidents.csv`. Columns are already
pre-computed in minutes (`mttd_minutes`, `mtta_minutes`, `mttc_minutes`,
`mttr_minutes`) **and** as raw timestamps (`first_activity`, `detected`,
`acknowledged`, `contained`, `resolved`) so students can rebuild them.

| Metric | Formula (from timestamps) | Meaning | Report as |
|--------|---------------------------|---------|-----------|
| **MTTD** — mean time to detect | `detected − first_activity` | dwell time; how long the adversary was in before we saw them | **median** (long tail) |
| **MTTA** — mean time to acknowledge | `acknowledged − detected` | how fast a human picks up the alert | mean + p90 |
| **MTTC** — mean time to contain | `contained − detected` | how fast we stop the bleeding | mean by severity |
| **MTTR** — mean time to respond/resolve | `resolved − detected` | full lifecycle to closure | mean by severity |

- **Targets (lab):** MTTA < 15 min; MTTC — Critical < 60 min, High < 4 h, Medium < 24 h, Low < 72 h (this is also the SLA); MTTR trend down.
- **Drives:** where automation/playbooks pay off, SLA feasibility, staffing by shift.
- **Gaming:** mark "contained" early; resolve then silently reopen. **Counter-metric:** reopen rate, SLA breach rate, false-escalation rate.
- **Watch:** MTTD **mean vs median** — in this dataset the mean is ~10× the median because ~12% of incidents are slow-burn. Reporting the mean would say detection is getting worse when the median shows it improving.

---

## 3. Quality / effectiveness

### False-positive rate
- **Formula:** `(False Positive + Duplicate) ÷ total alerts`.
- **Source:** `alerts.csv` → `disposition`.
- **Target:** trend down; < 50% is a common working goal for tuned rules.
- **Drives:** detection-engineering backlog (Class 06), analyst load.
- **Gaming:** suppress noisy rules regardless of value. **Counter-metric:** detections missed, ATT&CK coverage.

### True-positive yield
- **Formula:** `True Positive ÷ total alerts`.
- **Source:** `alerts.csv` → `disposition`.
- **Target:** trend up (rules are getting sharper).
- **Drives:** confidence in the pipeline; auto-escalation candidates.

### Escalation accuracy (1 − false-escalation rate)
- **Formula:** `1 − (false_escalation = "Yes" ÷ incidents opened)`.
- **Source:** `incidents.csv` → `false_escalation`.
- **Target:** > 90% (few cases escalated to IR that turn out benign).
- **Drives:** Tier-1 training, triage-criteria quality.

### SLA compliance
- **Formula:** `(incidents NOT breached) ÷ incidents`, overall and **by severity**.
- **Source:** `incidents.csv` → `sla_breached`, `sla_target_minutes`, `severity`.
- **Target:** ≥ 95% per severity band.
- **Drives:** the single number the customer/Board cares about; staffing and playbook investment where a band is failing.
- **Gaming:** downgrade severity so the clock is looser. **Counter-metric:** severity-downgrade rate, post-incident severity review.

### MITRE ATT&CK technique coverage
- **Formula:** `techniques with ≥1 validated detection ÷ techniques in scope`.
- **Source:** `kri_monthly.csv` → `attack_technique_coverage_pct` (also see `class-13-command.md` #5 for tactic distribution from live alerts).
- **Target:** trend up toward an agreed scoped set (not 100% of all ATT&CK).
- **Drives:** detection-engineering roadmap, purple-team priorities.

---

## 4. Risk indicators (KRI) — the CISO / Board view

All from `kri_monthly.csv`, one row per month. A KRI is **leading**: it tells you
risk is rising **before** an incident proves it.

| KRI | Column | Threshold (amber / red) | Risk it signals |
|-----|--------|-------------------------|-----------------|
| Endpoint EDR coverage % | `endpoint_edr_coverage_pct` | < 95 / < 90 | blind spots on unmanaged hosts |
| Log-source health % | `log_source_health_pct` | < 95 / < 90 | detections silently not firing |
| Open critical vulnerabilities | `critical_vulns_open` | > 20 / > 35 | exploitable exposure |
| Mean critical-vuln age (days) | `mean_critical_vuln_age_days` | > 14 / > 30 | patch process not keeping up |
| ATT&CK technique coverage % | `attack_technique_coverage_pct` | < 50 / < 35 | detection gaps |
| Phishing simulation click rate % | `phishing_sim_click_rate_pct` | > 10 / > 20 | human-layer exposure |
| Privileged accounts without MFA | `privileged_accounts_without_mfa` | > 2 / > 5 | account-takeover risk |
| Stale threat-intel indicators % | `stale_threat_intel_pct` | > 15 / > 30 | acting on expired IOCs |

- **Drives:** where the CISO spends budget and political capital; what goes in the enterprise risk register.
- **Reporting:** RAG tile + 6-month sparkline per KRI. One sentence: current value, direction, action.

---

## 5. Metrics to be suspicious of (vanity / trap metrics)

| Metric | Why it misleads | Ask instead |
|--------|-----------------|-------------|
| "Events collected" / "logs per day" | measures the bill, not security | coverage of **critical** sources |
| "Attacks blocked" | mostly internet background noise | incidents involving a real objective |
| "% of alerts closed" | rewards closing fast, not correctly | true-positive yield, reopen rate |
| "Number of dashboards / rules" | activity, not outcome | detections mapped to ATT&CK **and validated** |
| Single-number MTTR | hides the distribution and severity mix | MTTC/MTTR **by severity**, with p90 |
| Uptime of the SIEM | necessary, not sufficient | log-source health (are the feeds arriving?) |

---

## 6. Counter-metric pairs (put both on the dashboard)

| If you incentivise… | …you risk | So also show |
|---------------------|-----------|--------------|
| Low MTTR | premature closure | reopen rate, SLA breach |
| Low false-positive rate | suppressed real detections | ATT&CK coverage, missed detections |
| High alert-closure rate | rubber-stamping | escalation accuracy, QA sample pass rate |
| Fast triage (low MTTA) | shallow triage | false-escalation rate, Tier-2 kickback rate |
| More detections shipped | noisy, unvalidated rules | true-positive yield, per-rule FP rate |
