# Class 13 Lab — SOC Metrics, KPI, KRI, Dashboards & Executive Reporting

Build a real SOC performance dashboard from six months of (synthetic) operations
data, then turn it into a one-page executive brief. **Excel and Power BI paths
both included** — pick whichever your students have.

> All data is generated locally by `generate_data.py` (seed `1313`). Nothing
> here touches a network or a live SIEM. A rebuild reproduces the exact same
> rows, so [`ANSWER-KEY.md`](ANSWER-KEY.md) never drifts.

---

## The scenario

You are the SOC Manager at **Meghna Bank**. The CISO has the quarterly Board risk
review in two weeks and has asked for:

1. an **operational dashboard** the SOC leads watch daily, and
2. a **one-page executive scorecard** for the Board pack — "are we getting better
   or worse, and where is the risk?"

Your analysts have exported three files covering **March–August 2026**:

| File | Grain | What it is |
|------|-------|-----------|
| `data/alerts.csv` | one row per alert (~3,160) | everything the SOC received from SIEM/EDR/FW/WAF/IDS/Email-GW/CASB, with disposition (true/false positive) and whether it became an incident |
| `data/incidents.csv` | one row per escalated true positive (~283) | the case work — full timeline (first activity → detected → acknowledged → contained → resolved), severity, category, SLA target/breach, analyst |
| `data/kri_monthly.csv` | one row per month (6) | risk indicators for the CISO view — EDR coverage, log-source health, open critical vulns, ATT&CK technique coverage, phishing click rate, privileged accounts without MFA |

There is a story buried in the data (tuning is working, a July phishing campaign,
a night-shift triage problem). The lab is about **making that story visible** and
**reporting it to three different audiences without lying with charts**.

---

## Files

| Path | Purpose |
|------|---------|
| `generate_data.py` | Builds `data/*.csv`. Run once. Deterministic. |
| `METRIC-DEFINITIONS.md` | The metric catalogue — every KPI/KRI with its formula, data source, target, and how it gets gamed. Read this first. |
| `DASHBOARD-WALKTHROUGH.md` | Step-by-step build — **Part A Excel** (PivotTables + slicers), **Part B Power BI** (data model + DAX measures). |
| `EXECUTIVE-REPORT-TEMPLATE.md` | The one-pager structure + a fill-in-the-blank monthly service review. |
| `ANSWER-KEY.md` | Instructor copy — every number the dashboard should land on, plus the "story" talking points and common student mistakes. |

---

## Setup

### Data

```bash
cd labs/class-13-metrics-dashboard
python3 generate_data.py          # writes data/alerts.csv, incidents.csv, kri_monthly.csv
```

No non-stdlib packages needed. If `data/` is already committed, you can skip this.

### Tools — pick one path

| Path | Needs | Notes |
|------|-------|-------|
| **Excel** | Excel 2016+ **or** LibreOffice Calc **or** Google Sheets | Works on Kali via `sudo apt install -y libreoffice-calc`. PivotTables + slicers + PivotCharts are enough for the whole lab. |
| **Power BI** | Power BI Desktop (free, **Windows only**) | The "real" BI path — star schema, DAX measures, drill-through. Run it in a Windows VM or on the student's host. |
| **Fallback (no GUI)** | `python3` + `matplotlib` (already used in `class-13-command.md`) | `pip install pandas matplotlib --break-system-packages` — students who can't run either app compute the same measures in pandas and render the charts to PNG. |

---

## How to run the class (~3 hours)

A delivery plan for the live session. Times are a guide; the lab is the point.

### Block 0 — Framing (10 min)
The Board question: *"Are we secure?"* is unanswerable. What you **can** answer:
*"Here is what we handled, how fast, how well, and where the risk sits — and the
trend."* Define the four words in the title:
- **Metric** — anything you measure (alert count).
- **KPI** — a metric with a **target** that reflects a goal (MTTR < 4 h).
- **KRI** — a metric with a **threshold** that reflects **risk exposure**, leading not lagging (critical vulns open > 25 → risk rising).
- **SLA** — a **commitment** to a stakeholder, with consequences (respond to Critical in 60 min, 95% of the time).

### Block 1 — The SOC metric taxonomy (25 min)
Walk [`METRIC-DEFINITIONS.md`](METRIC-DEFINITIONS.md). Four families:
1. **Volume / operational** — alerts, EPS, incidents, alerts-per-analyst.
2. **Speed** — MTTD, MTTA, MTTC, MTTR, dwell time.
3. **Quality / effectiveness** — false-positive rate, true-positive yield, escalation accuracy, ATT&CK coverage, SLA compliance.
4. **Risk (KRI)** — coverage gaps, vuln exposure, phishing susceptibility, MFA gaps, stale intel.
For each: what decision does it drive? Who owns it? What happens if an analyst games it?

### Block 2 — What makes a metric good, and vanity metrics (15 min)
- Actionable, owned, trended (never a single number), has a target/threshold, has a named data source.
- **Vanity metrics** to challenge: "number of events collected", "attacks blocked", "% alerts closed" (close them fast by ignoring them...), dashboards with 40 widgets nobody looks at.
- Gaming: reward low MTTR → analysts resolve-then-reopen; reward low FP rate → analysts suppress noisy-but-real rules. Every KPI needs a **counter-metric**.

### Block 3 — Dashboard design (15 min)
- **Three audiences, three layers**: analyst (queue, real-time, granular) → SOC manager (SLA, workload, trends, this week) → CISO/Board (5–7 numbers, RAG status, quarter trend, one sentence each).
- One screen. Lead with the answer. Time series for trend, bar for comparison, big-number tiles for status. RAG against target, not raw value.
- Refresh cadence matches the decision cadence. A Board metric that changes daily is noise to the Board.

### Block 4 — Reporting cadence (10 min)
Daily shift handover → weekly ops review → **monthly service review** (the [`EXECUTIVE-REPORT-TEMPLATE.md`](EXECUTIVE-REPORT-TEMPLATE.md)) → quarterly Board pack. Data + **narrative**: what changed, why, what you're doing about it, what you need.

### Block 5 — LAB (60–75 min)
Students build the dashboard from [`DASHBOARD-WALKTHROUGH.md`](DASHBOARD-WALKTHROUGH.md).
Milestones (check as you circulate):
1. Data loaded, incident durations converted to hours/minutes correctly.
2. KPI tile row: MTTD (median), MTTA, MTTC, MTTR, SLA compliance %, true-positive yield.
3. Trend chart: monthly alert volume vs true-positive yield (the tuning story).
4. SLA compliance by severity (the Critical-containment problem).
5. Slicer/filter by month, severity, source, shift — and find the night-shift MTTA spike.
6. CISO sheet: the 6 KRIs as a monthly trend with threshold lines.

### Block 6 — Executive readout simulation (15 min)
Each student (or pair) gets **2 minutes** to brief "the Board" from their one-pager:
3 things going well, 1 risk, 1 ask. Class critiques: was it the right altitude?
Any chart that misleads? Did they bury the phishing campaign or explain it?

### Block 7 — Wrap + homework (5 min)
Homework: add a **forecast** (next-quarter incident volume via a trendline) and a
**capacity metric** (incidents-per-analyst vs a sane ceiling) and write the
"resourcing ask" paragraph for the Board pack. Feeds Class 19.

---

## What "done" looks like

A two-sheet dashboard (**Operations** + **Executive**) that a stranger can read in
30 seconds and correctly answer:
- Is SOC performance improving? *(yes — noise down ~34%, TP yield 17%→44%, MTTC and SLA breaches down)*
- What's the biggest operational weakness? *(Critical-severity containment — 34% breach the 60-min SLA; night-shift triage is 3× slower)*
- What happened in July? *(phishing campaign — alert spike + incident spike, contained without SLA blowout)*
- Where is residual risk? *(ATT&CK coverage still ~49%, ~17 critical vulns open)*

Exact figures and the full talking track: [`ANSWER-KEY.md`](ANSWER-KEY.md).
