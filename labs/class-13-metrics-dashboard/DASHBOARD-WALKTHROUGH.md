# Dashboard Build Walkthrough — Class 13

Two paths to the same dashboard. Do **Part A (Excel)** if that's what your
students have; **Part B (Power BI)** if you want the proper BI workflow. Part C is
the no-GUI fallback in pandas.

The finished workbook/report has **two pages**:

- **Operations** — for the SOC leads: KPI tiles, trend, SLA by severity, source/shift breakdowns, month slicer.
- **Executive** — for the CISO/Board: 6 KRI tiles with RAG + sparkline, one headline chart, a narrative box.

---

## Data recap

```
data/alerts.csv        alert_id, timestamp, month, source, rule_name, severity,
                       mitre_tactic, disposition, escalated_to_incident, analyst, shift

data/incidents.csv     incident_id, source_alert_id, month, category, severity, mitre_tactic,
                       first_activity, detected, acknowledged, contained, resolved,
                       mttd_minutes, mtta_minutes, mttc_minutes, mttr_minutes,
                       sla_target_minutes, sla_breached, analyst_tier1, analyst_tier2,
                       shift, false_escalation

data/kri_monthly.csv   month, endpoint_edr_coverage_pct, log_source_health_pct,
                       critical_vulns_open, mean_critical_vuln_age_days,
                       attack_technique_coverage_pct, phishing_sim_click_rate_pct,
                       privileged_accounts_without_mfa, stale_threat_intel_pct,
                       alerts_total, true_positive_yield_pct, incidents_opened,
                       sla_breaches, backlog_open_month_end, analyst_overtime_hours
```

The `*_minutes` columns in `incidents.csv` are pre-computed so you can start fast.
**Task 0 for every student:** rebuild `mttc_minutes` yourself from
`contained − detected` and confirm it matches — that's the point of the lesson.

---

# Part A — Excel / LibreOffice Calc

### A1. Load the three CSVs

Excel: **Data ▸ Get Data ▸ From Text/CSV** for each file, load `alerts` and
`incidents` as **connections + add to Data Model** (enables cross-table work and
slicers). LibreOffice/Sheets: just open/import into three sheets.

Set column types: `timestamp`, `first_activity`, `detected`, `acknowledged`,
`contained`, `resolved` → **Date/Time**. Everything `*_minutes` and `*_pct` →
**Number**.

### A2. Helper columns on `incidents`

Add these so charts read cleanly:

| Column | Formula (row 2 shown) | Why |
|--------|----------------------|-----|
| `mttc_hours` | `=[@mttc_minutes]/60` | Board reads hours, not minutes |
| `mttr_hours` | `=[@mttr_minutes]/60` | same |
| `mttd_check` | `=(detected-first_activity)*1440` | must equal `mttd_minutes` (±0.1) |
| `breach_flag` | `=IF([@sla_breached]="Yes",1,0)` | numeric for averaging → breach rate |
| `within_sla` | `=1-[@breach_flag]` | for compliance % |

### A3. KPI tile row (Operations page)

Use a **PivotTable** off `incidents` (or `AVERAGEIFS`/`MEDIAN` array formulas).
Target the numbers in [`ANSWER-KEY.md`](ANSWER-KEY.md):

| Tile | Formula | Lands near |
|------|---------|-----------|
| MTTD (median) | `=MEDIAN(incidents[mttd_minutes])/60` h | ~3.1 h |
| MTTA (mean) | `=AVERAGE(incidents[mtta_minutes])` min | ~8.5 min |
| MTTC (mean) | `=AVERAGE(incidents[mttc_minutes])/60` h | ~10.2 h |
| MTTR (mean) | `=AVERAGE(incidents[mttr_minutes])/60` h | ~36 h |
| SLA compliance | `=AVERAGE(incidents[within_sla])` → format % | ~87% |
| True-positive yield | `=COUNTIFS(alerts[disposition],"True Positive")/COUNTA(alerts[alert_id])` | ~29% |
| Incidents opened | `=COUNTA(incidents[incident_id])` | 283 |
| False-escalation rate | `=COUNTIFS(incidents[false_escalation],"Yes")/COUNTA(incidents[incident_id])` | ~5.7% |

Format each as a big-number cell with the **target** underneath and conditional
formatting (green if meeting target, amber/red if not).

### A4. Trend chart — the tuning story

PivotTable: **Rows** = `month` (from `alerts`), **Values** = Count of `alert_id`.
Add a second series: true-positive yield per month
(`=COUNTIFS(alerts[month],<m>,alerts[disposition],"True Positive")/COUNTIFS(alerts[month],<m>)`).

PivotChart: **combo** — alert volume as **columns** (left axis), TP yield as a
**line** (right axis, %). This one chart shows noise falling while quality rises.

### A5. SLA compliance by severity — the weakness

PivotTable: **Rows** = `severity` (order Critical→Low with a custom sort),
**Values** = Average of `within_sla` (% format) and Count of `incident_id`.
Bar chart. Critical sits around **66%** compliance — well under the 95% target.
Add a data-labelled 95% reference line.

### A6. Breakdowns + slicers

- PivotTable + bar: incidents by `category` (Phishing dominates, ~90).
- PivotTable + bar: alert count by `source` (SIEM and EDR are the loudest).
- PivotTable: Average of `mtta_minutes` by `shift` → **Night ≈ 21 min vs Morning ≈ 6 min**. Call this out; it's a real finding.
- Insert **Slicers** for `month`, `severity`, `source`, `shift`, connected to all
  Operations PivotTables (**Slicer ▸ Report Connections**). Demonstrate filtering
  to July and watching the phishing spike appear.

### A7. Executive page

Pull `kri_monthly.csv` onto its own sheet. For each of the 8 KRIs:

- a **tile** = latest month's value, with conditional formatting against the
  amber/red thresholds in [`METRIC-DEFINITIONS.md`](METRIC-DEFINITIONS.md) §4;
- a **sparkline** (`Insert ▸ Sparklines ▸ Line`) across the 6 months;
- keep only 6–8 tiles. This page has **no PivotTable clutter**, one optional
  headline chart (EDR coverage % and phishing click rate % over 6 months), and a
  text box for the narrative (see `EXECUTIVE-REPORT-TEMPLATE.md`).

### A8. Polish

Consistent number formats, no gridlines on the Executive page, a title with the
reporting period ("Meghna Bank SOC — Mar–Aug 2026"), a "data as of" date, and a
footer naming the data source. Hide the working sheets.

---

# Part B — Power BI Desktop

### B1. Get data

**Home ▸ Get data ▸ Text/CSV** ×3. In **Power Query**:
- `incidents`: set the five timestamp columns to **Date/Time**; set `*_minutes` to **Decimal**. **Close & Apply**.
- `alerts`: set `timestamp` to Date/Time.
- `kri_monthly`: set `month` to Text (it's a `YYYY-MM` label), all metrics to Decimal/Whole.

### B2. Date table + model

Create a date table:

```DAX
DimDate =
ADDCOLUMNS (
    CALENDAR ( DATE(2026,3,1), DATE(2026,8,31) ),
    "Month",      FORMAT ( [Date], "YYYY-MM" ),
    "MonthName",  FORMAT ( [Date], "MMM YYYY" ),
    "MonthSort",  YEAR([Date])*100 + MONTH([Date])
)
```

Mark it as a date table. Relationships:
- `DimDate[Date]` → `incidents[detected]` (active, single direction)
- `DimDate[Date]` → `alerts[timestamp]` (you may need `DimDate[Date]` vs the date
  portion — add a `Date` column in Power Query: `Date.From([timestamp])`)
- `kri_monthly[month]` → a `DimDate` month key, or just slice it by its own `month` column.

Sort `MonthName` by `MonthSort`.

### B3. Core measures (new **_Measures** table)

```DAX
Incidents           = DISTINCTCOUNT ( incidents[incident_id] )
Alerts              = DISTINCTCOUNT ( alerts[alert_id] )

MTTD median (hrs)   = MEDIAN ( incidents[mttd_minutes] ) / 60
MTTA (min)          = AVERAGE ( incidents[mtta_minutes] )
MTTC (hrs)          = AVERAGE ( incidents[mttc_minutes] ) / 60
MTTR (hrs)          = AVERAGE ( incidents[mttr_minutes] ) / 60

SLA breaches        = CALCULATE ( [Incidents], incidents[sla_breached] = "Yes" )
SLA compliance %    = DIVIDE ( [Incidents] - [SLA breaches], [Incidents] )

TP alerts           = CALCULATE ( [Alerts], alerts[disposition] = "True Positive" )
True positive yield % = DIVIDE ( [TP alerts], [Alerts] )
False positive %    =
    DIVIDE (
        CALCULATE ( [Alerts], alerts[disposition] IN { "False Positive", "Duplicate" } ),
        [Alerts]
    )

False escalations   = CALCULATE ( [Incidents], incidents[false_escalation] = "Yes" )
False escalation %   = DIVIDE ( [False escalations], [Incidents] )
```

Targets as measures so RAG logic is one place:

```DAX
SLA target %        = 0.95
SLA RAG =
VAR v = [SLA compliance %]
RETURN SWITCH ( TRUE(), v >= 0.95, "Green", v >= 0.85, "Amber", "Red" )
```

### B4. Operations page

- **Card** visuals for the KPI row, each with a conditional-formatting rule off its `… RAG` measure.
- **Line + clustered column** chart: axis `DimDate[MonthName]`, columns `[Alerts]`, line `[True positive yield %]` (secondary axis).
- **Clustered bar**: axis `incidents[severity]`, value `[SLA compliance %]`, constant line at `0.95`. Set severity sort order via a sort column.
- **Clustered bar**: `alerts[source]` vs `[Alerts]`.
- **Matrix**: rows `incidents[shift]`, values `[MTTA (min)]`, `[Incidents]` — Night stands out.
- **Slicers**: `DimDate[MonthName]`, `incidents[severity]`, `alerts[source]`, `incidents[shift]`.
- Turn on **drill-through** to an incident-detail page (table of the timeline columns) filtered by `severity` / `category`.

### B5. Executive page

- 8 **card** visuals (or a single multi-row card) for the KRIs, latest month via
  `CALCULATE ( MAX ( kri_monthly[...] ), kri_monthly[month] = "2026-08" )` or a
  "last month" measure using `LASTNONBLANK`.
- Conditional formatting against the thresholds table.
- One **line chart**: `endpoint_edr_coverage_pct` and `phishing_sim_click_rate_pct` over `month`.
- A **text box** narrative. Keep this page to ~6 visuals.
- **File ▸ Export ▸ PDF** → this is the page that goes in the Board pack.

### B6. Sanity checks

Match [`ANSWER-KEY.md`](ANSWER-KEY.md). If `[Alerts]` ≠ 3,162 your date
relationship is filtering rows — check the `alerts[Date]` column and the
DimDate range.

---

# Part C — pandas fallback (no spreadsheet app)

```bash
pip install pandas matplotlib --break-system-packages
```

```python
import pandas as pd, matplotlib.pyplot as plt
a = pd.read_csv("data/alerts.csv", parse_dates=["timestamp"])
i = pd.read_csv("data/incidents.csv",
                parse_dates=["first_activity","detected","acknowledged","contained","resolved"])
k = pd.read_csv("data/kri_monthly.csv")

# rebuild MTTC and verify
i["mttc_calc"] = (i.contained - i.detected).dt.total_seconds()/60
assert (i.mttc_calc - i.mttc_minutes).abs().max() < 0.2

# KPI row
print("MTTD median (h):", round(i.mttd_minutes.median()/60, 1))
print("MTTA mean (min):", round(i.mtta_minutes.mean(), 1))
print("MTTC mean (h):",  round(i.mttc_minutes.mean()/60, 1))
print("MTTR mean (h):",  round(i.mttr_minutes.mean()/60, 1))
print("SLA compliance %:", round(100*(i.sla_breached.eq("No")).mean(), 1))
print("TP yield %:", round(100*a.disposition.eq("True Positive").mean(), 1))

# tuning-story chart
g = a.groupby("month").agg(alerts=("alert_id","size"),
        tp_yield=("disposition", lambda s: 100*s.eq("True Positive").mean()))
fig, ax1 = plt.subplots(figsize=(8,4))
ax1.bar(g.index, g.alerts, alpha=.5, label="alerts")
ax2 = ax1.twinx(); ax2.plot(g.index, g.tp_yield, "o-", color="tab:green", label="TP yield %")
ax1.set_title("Alert volume vs true-positive yield — Mar–Aug 2026")
fig.tight_layout(); fig.savefig("/tmp/tuning_story.png", dpi=150)

# SLA by severity
sev = pd.Categorical(i.severity, ["Critical","High","Medium","Low"], ordered=True)
print(i.assign(sev=sev).groupby("sev", observed=True)
        .sla_breached.apply(lambda s: round(100*s.eq("No").mean(),1)))

# night-shift triage
print(i.groupby("shift").mtta_minutes.mean().round(1))
```

The [`class-13-command.md`](../../class-13-command.md) reference (#1, #13, #17)
covers the same MTTD/MTTR and charting steps at the command line.
