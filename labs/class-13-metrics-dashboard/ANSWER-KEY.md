# Instructor Answer Key — Class 13

Numbers are from the committed dataset (`generate_data.py`, seed `1313`). Small
rounding differences are fine; if a student is off by more than ~1–2% on a
headline number, something is wrong with their model (usually a date relationship
dropping rows, minutes-vs-hours, or mean where the key says median).

Hand out the room without this file if you want students to work cold.

---

## Dataset shape

| | Value |
|---|---|
| Alerts | **3,162** (Mar–Aug 2026) |
| Incidents (escalated true positives) | **283** |
| Escalation rate (incidents ÷ alerts) | **8.95%** |
| Sources, loudest first | SIEM 951 · EDR 722 · Firewall 412 · Email-GW 339 · WAF 314 · IDS 307 · CASB 117 |
| Incidents by severity | High 109 · Medium 108 · Critical 35 · Low 31 |
| Incidents by category | Phishing 90 · Unauthorized Access 50 · Policy Violation 40 · Malware 36 · Recon/Scanning 33 · DoS 15 · Data Loss 11 · Insider 8 |

---

## KPI tile row (whole period)

| KPI | Value | Target | Verdict |
|-----|-------|--------|---------|
| MTTD — **median** dwell | **185 min ≈ 3.1 h** | trend ↓ | improving (308→132 min Mar→Aug) |
| MTTD — mean dwell | 1,751 min ≈ 29 h | — | **do not report this** — ~12% slow-burn cases wreck the average |
| MTTA — mean acknowledge | **8.5 min** | < 15 min | meeting |
| MTTC — mean contain | **614 min ≈ 10.2 h** | by severity | see below |
| MTTR — mean resolve | **2,169 min ≈ 36 h** | trend ↓ | improving (43→31 h) |
| SLA compliance (all severities) | **87.3%** (36 breaches / 283) | ≥ 95% | **failing** — driven by Critical |
| True-positive yield | **28.6%** | trend ↑ | improving (16.7%→43.6%) |
| False-positive + duplicate rate | **55.8%** | < 50% | close, improving (63%→44%) |
| False-escalation rate | **5.7%** (16 / 283) | < 10% | meeting |

---

## MTTC and SLA compliance by severity — the operational weakness

| Severity | n | Mean MTTC | SLA target | **SLA compliance** |
|----------|---|-----------|-----------|--------------------|
| Critical | 35 | **51 min** | 60 min | **65.7%** ← the problem |
| High | 109 | 172 min | 240 min | 82.6% |
| Medium | 108 | 752 min | 1,440 min | 97.2% |
| Low | 31 | 2,322 min | 4,320 min | 93.5% |

The mean Critical MTTC (51 min) is *inside* SLA, but **a third of Critical
incidents still breach** — the distribution has a fat right tail. This is the
teaching point: **report compliance % and p90, not just the mean.** A mean that
looks fine can hide a serious tail.

---

## Trends by month (the "tuning is working" story)

| Month | Alerts | FP+Dup % | TP yield % | Incidents | MTTD median (min) | SLA breach % |
|-------|-------:|---------:|-----------:|----------:|------------------:|-------------:|
| 2026-03 | 598 | 63.0 | 16.7 | 27 | 308 | 22.2 |
| 2026-04 | 551 | 60.8 | 22.0 | 36 | 238 | 19.4 |
| 2026-05 | 517 | 55.5 | 28.2 | 40 | 184 | 20.0 |
| 2026-06 | 469 | 55.4 | 29.4 | 53 | 235 | 13.2 |
| 2026-07 | **630** | 52.4 | 36.0 | **72** | 172 | 9.7 |
| 2026-08 | 397 | 43.8 | 43.6 | 55 | 132 | **1.8** |

- **Alert noise down ~34%** March→August while headcount is flat → tuning + automation working.
- **TP yield 17% → 44%** → the alerts that fire are increasingly real.
- **SLA breach rate 22% → 2%** → containment discipline improving.
- **July is the exception:** alert *and* incident spike — that's the phishing campaign, not a regression. It was absorbed without an SLA blowout (breach rate still fell). Students who report July as "performance got worse" have misread it — that's a deliberate trap.

---

## Night-shift triage problem (found via the shift slicer)

| Shift | Incidents | Mean MTTA |
|-------|----------:|----------:|
| Morning | 147 | **5.9 min** |
| Evening | 113 | 9.5 min |
| Night | 23 | **20.6 min** |

Night acknowledges **~3.5× slower** than morning. Low volume (23 incidents) so
it doesn't move the overall MTTA much — but it's a real coverage risk and a
concrete resourcing ask for the Board pack (Class 19). Good students find this;
great students note the small-n caveat.

---

## Analyst (Tier-1) incident load — roughly even

n.akter 53 · t.begum 52 · a.rahman 52 · s.khatun 47 · r.islam 41 · m.hasan 38.
No single analyst is overloaded on incident *ownership*; if a student wants a
workload story, the alert-level `analyst` + `shift` breakdown is the place to look.

---

## Executive / KRI page (compare first vs last month)

| KRI | Mar 2026 | Aug 2026 | Threshold (amber/red) | Aug status |
|-----|---------:|---------:|-----------------------|------------|
| Endpoint EDR coverage % | 87.6 | **96.0** | < 95 / < 90 | 🟢 (just crossed) |
| Log-source health % | 92.3 | **98.2** | < 95 / < 90 | 🟢 |
| Open critical vulnerabilities | 43 | **17** | > 20 / > 35 | 🟢 (crossed under 20) |
| Mean critical-vuln age (days) | 20.2 | ~7 | > 14 / > 30 | 🟢 |
| ATT&CK technique coverage % | 33.1 | **49.2** | < 50 / < 35 | 🟡 — still short of 50% |
| Phishing sim click rate % | 17.8 | **7.9** | > 10 / > 20 | 🟢 (crossed under 10) |
| Privileged accounts without MFA | 10 | **1** | > 2 / > 5 | 🟢 |
| Stale threat-intel indicators % | 13.2 | ~4 | > 15 / > 30 | 🟢 |

Every KRI is trending the right way. The one that is **still amber** is **ATT&CK
technique coverage (~49%)** — that's the honest "where we're still exposed" line
for the Board, and it hands work to Class 06 / Class 17.

---

## The four questions the finished dashboard must answer

1. **Is SOC performance improving?** — Yes. Alert noise −34%, true-positive yield 17%→44%, SLA breach rate 22%→2%, MTTD median 308→132 min. All flat-headcount.
2. **Biggest operational weakness?** — Critical-severity containment: **34% of Critical incidents breach the 60-minute SLA** despite an acceptable mean. Secondary: night-shift MTTA ~3.5× day.
3. **What happened in July?** — A phishing campaign (13–19 Jul). Alerts +34% on trend, incidents at a 6-month high (72), Email-GW true-positive share jumped. Contained without an SLA blowout — evidence the process scales.
4. **Where is residual risk?** — ATT&CK detection coverage still ~49% (amber); ~17 critical vulns open. Everything else is green but EDR/log coverage only *just* crossed target and needs to hold.

---

## Common student mistakes

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Reporting **mean** MTTD | "detection is 29 hours / getting worse" | use median; show the histogram once to explain why |
| Minutes vs hours | MTTR shown as "2,169" with no unit, or 60× off | one helper column, label the axis |
| Date relationship drops rows in Power BI | `[Alerts]` ≠ 3,162 | add a pure `Date` column, relate that to DimDate |
| July read as a regression | narrative says performance dipped | it's a campaign; breach rate still fell |
| SLA reported only overall | "87%, bit low" — no insight | break by severity; Critical is the story |
| Executive page has 20 widgets | Board can't find the answer | 6–8 tiles, 1 chart, 1 paragraph, RAG vs threshold |
| No targets on the dashboard | every number is contextless | target/threshold next to every KPI, RAG colour |
| Charting raw counts for comparison across months | July looks alarming | normalise or pair with a rate (yield %, breach %) |
| Vanity metric front and centre | "3,162 alerts triaged!" as the headline | lead with outcome + trend, not activity |
