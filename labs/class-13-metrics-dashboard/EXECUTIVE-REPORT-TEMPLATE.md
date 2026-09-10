# Executive Reporting Templates — Class 13

Two artefacts. The **one-pager** is the Board scorecard (goes in the quarterly
pack). The **monthly service review** is the working document the SOC and the
CISO walk through together. Both are *narrative + data* — a chart with no
sentence next to it is not a report.

Fill these in from your dashboard. Reference values are in
[`ANSWER-KEY.md`](ANSWER-KEY.md).

---

## A. One-page executive scorecard

> Audience: CISO → Board Risk Committee. Read time: 60 seconds.
> One page. No jargon. Every number has a direction and a target.

```
╔══════════════════════════════════════════════════════════════════════╗
║  MEGHNA BANK — SECURITY OPERATIONS SCORECARD                          ║
║  Reporting period: March – August 2026        Data as of: 2026-09-01  ║
╠══════════════════════════════════════════════════════════════════════╣
║  HEADLINE                                                             ║
║  SOC performance improved across every dimension this half, at flat   ║
║  headcount. One weakness (rapid containment of Critical incidents)    ║
║  and one residual gap (detection coverage) remain and are owned.      ║
╠═══════════════════════╦═══════════╦═══════════╦══════════╦════════════╣
║  KPI                  ║  Now      ║  6 mo ago ║  Target  ║  Status    ║
╠═══════════════════════╬═══════════╬═══════════╬══════════╬════════════╣
║  Median detection time║  ___ h    ║  5.1 h    ║  ↓ trend ║  🟢         ║
║  SLA compliance (all) ║  ___ %    ║  78 %     ║  ≥ 95 %  ║  🟡         ║
║  SLA — Critical only  ║  ___ %    ║  ~60 %    ║  ≥ 95 %  ║  🔴         ║
║  True-positive yield  ║  ___ %    ║  17 %     ║  ↑ trend ║  🟢         ║
║  Alert noise (FP rate)║  ___ %    ║  63 %     ║  < 50 %  ║  🟡         ║
║  EDR coverage         ║  ___ %    ║  88 %     ║  ≥ 95 %  ║  🟢         ║
║  ATT&CK detection cov.║  ___ %    ║  33 %     ║  ≥ 50 %  ║  🟡         ║
║  Priv. accounts no MFA║  ___      ║  10       ║  0       ║  🟢         ║
╠═══════════════════════╩═══════════╩═══════════╩══════════╩════════════╣
║  WHAT WENT WELL                                                       ║
║  1. Alert noise down ~34%; the alerts that fire are now real 44% of   ║
║     the time (was 17%). Tuning + automation, no extra staff.          ║
║  2. SLA breach rate fell from 22% to 2% month-on-month.               ║
║  3. Human-layer risk down: phishing click rate 18% → 8%, MFA gap      ║
║     on privileged accounts closed from 10 accounts to 1.              ║
║                                                                      ║
║  WATCH / RISK                                                         ║
║  • Critical incidents: ~1 in 3 still miss the 60-minute containment   ║
║    target. Mean looks fine; the tail does not. Fix: dedicated         ║
║    Critical playbook + on-call escalation, and night-shift cover      ║
║    (night triage is 3.5× slower than day).                            ║
║  • Detection coverage ~49% of the agreed ATT&CK technique set —       ║
║    still short of the 50% floor. Detection-engineering plan in place. ║
║                                                                      ║
║  ASK                                                                  ║
║  • Approve 1 additional night-shift analyst (or MSSP night cover) to  ║
║    close the Critical-containment and after-hours gap. ~$___ /yr.     ║
╚══════════════════════════════════════════════════════════════════════╝
```

**Charts to attach (max 2):**
1. Alert volume (bars) vs true-positive yield % (line), 6 months — the tuning story.
2. SLA compliance by severity (bars) with the 95% line — shows exactly where the gap is.

---

## B. Monthly SOC service review

> Audience: CISO + SOC leadership. Working session, ~30 min. This is where you
> explain *why* the numbers moved and agree actions.

### 1. Period & scope
- Month: `__________`  ·  Reporting SOC: `__________`  ·  Prepared by: `__________`

### 2. Volume
| | This month | Last month | 3-mo avg | Note |
|---|---:|---:|---:|---|
| Alerts received | | | | |
| Incidents opened | | | | |
| Major incidents (Sev-1) | | | | |
| Alerts per analyst / shift | | | | vs ceiling of ___ |

### 3. Speed (by severity where it matters)
| Metric | Critical | High | Medium | Low | Target | Trend |
|--------|---:|---:|---:|---:|---|---|
| MTTA (min) | | | | | < 15 | |
| MTTC | | | | | 60m / 4h / 24h / 72h | |
| MTTR | | | | | ↓ | |
| **SLA compliance %** | | | | | ≥ 95% | |

- Median detection time (dwell): `______`  (report median, note the p90: `______`)

### 4. Quality
| | This month | Target | Trend |
|---|---:|---|---|
| True-positive yield % | | ↑ | |
| False-positive + duplicate rate % | | < 50% | |
| False-escalation rate % | | < 10% | |
| Reopened incidents | | 0 | |
| ATT&CK technique coverage % | | ≥ 50% | |

### 5. Risk indicators (KRI)
| KRI | Value | Amber/Red | Direction | Owner | Action / due |
|-----|---:|---|---|---|---|
| EDR coverage % | | <95 / <90 | | | |
| Log-source health % | | <95 / <90 | | | |
| Open critical vulns | | >20 / >35 | | | |
| Mean critical-vuln age (d) | | >14 / >30 | | | |
| Phishing sim click rate % | | >10 / >20 | | | |
| Priv. accounts without MFA | | >2 / >5 | | | |
| Stale threat-intel % | | >15 / >30 | | | |

### 6. Narrative — the part that matters
- **What changed and why (2–3 sentences):** `__________`
- **Notable incidents / campaigns this month:** `__________`
- **What we're doing about the worst number:** `__________`
- **Blockers / what we need from the business:** `__________`

### 7. Actions from this review
| # | Action | Owner | Due | Status |
|---|--------|-------|-----|--------|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

---

## C. Reporting cadence — who gets what, how often

| Report | Audience | Cadence | Contents | Format |
|--------|----------|---------|----------|--------|
| Shift handover | Next shift lead | Every shift | Open cases, watch-items, pending escalations | Ticket queue + 3 bullets |
| Weekly ops review | SOC manager + leads | Weekly | SLA this week, backlog, tuning done, staffing | Dashboard "Operations" page |
| **Monthly service review** | CISO + SOC leadership | Monthly | Template B above | Deck / doc, 20–30 min |
| **Quarterly Board scorecard** | Board Risk Committee | Quarterly | Template A above | 1 page in the risk pack |
| Ad-hoc major-incident report | CISO / Exec / (Regulator) | Per Sev-1 | Timeline, impact, root cause, actions | Incident report template (Class 08) |

**Golden rules**
- Match refresh rate to decision rate — a Board metric that changes daily is noise to the Board.
- Same metric, same definition, every period. If a definition changes, restate history.
- Lead with the answer, then the evidence. The Board reads the headline and the RAG; the detail is backup.
- Never a chart without a sentence. Never a number without a target and a direction.
