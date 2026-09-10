#!/usr/bin/env python3
"""
Class 13 lab - synthetic SOC dataset generator.

Produces three CSVs under ./data/ that the Excel / Power BI walkthroughs build on:

    data/alerts.csv        one row per alert the SOC received (Mar-Aug 2026)
    data/incidents.csv     one row per escalated true-positive (the case work)
    data/kri_monthly.csv   one row per month - risk indicators for the CISO view

Everything is deterministic (seed = 1313). A rebuild reproduces the exact same
rows, so ANSWER-KEY.md never drifts. Nothing touches the network or the host.
"""

import csv
import os
import random
from datetime import datetime, timedelta

SEED = 1313
random.seed(SEED)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data")
os.makedirs(OUT, exist_ok=True)

START = datetime(2026, 3, 1)
END = datetime(2026, 8, 31, 23, 59, 59)
MONTHS = ["2026-03", "2026-04", "2026-05", "2026-06", "2026-07", "2026-08"]

SOURCES = ["SIEM", "EDR", "Firewall", "WAF", "IDS", "Email-GW", "CASB"]
SOURCE_W = [30, 22, 13, 10, 10, 11, 4]

SEV = ["Low", "Medium", "High", "Critical"]
SEV_W = [46, 32, 17, 5]

TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

RULES = {
    "SIEM": ["Impossible travel", "Brute-force logon burst", "New privileged account",
             "Logon from disabled account", "Mass file download", "Audit log cleared"],
    "EDR": ["LOLBin execution", "Credential dumping tool", "Ransomware canary file",
            "Suspicious PowerShell", "Unsigned driver load", "Process hollowing"],
    "Firewall": ["Outbound to known C2", "Inbound port scan", "Geo-blocked destination",
                 "DNS tunneling pattern", "Tor exit node traffic"],
    "WAF": ["SQL injection attempt", "XSS attempt", "Path traversal", "Web shell upload"],
    "IDS": ["EternalBlue exploit", "Cobalt Strike beacon", "SMB lateral movement", "Nmap scan"],
    "Email-GW": ["Phishing URL", "Malicious attachment", "Business email compromise",
                 "Spoofed internal sender"],
    "CASB": ["SaaS impossible travel", "Mass external share", "OAuth grant to risky app"],
}

T1 = ["a.rahman", "s.khatun", "m.hasan", "t.begum", "r.islam", "n.akter"]
T2 = ["j.chowdhury", "f.ahmed", "k.das"]

CATEGORIES = ["Phishing", "Malware", "Unauthorized Access", "Policy Violation",
              "Recon/Scanning", "Data Loss", "Denial of Service", "Insider Threat"]

# containment SLA target in minutes, by severity (measured detected -> contained)
SLA_TARGET = {"Critical": 60, "High": 240, "Medium": 1440, "Low": 4320}


def shift_of(dt):
    h = dt.hour
    if 6 <= h < 14:
        return "Morning"
    if 14 <= h < 22:
        return "Evening"
    return "Night"


def wpick(choices, weights):
    return random.choices(choices, weights=weights, k=1)[0]


def rand_ts(day):
    """A timestamp somewhere in `day`, biased toward business hours."""
    hour = wpick(range(24), [
        1, 1, 1, 1, 1, 2, 4, 7, 9, 10, 10, 9,
        8, 9, 10, 10, 9, 7, 5, 4, 3, 2, 2, 1,
    ])
    return day + timedelta(hours=hour, minutes=random.randint(0, 59),
                           seconds=random.randint(0, 59))


# ---------------------------------------------------------------- alerts
alerts = []
aid = 0
day = START
while day <= END:
    month = day.strftime("%Y-%m")
    weekday = day.weekday() < 5

    base = 24 if weekday else 9
    # improvement over the 6 months: tuning cuts daily noise
    base -= MONTHS.index(month) * 1.1
    # July phishing campaign spike (2026-07-13 .. 2026-07-19)
    if datetime(2026, 7, 13) <= day <= datetime(2026, 7, 19):
        base += 22
    n = max(3, int(random.gauss(base, 3)))

    for _ in range(n):
        aid += 1
        ts = rand_ts(day)
        src = wpick(SOURCES, SOURCE_W)
        sev = wpick(SEV, SEV_W)
        rule = random.choice(RULES[src])
        tactic = random.choice(TACTICS)

        # disposition - the SOC is noisy; false positives dominate, and the
        # false-positive share shrinks month over month as rules get tuned.
        fp_bias = 0.80 - MONTHS.index(month) * 0.035
        if src in ("Email-GW",) and day >= datetime(2026, 7, 13) and day <= datetime(2026, 7, 22):
            fp_bias -= 0.25  # real campaign - more of these are true
        r = random.random()
        if r < fp_bias:
            disp = wpick(["False Positive", "Benign True Positive", "Duplicate"], [70, 22, 8])
        else:
            disp = "True Positive"

        escalated = False
        if disp == "True Positive":
            p = {"Critical": 0.95, "High": 0.8, "Medium": 0.35, "Low": 0.08}[sev]
            escalated = random.random() < p

        alerts.append({
            "alert_id": f"ALT-{aid:06d}",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "month": month,
            "source": src,
            "rule_name": rule,
            "severity": sev,
            "mitre_tactic": tactic,
            "disposition": disp,
            "escalated_to_incident": "Yes" if escalated else "No",
            "analyst": random.choice(T1),
            "shift": shift_of(ts),
        })
    day += timedelta(days=1)

alerts.sort(key=lambda a: a["timestamp"])

# ---------------------------------------------------------------- incidents
incidents = []
iid = 0
for a in alerts:
    if a["escalated_to_incident"] != "Yes":
        continue
    iid += 1
    sev = a["severity"]
    midx = MONTHS.index(a["month"])
    detected = datetime.strptime(a["timestamp"], "%Y-%m-%d %H:%M:%S")

    # dwell time (first activity -> detection). Improves over time; stealthy
    # categories dwell longer.
    dwell_base = 180 - midx * 18
    if sev in ("Low", "Medium"):
        dwell_base += 90
    dwell = max(1, random.gauss(dwell_base, dwell_base * 0.6))
    if random.random() < 0.12:          # a few slow-burn cases
        dwell += random.randint(1440, 20160)
    created = detected - timedelta(minutes=dwell)

    # triage delay (detect -> acknowledge). Night shift is slower.
    ack_base = {"Morning": 8, "Evening": 11, "Night": 26}[a["shift"]]
    ack_base -= midx * 0.7
    ack = max(1, random.gauss(ack_base, ack_base * 0.5))
    acknowledged = detected + timedelta(minutes=ack)

    # containment (detect -> contain). Driven by severity, improves over time.
    cont_base = {"Critical": 55, "High": 200, "Medium": 900, "Low": 3000}[sev]
    cont_base *= (1 - midx * 0.06)
    contain = max(ack + 3, random.gauss(cont_base, cont_base * 0.45))
    contained = detected + timedelta(minutes=contain)

    # remediation (contain -> resolve)
    rem = random.gauss({"Critical": 2600, "High": 1900, "Medium": 1200, "Low": 700}[sev], 700)
    rem = max(30, rem)
    resolved = contained + timedelta(minutes=rem)

    target = SLA_TARGET[sev]
    breached = contain > target

    cat = wpick(CATEGORIES, [24, 20, 16, 12, 10, 7, 6, 5])
    if a["source"] == "Email-GW":
        cat = "Phishing"
    elif a["source"] == "WAF":
        cat = wpick(["Unauthorized Access", "Recon/Scanning"], [1, 1])

    incidents.append({
        "incident_id": f"INC-{iid:05d}",
        "source_alert_id": a["alert_id"],
        "month": a["month"],
        "category": cat,
        "severity": sev,
        "mitre_tactic": a["mitre_tactic"],
        "first_activity": created.strftime("%Y-%m-%d %H:%M:%S"),
        "detected": detected.strftime("%Y-%m-%d %H:%M:%S"),
        "acknowledged": acknowledged.strftime("%Y-%m-%d %H:%M:%S"),
        "contained": contained.strftime("%Y-%m-%d %H:%M:%S"),
        "resolved": resolved.strftime("%Y-%m-%d %H:%M:%S"),
        "mttd_minutes": round(dwell, 1),
        "mtta_minutes": round(ack, 1),
        "mttc_minutes": round(contain, 1),
        "mttr_minutes": round((resolved - detected).total_seconds() / 60, 1),
        "sla_target_minutes": target,
        "sla_breached": "Yes" if breached else "No",
        "analyst_tier1": a["analyst"],
        "analyst_tier2": random.choice(T2),
        "shift": a["shift"],
        "false_escalation": "No",
    })

# a handful of incidents that turned out benign after escalation (over-escalation KRI)
for inc in random.sample(incidents, k=int(len(incidents) * 0.06)):
    inc["false_escalation"] = "Yes"

# ---------------------------------------------------------------- monthly KRIs
kri_rows = []
for i, m in enumerate(MONTHS):
    inc_m = [x for x in incidents if x["month"] == m]
    alt_m = [x for x in alerts if x["month"] == m]
    tp_m = [x for x in alt_m if x["disposition"] == "True Positive"]
    kri_rows.append({
        "month": m,
        "endpoint_edr_coverage_pct": round(87.5 + i * 1.7 + random.uniform(-0.6, 0.6), 1),
        "log_source_health_pct": round(92.0 + i * 1.1 + random.uniform(-1.0, 1.0), 1),
        "critical_vulns_open": max(4, int(42 - i * 5 + random.uniform(-3, 3))),
        "mean_critical_vuln_age_days": round(max(3, 21 - i * 2.4 + random.uniform(-1.5, 1.5)), 1),
        "attack_technique_coverage_pct": round(33 + i * 3.4 + random.uniform(-1, 1), 1),
        "phishing_sim_click_rate_pct": round(max(4.0, 17.5 - i * 1.9 + random.uniform(-0.8, 0.8)), 1),
        "privileged_accounts_without_mfa": max(0, int(11 - i * 2 + random.uniform(-1, 1))),
        "stale_threat_intel_pct": round(max(2.0, 14 - i * 1.6 + random.uniform(-1, 1)), 1),
        "alerts_total": len(alt_m),
        "true_positive_yield_pct": round(100 * len(tp_m) / len(alt_m), 1),
        "incidents_opened": len(inc_m),
        "sla_breaches": sum(1 for x in inc_m if x["sla_breached"] == "Yes"),
        "backlog_open_month_end": max(0, int(random.uniform(3, 9) - i * 0.4)),
        "analyst_overtime_hours": max(0, int(random.gauss(120 - i * 8, 15))),
    })


def dump(name, rows):
    path = os.path.join(OUT, name)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"  {name:22s} {len(rows):>6d} rows")


print("Writing lab data to ./data/ ...")
dump("alerts.csv", alerts)
dump("incidents.csv", incidents)
dump("kri_monthly.csv", kri_rows)
print("Done. Seed =", SEED)
