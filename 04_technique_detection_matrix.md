# Technique → Detection Matrix

← [Back to README](../README.md)

---

> **How to use this matrix:** The tables below cross-reference the ten baseline statistical techniques in `02_baseline_hunts/` against the nine detection use cases in `03_detection_use_cases/`. Use them to answer three questions:
> 1. *"I want to detect X — which techniques give me the strongest signal?"* → Read the Detection Use Case rows.
> 2. *"I just learned technique Y — what threats can I apply it to?"* → Read the Technique columns.
> 3. *"What data sources do I need for a given detection?"* → Use the Data Source Coverage table.

**Legend:** `Primary` = the technique is the main detection engine for this use case. `Supporting` = the technique adds corroborating evidence or context. `—` = not typically applicable.

---

## Table 1 — Technique × Detection Use Case

| Detection Use Case | [Freq](02_baseline_hunts/01_frequency_analysis.md) | [Cardinality](02_baseline_hunts/02_cardinality_analysis.md) | [Z-Score](02_baseline_hunts/03_zscore_stdev.md) | [Percentile/IQR](02_baseline_hunts/04_percentile_iqr.md) | [Entropy](02_baseline_hunts/05_entropy_analysis.md) | [Moving Avg](02_baseline_hunts/06_moving_averages.md) | [Rate of Change](02_baseline_hunts/07_rate_of_change.md) | [Time-Series](02_baseline_hunts/08_timeseries_forecasting.md) | [Behavioral](02_baseline_hunts/09_behavioral_profiling.md) | [Anomaly Det.](02_baseline_hunts/10_anomaly_detection.md) |
|---|---|---|---|---|---|---|---|---|---|---|
| [Beaconing](03_detection_use_cases/01_beaconing.md) | Supporting | — | Supporting | Primary | — | Supporting | Primary | Supporting | — | Supporting |
| [Data Exfiltration](03_detection_use_cases/02_data_exfiltration.md) | — | — | Primary | Primary | — | Primary | Supporting | Supporting | Supporting | Supporting |
| [Credential Attacks](03_detection_use_cases/03_credential_attacks.md) | Primary | Primary | Supporting | Supporting | — | — | Supporting | Supporting | Supporting | — |
| [DNS Tunneling / DGA](03_detection_use_cases/04_dns_tunneling_dga.md) | Supporting | Primary | — | — | Primary | — | — | — | — | Supporting |
| [Lateral Movement](03_detection_use_cases/05_lateral_movement.md) | Supporting | Primary | Primary | — | — | Supporting | — | — | Primary | Supporting |
| [Privilege Escalation](03_detection_use_cases/06_privilege_escalation.md) | Primary | Supporting | Supporting | — | — | — | — | — | Primary | Supporting |
| [Insider Threat / UEBA](03_detection_use_cases/07_insider_threat.md) | — | Supporting | Primary | Supporting | — | Supporting | — | Supporting | Primary | Primary |
| [Port Scanning](03_detection_use_cases/08_port_scanning.md) | Supporting | Primary | — | — | — | — | Primary | — | — | — |
| [Rogue Services / Processes](03_detection_use_cases/09_rogue_services_processes.md) | Primary | — | — | Supporting | — | — | — | — | Supporting | Supporting |

---

## Table 2 — Detection Use Case × Data Source Coverage

| Detection Use Case | conn.log | dns.log | http.log | ssl.log | EID 4624 | EID 4625 | EID 4688 | EID 7045 | Sysmon 1 | Sysmon 3 | Sysmon 7 | Sysmon 10 | Sysmon 22 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Beaconing | ✓ | ✓ | ✓ | ✓ | — | — | — | — | — | ✓ | — | — | ✓ |
| Data Exfiltration | ✓ | ✓ | ✓ | ✓ | — | — | — | — | — | ✓ | — | — | — |
| Credential Attacks | — | — | — | — | ✓ | ✓ | — | — | — | — | — | — | — |
| DNS Tunneling / DGA | — | ✓ | — | — | — | — | — | — | — | — | — | — | ✓ |
| Lateral Movement | ✓ | — | — | — | ✓ | ✓ | ✓ | — | ✓ | ✓ | — | — | — |
| Privilege Escalation | — | — | — | — | ✓ | — | ✓ | ✓ | ✓ | — | — | — | — |
| Insider Threat / UEBA | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | — | ✓ | — | — | — | — |
| Port Scanning | ✓ | — | — | — | — | — | — | — | — | ✓ | — | — | — |
| Rogue Services / Processes | — | — | — | — | — | — | ✓ | ✓ | ✓ | — | ✓ | ✓ | — |

**Data Source Key:**

| Abbreviation | Full Name |
|---|---|
| conn.log | Corelight `conn.log` (network flows) |
| dns.log | Corelight `dns.log` (DNS transactions) |
| http.log | Corelight `http.log` (HTTP metadata) |
| ssl.log | Corelight `ssl.log` (TLS metadata, JA3) |
| EID 4624 | Windows Event Log — Successful Logon |
| EID 4625 | Windows Event Log — Failed Logon |
| EID 4688 | Windows Event Log — Process Creation |
| EID 7045 | Windows Event Log — New Service Installed |
| Sysmon 1 | Sysmon Event ID 1 — Process Create |
| Sysmon 3 | Sysmon Event ID 3 — Network Connection |
| Sysmon 7 | Sysmon Event ID 7 — Image Load (DLL) |
| Sysmon 10 | Sysmon Event ID 10 — ProcessAccess |
| Sysmon 22 | Sysmon Event ID 22 — DNS Query |

---

## Table 3 — Technique → Primary SPL Commands

| Technique | Core Commands | Key Functions / Options |
|---|---|---|
| [Frequency Analysis](02_baseline_hunts/01_frequency_analysis.md) | `top`, `rare`, `stats count`, `eventstats` | `limit=N`, `showother=true`, `by <field>` |
| [Cardinality Analysis](02_baseline_hunts/02_cardinality_analysis.md) | `stats dc()`, `eventstats dc()` | `dc(field)` distinct count, `by src_host` |
| [Z-Score / Stdev](02_baseline_hunts/03_zscore_stdev.md) | `stats avg() stdev()`, `eventstats`, `eval` | `(value - avg) / stdev`, `abs(zscore) > 3` |
| [Percentile / IQR](02_baseline_hunts/04_percentile_iqr.md) | `stats perc95() perc99()`, `eval` | `perc25/75`, `iqr = p75 - p25` |
| [Entropy Analysis](02_baseline_hunts/05_entropy_analysis.md) | `eval`, `rex`, `stats` | Custom entropy `eval` with `len()`, `mvcount()` |
| [Moving Averages](02_baseline_hunts/06_moving_averages.md) | `streamstats window=N avg()`, `eval` | `current=false`, rolling window, delta |
| [Rate of Change](02_baseline_hunts/07_rate_of_change.md) | `timechart`, `autoregress`, `eval` | `delta = current - prev`, percentage change |
| [Time-Series Forecast](02_baseline_hunts/08_timeseries_forecasting.md) | `predict`, `timechart` | `algorithm=LLP5`, `future_timespan`, upper/lower |
| [Behavioral Profiling](02_baseline_hunts/09_behavioral_profiling.md) | `eventstats`, `streamstats`, `stats` | Per-entity baselines, `by user host`, rolling stats |
| [Anomaly Detection](02_baseline_hunts/10_anomaly_detection.md) | `anomalydetection`, `cluster`, `kmeans` | `action=annotate`, `threshold=0.02` |

---

## Table 4 — Detection Use Case → MITRE ATT&CK Mapping

| Detection Use Case | Technique IDs | Technique Names | Tactic |
|---|---|---|---|
| Beaconing | T1071, T1071.001, T1071.004, T1573 | Application Layer Protocol, Web Protocols, DNS, Encrypted Channel | Command and Control |
| Data Exfiltration | T1041, T1048, T1048.003 | Exfil Over C2, Exfil Over Alternative Protocol, Exfil Over Unencrypted/Obfuscated Protocol | Exfiltration |
| Credential Attacks | T1110, T1110.001, T1110.003, T1110.004 | Brute Force, Password Guessing, Password Spraying, Credential Stuffing | Credential Access |
| DNS Tunneling / DGA | T1071.004, T1568.002, T1132 | DNS, Domain Generation Algorithms, Data Encoding | Command and Control |
| Lateral Movement | T1021, T1021.001, T1021.002, T1550.002 | Remote Services, RDP, SMB/Windows Admin Shares, Pass-the-Hash | Lateral Movement |
| Privilege Escalation | T1078, T1134, T1068, T1543 | Valid Accounts, Access Token Manipulation, Exploit for Priv Esc, Create or Modify System Process | Privilege Escalation |
| Insider Threat / UEBA | T1078, T1078.002, T1078.003 | Valid Accounts, Domain Accounts, Local Accounts | Initial Access / Defense Evasion |
| Port Scanning | T1046 | Network Service Discovery | Discovery |
| Rogue Services / Processes | T1543.003, T1059, T1569.002 | Windows Service, Command and Scripting Interpreter, System Services | Persistence / Execution |

---

## Table 5 — AD Attack Technique → Detection Use Case Mapping

The course modules in `05_courses/` introduce specific AD attack techniques. This table maps each attack to the statistical technique and detection use case that best surfaces it.

| AD Attack | MITRE ID | Primary Statistical Technique | Detection Use Case | Key Data Source |
|---|---|---|---|---|
| Kerberoasting | T1558.003 | Frequency Analysis — spike in RC4 TGS requests | Credential Attacks | WinEvent 4769 |
| AS-REP Roasting | T1558.004 | Frequency Analysis — 4768 without pre-auth | Credential Attacks | WinEvent 4768 |
| Pass-the-Hash | T1550.002 | Behavioral Profiling — NTLM from unusual source | Lateral Movement | WinEvent 4624 |
| DCSync | T1003.006 | Cardinality — non-DC replication calls | Privilege Escalation | WinEvent 4662 |
| Golden Ticket | T1558.001 | Anomaly Detection — ticket lifetime / encryption anomalies | Credential Attacks | WinEvent 4769 |
| BloodHound Enumeration | T1087.002 | Cardinality — dc(AttributeName) LDAP burst | Lateral Movement | WinEvent 4662 |
| Password Spray | T1110.003 | Cardinality — dc(TargetUserName) with count/user < 3 | Credential Attacks | WinEvent 4625 |
| LSASS Dump | T1003.001 | Frequency — rare ProcessAccess on lsass.exe | Rogue Services / Processes | Sysmon EID 10 |

---

## Quick-Start Paths by Threat Type

Use these paths if you are new to a threat category and need to build your knowledge in the right order.

| If your threat concern is… | Start with this baseline technique | Then apply this detection use case | Reference modules |
|---|---|---|---|
| **C2 / beaconing implants** | [Rate of Change](02_baseline_hunts/07_rate_of_change.md) — understand interval variance | [Beaconing](03_detection_use_cases/01_beaconing.md) | Module 04 (Attacks), Module 05 (Tooling) |
| **Credential stuffing / spraying** | [Frequency Analysis](02_baseline_hunts/01_frequency_analysis.md) — count failures by source | [Credential Attacks](03_detection_use_cases/03_credential_attacks.md) | Module 03 (Auth Patterns), Module 04 (Attacks) |
| **Insider data theft** | [Behavioral Profiling](02_baseline_hunts/09_behavioral_profiling.md) — per-user transfer baselines | [Data Exfiltration](03_detection_use_cases/02_data_exfiltration.md) + [Insider Threat](03_detection_use_cases/07_insider_threat.md) | Module 03 (Auth Patterns) |
| **DNS tunneling / DGA** | [Entropy Analysis](02_baseline_hunts/05_entropy_analysis.md) — measure domain randomness | [DNS Tunneling / DGA](03_detection_use_cases/04_dns_tunneling_dga.md) | Module 01 (AD Traffic — DNS section) |
| **Lateral movement** | [Cardinality Analysis](02_baseline_hunts/02_cardinality_analysis.md) — dc(dest) per source host | [Lateral Movement](03_detection_use_cases/05_lateral_movement.md) | Module 02 (Infrastructure), Module 04 (Attacks) |
| **Kerberoasting / AS-REP** | [Frequency Analysis](02_baseline_hunts/01_frequency_analysis.md) — spike in TGS requests | [Credential Attacks](03_detection_use_cases/03_credential_attacks.md) | Module 01 (AD Traffic), Module 04 (Attacks) |
| **Rogue processes / malware** | [Frequency Analysis](02_baseline_hunts/01_frequency_analysis.md) — rare parent→child chains | [Rogue Services / Processes](03_detection_use_cases/09_rogue_services_processes.md) | Module 04 (Attacks), Module 05 (Tooling) |
| **Privilege escalation** | [Behavioral Profiling](02_baseline_hunts/09_behavioral_profiling.md) — DA account activity baseline | [Privilege Escalation](03_detection_use_cases/06_privilege_escalation.md) | Module 03 (Auth), Module 04 (Attacks) |
| **DCSync / credential dumping** | [Cardinality Analysis](02_baseline_hunts/02_cardinality_analysis.md) — non-DC replication sources | [Privilege Escalation](03_detection_use_cases/06_privilege_escalation.md) | Module 01 (AD Traffic), Module 04 (Attacks) |
| **Pass-the-Hash / token abuse** | [Behavioral Profiling](02_baseline_hunts/09_behavioral_profiling.md) — NTLM logon type baseline | [Lateral Movement](03_detection_use_cases/05_lateral_movement.md) | Module 03 (Auth Patterns), Module 04 (Attacks) |

---

## Dependency Flowchart — Techniques → Use Cases → PEAK Phase

```mermaid
flowchart TD
    subgraph TECHNIQUES["Baseline Techniques (02_baseline_hunts/)"]
        T1[Frequency Analysis\ntop / rare / stats count]
        T2[Cardinality\nstats dc()]
        T3[Z-Score / Stdev\navg / stdev / eventstats]
        T4[Percentile / IQR\nperc95 / eval]
        T5[Entropy\neval len / rex]
        T6[Moving Averages\nstreamstats window=N]
        T7[Rate of Change\nautoregress / timechart]
        T8[Time-Series Forecast\npredict]
        T9[Behavioral Profiling\neventstats by entity]
        T10[Anomaly Detection\nanomalydetection / cluster]
    end

    subgraph USECASES["Detection Use Cases (03_detection_use_cases/)"]
        D1[Beaconing]
        D2[Data Exfiltration]
        D3[Credential Attacks]
        D4[DNS Tunneling / DGA]
        D5[Lateral Movement]
        D6[Privilege Escalation]
        D7[Insider Threat / UEBA]
        D8[Port Scanning]
        D9[Rogue Services]
    end

    subgraph PEAK["PEAK Phases"]
        P1[Prepare\nHypothesis + Scope]
        P2[Explore\nBaseline + Frequency]
        P3[Analyze\nStatistical Deviation]
        P4[Knowledge\nAlert + Detection Rule]
    end

    T1 --> D3
    T1 --> D6
    T1 --> D9
    T2 --> D3
    T2 --> D4
    T2 --> D5
    T2 --> D8
    T3 --> D2
    T3 --> D5
    T4 --> D1
    T4 --> D2
    T5 --> D4
    T6 --> D2
    T7 --> D1
    T7 --> D8
    T8 --> D3
    T9 --> D5
    T9 --> D6
    T9 --> D7
    T10 --> D7

    D1 --> P3
    D2 --> P3
    D3 --> P2
    D4 --> P3
    D5 --> P3
    D6 --> P2
    D7 --> P4
    D8 --> P2
    D9 --> P2

    P1 --> P2 --> P3 --> P4

    style TECHNIQUES fill:#1a3a2a,color:#ccc,stroke:#2d6a4f
    style USECASES fill:#1a2a3a,color:#ccc,stroke:#2d4a6a
    style PEAK fill:#2a1a3a,color:#ccc,stroke:#4a2d6a
```

---

## SPL Quick Reference — Most-Used Commands by Phase

### Explore Phase (Build Your Baseline)

```spl
/* Frequency — top processes */
index=sysmon EventCode=1 earliest=-30d
| top limit=20 process_name by host

/* Cardinality — unique destinations per source */
index=corelight sourcetype=corelight_conn earliest=-7d
| stats dc(id.resp_h) as unique_dests, dc(id.resp_p) as unique_ports by id.orig_h
| sort - unique_dests

/* Rare processes — find the long tail */
index=sysmon EventCode=1 earliest=-30d
| rare limit=50 process_name
```

### Analyze Phase (Find Deviations)

```spl
/* Z-score — flag outlier byte counts */
index=corelight sourcetype=corelight_conn earliest=-7d
| stats avg(orig_bytes) as avg_bytes, stdev(orig_bytes) as sd_bytes by id.orig_h
| eval zscore = (orig_bytes - avg_bytes) / sd_bytes
| where zscore > 3

/* IQR — flag outlier connection intervals */
index=corelight sourcetype=corelight_conn earliest=-7d
| stats perc25(orig_bytes) as p25, perc75(orig_bytes) as p75 by id.orig_h
| eval iqr = p75 - p25
| eval upper_fence = p75 + (1.5 * iqr)
| where orig_bytes > upper_fence
```

### Knowledge Phase (Operationalise)

```spl
/* Saved detection — Kerberoasting via RC4 spike */
index=wineventlog EventCode=4769 TicketEncryptionType=0x17 earliest=-1h
| stats count as rc4_requests, dc(ServiceName) as unique_services by IpAddress, TargetUserName
| where rc4_requests > 5
| sort - rc4_requests

/* Saved detection — cardinality-based port scan */
index=corelight sourcetype=corelight_conn earliest=-15m
| stats dc(id.resp_p) as unique_ports, dc(id.resp_h) as unique_hosts by id.orig_h
| where unique_ports > 100 OR unique_hosts > 50
| sort - unique_ports

/* Saved detection — DCSync from non-DC account */
index=wineventlog EventCode=4662 earliest=-1h
| search Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ab-9c07-11d1-f79f-00c04fc2dcd2*"
| stats count by SubjectUserName, SubjectDomainName, ObjectType
| where NOT match(SubjectUserName, "(?i)\$$")
| sort - count

/* Saved detection — password spray (dc of target users per source, low per-user count) */
index=wineventlog EventCode=4625 earliest=-30m
| stats dc(TargetUserName) as unique_users, count as total_failures by IpAddress
| eval avg_per_user = total_failures / unique_users
| where unique_users > 20 AND avg_per_user < 3
| sort - unique_users
```

---

*Navigation: ← [Back to README](../README.md) | [Course Overview →](05_courses/00_course_overview.md)*

*Last updated: 2026-03-29*
