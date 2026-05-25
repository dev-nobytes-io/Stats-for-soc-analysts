# Custom Hunt Chains & Hunt Jeopardy Framework

---

## Part A: Custom Multi-Technique Hunt Chains

Custom chains trace the complete attacker lifecycle across multiple techniques, phases, and data sources. Unlike single-technique hunts, chain hunts require temporal and causal correlation of events spanning days to weeks.

---

## Chain 1: Complete Ransomware Intrusion Lifecycle

### Threat Model
Modern ransomware operators (Conti, LockBit, BlackCat) follow a consistent multi-phase intrusion pattern before deploying encryption. The window between initial access and encryption (dwell time) ranges from 3 to 21 days. Detecting any phase terminates the chain.

### Full Timeline
```
Day 1-2:  External Reconnaissance         (T1592, T1595, T1046)
Day 2-3:  Initial Access                  (T1190, T1566, T1078)
Day 3:    Establish Persistence           (T1547, T1053)
Day 3-4:  Defense Evasion                 (T1562, T1070, T1036)
Day 4:    Privilege Escalation            (T1134, T1548, T1078.002)
Day 4-7:  Lateral Movement               (T1021, T1570, T1550)
Day 6-8:  Collection / Staging           (T1560, T1074, T1005)
Day 8-9:  Exfiltration                   (T1048, T1567, T1041)
Day 9:    Impact / Encryption            (T1486, T1490, T1489)
```

### Phase-by-Phase Hunt Queries

**Phase 1: Reconnaissance Footprint**
```spl
index=network dest_port IN (445, 139, 3389, 22, 80, 443, 8080, 8443)
| bucket _time span=1h
| stats dc(dest_ip) as unique_targets, dc(dest_port) as unique_ports, count as attempts
  by _time, src_ip
| where unique_targets > 20 OR (unique_ports > 5 AND attempts > 50)
| lookup geoip.csv src_ip OUTPUT country as src_country
| where src_country NOT IN ("US", "CA", "AU", "UK", "DE")
| table _time, src_ip, src_country, unique_targets, unique_ports
```

**Phase 2: Initial Access — Vulnerability Exploitation**
```spl
index=web_app status IN (500, 400, 403)
| rex field=uri "(?<suspicious_path>(/etc/passwd|cmd\.exe|\.\.\/|%00|union\+select|<script))"
| where isnotnull(suspicious_path)
| stats count by src_ip, uri, status, suspicious_path
| where count > 5
| table _time, src_ip, uri, suspicious_path, count
```

**Phase 3: Persistence Installation**
```spl
index=sysmon EventCode IN (13, 14)
TargetObject IN (
    "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*",
    "*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon*",
    "*\\System\\CurrentControlSet\\Services*",
    "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options*"
)
| lookup known_persistence_paths.csv TargetObject OUTPUT is_known_good
| where is_known_good != "yes"
| stats count by ComputerName, User, TargetObject, Details
| table _time, ComputerName, User, TargetObject, Details
```

**Phase 4: Privilege Escalation Indicators**
```spl
index=windows_security EventCode IN (4672, 4673)
| where PrivilegeList IN ("SeDebugPrivilege", "SeLoadDriverPrivilege", "SeTcbPrivilege")
| join SubjectUserName [
    search index=windows_security EventCode=4624
    | where LogonType=3 AND SubjectUserName NOT IN ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
    | stats count by SubjectUserName
    | where count > 1
  ]
| stats count by SubjectUserName, ComputerName, PrivilegeList
| table _time, SubjectUserName, ComputerName, PrivilegeList
```

**Phase 5: Lateral Movement — Multiple Methods**
```spl
(index=windows_security EventCode=4624 LogonType IN (3, 10) NOT SubjectUserName="*$")
OR (index=sysmon EventCode=3 dest_port IN (445, 3389, 5985, 5986))
OR (index=sysmon EventCode=1 Image IN ("*\\psexec.exe", "*\\wmiexec.exe") OR
    CommandLine IN ("*invoke-wmimethod*", "*Enter-PSSession*"))
| eval lateral_method = case(
    EventCode=4624 AND LogonType=10, "RDP",
    EventCode=4624 AND LogonType=3, "SMB/Network",
    match(Image, "psexec"), "PsExec",
    match(CommandLine, "wmi"), "WMI",
    true(), "Unknown")
| stats count, dc(ComputerName) as unique_hosts, values(ComputerName) as hosts
  by SubjectUserName, lateral_method
| where unique_hosts > 2
| sort - unique_hosts
```

**Phase 6: Data Staging / Pre-Exfiltration**
```spl
index=sysmon EventCode=1
CommandLine IN ("*7z*a*", "*rar*a*", "*tar*cz*", "*robocopy*", "*xcopy*")
OR Image IN ("*\\7z.exe", "*\\rar.exe", "*\\winrar.exe")
| join ComputerName [
    search index=network direction=outbound bytes_out > 10485760
    | stats sum(bytes_out) as total_bytes by src_ip
    | lookup asset_inventory.csv src_ip OUTPUT ComputerName
  ]
| table _time, ComputerName, Image, CommandLine, total_bytes
```

**Phase 7: VSS Deletion — Ransomware Precursor**
```spl
index=sysmon EventCode=1
(CommandLine IN ("*vssadmin delete shadows*", "*wmic shadowcopy delete*",
                 "*bcdedit /set*", "*wbadmin delete*")
 OR Image IN ("*\\vssadmin.exe", "*\\wmic.exe", "*\\bcdedit.exe"))
| eval CRITICAL_PRE_RANSOMWARE_INDICATOR = "TRUE"
| stats count by ComputerName, User, CommandLine
| sort - count
```

### Chain Correlation Query (Full Chain Detection)
```spl
| tstats count WHERE index=* BY host, sourcetype, _time span=1d
| where host IN [
    search index=sysmon EventCode=1
    CommandLine IN ("*vssadmin delete shadows*", "*wmic shadowcopy delete*")
    | stats count by ComputerName | return ComputerName
  ]
| join host [
    search index=windows_security EventCode=4672 PrivilegeList="SeDebugPrivilege"
    | stats count by ComputerName | rename ComputerName as host
  ]
| eval attack_stage_count = mvcount(split(sourcetype, ","))
| where attack_stage_count > 3
| eval chain_confidence = round(attack_stage_count / 7 * 100, 0) . "% chain coverage"
| table host, sourcetype, chain_confidence
```

---

## Chain 2: Supply Chain Trojanization

### Threat Model
Attacker compromises legitimate software update mechanism; malicious code executes as trusted process with high-privilege context. Indicators are subtle — the executing process is genuinely legitimate.

### Hunt Queries

**Detect update directory spawning unexpected processes:**
```spl
index=sysmon EventCode=1
| eval parent_dir = lower(mvindex(split(ParentImage, "\\"), -2))
| where match(parent_dir, "update|updater|autoupdate|softwareupdate|patch")
| where NOT (Image IN ("*\\msiexec.exe", "*\\setup.exe", "*\\install.exe",
                       "*\\uninstall.exe", "*\\regsvr32.exe"))
  AND NOT match(lower(Image), "update")
| stats count by ComputerName, ParentImage, Image, CommandLine
| lookup process_reputation.csv Image OUTPUT reputation
| where reputation != "trusted"
| table ComputerName, ParentImage, Image, CommandLine, reputation
```

**Detect hash change in monitored software binaries:**
```spl
index=sysmon EventCode=7
ImageLoaded IN ("*\\CompanyX\\*", "*\\TrustedVendor\\*")
| stats values(Hashes) as hash_list, dc(Hashes) as unique_hashes by ImageLoaded
| where unique_hashes > 1
| lookup approved_hashes.csv ImageLoaded OUTPUT approved_hash
| eval has_unapproved = if(mvfind(hash_list, approved_hash) < 0, "HASH CHANGED", "approved")
| where has_unapproved = "HASH CHANGED"
| table ImageLoaded, hash_list, unique_hashes
```

---

## Chain 3: Insider Data Theft

### Threat Model
Privileged user (DBA, sysadmin, departing employee) stages and exfiltrates sensitive data. Often occurs within days of resignation notification or performance review.

### Statistical Baseline for Insider Detection

Use Benford's Law on file access counts — legitimate users show natural first-digit distribution. Bulk data staging creates artifically even access counts that violate Benford distribution.

```spl
index=dlp OR index=file_access
| stats count as access_count by user, file_path
| eval leading_digit = tonumber(substr(tostring(access_count), 1, 1))
| where leading_digit >= 1 AND leading_digit <= 9
| stats count as observed by leading_digit
| eventstats sum(observed) as N
| eval expected_pct = case(leading_digit=1, 0.301, leading_digit=2, 0.176,
    leading_digit=3, 0.125, leading_digit=4, 0.097, leading_digit=5, 0.079,
    leading_digit=6, 0.067, leading_digit=7, 0.058, leading_digit=8, 0.051,
    leading_digit=9, 0.046)
| eval expected = N * expected_pct
| eval chi_sq = pow(observed - expected, 2) / expected
| stats sum(chi_sq) as total_chi_sq
| eval benford_violation = if(total_chi_sq > 15.507, "SUSPICIOUS - bulk access pattern", "normal")
```

**Combine with HR context:**
```spl
index=dlp
| lookup hr_events.csv user OUTPUT event_type as hr_event, event_date
| where hr_event IN ("resignation", "pip", "performance_review", "termination_notice")
| eval days_since_hr = round((_time - strptime(event_date, "%Y-%m-%d")) / 86400, 0)
| where days_since_hr >= 0 AND days_since_hr <= 90
| stats sum(bytes_transferred) as total_bytes, dc(dest_ip) as unique_dests,
        values(file_category) as categories by user, hr_event
| eval risk_level = case(
    total_bytes > 1073741824 AND hr_event="resignation", "CRITICAL",
    total_bytes > 104857600 AND hr_event IN ("pip", "termination_notice"), "HIGH",
    true(), "MEDIUM")
| where risk_level IN ("CRITICAL", "HIGH")
| table user, hr_event, total_bytes, unique_dests, categories, risk_level
```

---

## Chain 4: Cryptojacking

### Threat Model
Attackers compromise servers, cloud instances, or Kubernetes clusters to mine cryptocurrency. Detection is challenging because CPU abuse mimics legitimate compute workloads. Cryptojacking often coexists with other threats (initial access, lateral movement) and uses the same LOLBin techniques as ransomware operators.

### Attack Lifecycle
```
T1190 / T1078     Initial Access (exploit or stolen creds)
T1059.001 / T1059.004  Dropper execution (PowerShell or bash)
T1105             Miner binary ingress (curl/wget to attacker infra)
T1053 / T1543     Persistence (cron, scheduled task, service install)
T1071 / T1573     Stratum C2 pool communications (TCP 3333/4444/14444)
T1562             Kill competing miners and security tools
T1070             Log cleanup to extend dwell time
```

### Key Statistical Signatures

| Metric | Pattern | Test |
|--------|---------|------|
| CPU utilization | Sustained 80-100%, very low variance | Z-score on stdev(cpu) per host |
| Stratum port connections | Regular intervals, low jitter | Spectral analysis on conn intervals |
| DNS to pool domains | Novel domains, short TTL | MAD on query entropy |
| Process CPU share | Single process dominates all cores | IQR on per-process CPU % |
| Cron / scheduled task | New entry absent from baseline | First-seen tracking |

### Hunt Queries

**Phase 1: Sustained high CPU with low variance (miner signature)**
```spl
index=os_metrics metric_name=cpu_usage_pct
| bucket _time span=1h
| stats avg(value) as avg_cpu, stdev(value) as std_cpu by _time, host
| eventstats avg(avg_cpu) as baseline_cpu, stdev(avg_cpu) as sigma_cpu by host
| eval cpu_z = (avg_cpu - baseline_cpu) / sigma_cpu
| eval low_variance_flag = if(std_cpu < 5 AND avg_cpu > 70, 1, 0)
| where cpu_z > 2.5 AND low_variance_flag = 1
| eval anomaly = "Sustained high CPU - low variance - possible miner"
| sort - avg_cpu
| table _time, host, avg_cpu, std_cpu, cpu_z, anomaly
```

**Phase 2: Network connections to stratum ports and mining pool domains**
```spl
index=network dest_port IN (3333, 4444, 5555, 7777, 8888, 9999, 14444, 45560)
| stats count as connections, dc(dest_ip) as pool_ips, values(dest_ip) as ip_list by src_ip
| where connections > 10
| lookup known_mining_pools.csv dest_ip OUTPUT pool_name
| eval confirmed = if(isnotnull(pool_name), "CONFIRMED POOL", "SUSPICIOUS PORT")
| table src_ip, connections, pool_ips, ip_list, confirmed
```

**Phase 3: Miner process detection by name and argument patterns**
```spl
index=sysmon EventCode=1
| eval cmd_lower = lower(CommandLine)
| where match(cmd_lower, "(xmrig|xmr|monero|nicehash|cpuminer|cryptonight|stratum\+tcp)")
      OR match(cmd_lower, "\-o\s+(pool|mine|stratum)")
      OR match(lower(Image), "(miner|xmrig|cpuminer)")
| stats count by ComputerName, User, Image, CommandLine
| lookup process_reputation.csv Image OUTPUT is_known_miner
| eval confidence = if(is_known_miner="yes", "HIGH", "MEDIUM")
| table ComputerName, User, Image, CommandLine, confidence
```

**Phase 4: Persistence — new cron entry or scheduled task with download behavior**
```spl
index=linux_audit path IN ("/etc/cron.d/*", "/var/spool/cron/*", "/etc/crontab")
| rex field=message "(?<cron_cmd>(curl|wget|bash|python|sh)\s+\S+)"
| where isnotnull(cron_cmd)
| stats count by host, user, cron_cmd
| eval new_cron = "UNEXPECTED CRON ENTRY"
| table host, user, cron_cmd

| append [
    search index=sysmon EventCode=1 Image="*\\schtasks.exe"
    | where match(lower(CommandLine), "(curl|wget|powershell.*download|bitsadmin)")
    | table ComputerName, User, CommandLine
  ]
```

**Phase 5: Security tool termination (miner self-defense)**
```spl
index=sysmon EventCode=1
CommandLine IN ("*taskkill*", "*kill *", "*pkill*", "*service * stop*", "*systemctl stop*")
| eval target = lower(CommandLine)
| where match(target, "(defender|crowdstrike|carbonblack|sentinel|cylance|symantec|mcafee|antivir|firewall|ufw|iptables)")
| stats count by ComputerName, User, CommandLine
| eval severity = "CRITICAL - security tool termination preceding mining activity"
| table _time, ComputerName, User, CommandLine, severity
```

**Phase 6: Multi-stage chain correlation**
```spl
| union
    [search index=os_metrics metric_name=cpu_usage_pct | stats avg(value) as avg_cpu by host | where avg_cpu > 80 | eval stage="1_high_cpu"]
    [search index=network dest_port IN (3333,4444,14444) | stats count by src_ip | rename src_ip as host | eval stage="2_stratum_port"]
    [search index=sysmon EventCode=1 | where match(lower(CommandLine),"xmrig|stratum") | stats count by ComputerName | rename ComputerName as host | eval stage="3_miner_process"]
    [search index=sysmon EventCode=1 | where match(lower(CommandLine),"taskkill.*defender") | stats count by ComputerName | rename ComputerName as host | eval stage="4_killed_av"]
| stats dc(stage) as stage_count, values(stage) as stages by host
| where stage_count >= 2
| eval confidence = case(stage_count >= 3, "HIGH", stage_count=2, "MEDIUM", true(), "LOW")
| lookup asset_inventory.csv host OUTPUT owner, dept, asset_class
| sort - stage_count
| table host, owner, dept, asset_class, stage_count, stages, confidence
```

**Cloud context — unexpected GPU/compute instance creation**
```spl
index=cloudtrail eventName IN ("RunInstances", "StartInstances")
| where match(requestParameters.instanceType, "(p3|p4|g4|g5|gpu|metal)")
| stats count as gpu_launches, values(requestParameters.instanceType) as types
  by userIdentity.arn, awsRegion
| lookup expected_instance_types.csv userIdentity.arn OUTPUT approved_gpu
| where isnull(approved_gpu) OR approved_gpu != "yes"
| eval flag = "UNAPPROVED GPU INSTANCE - possible cloud cryptojacking"
| table _time, userIdentity.arn, awsRegion, gpu_launches, types, flag
```

---

## Part B: Hunt Jeopardy Framework

The Hunt Jeopardy Framework structures the annual threat hunting calendar into 12 monthly themes. Each month focuses on a specific threat category, associated actors, and a set of rotation hunts designed for that theme. The "jeopardy" metaphor: categories are the threat themes, and the "answers" are the hunt hypotheses.

---

## 12-Month Rotating Hunt Schedule

| Month | Theme | Primary Threat Actors | Seasonal Context |
|-------|-------|----------------------|-----------------|
| **January** | APT Campaign Kickoff | APT1 (Comment Crew), Tonto Team, TA505 | New year = new attack infrastructure registered in December |
| **February** | Ransomware Pre-Positioning | Conti, LockBit, BlackCat/ALPHV | Tax season = phishing spike targeting accounting |
| **March** | Nation-State Espionage | APT28 (Fancy Bear), APT29 (Cozy Bear), Lazarus Group | Q1 earnings = M&A activity = IP theft targeting |
| **April** | Web Shell Deployment | HAFNIUM, China-nexus groups | Spring patching cycle = exploitation window on unpatched assets |
| **May** | Cloud & SaaS Compromise | CLOP, FIN7, Scattered Spider | Cloud migration projects create configuration drift |
| **June** | Supply Chain Attacks | SolarWinds-type actors, 3CX-type actors | Vendor release cycles peak in Q2 |
| **July** | Reconnaissance & Initial Access | Mirai operators, Initial Access Brokers | Summer staffing gaps = reduced monitoring |
| **August** | Persistence Deep-Dive | Carbanak, Turla, Sandworm | Back-to-school = new devices onboarded |
| **September** | Credential Harvesting | Wizard Spider, FIN11, Scattered Spider | September = high-activity credential markets |
| **October** | Anti-Forensics & Defense Evasion | Sandworm, Wizard Spider | Pre-ransomware cleanup before encryption |
| **November** | Privilege Escalation Chains | APT28, Wizard Spider, BRONZE SILHOUETTE | Pre-holiday = "smash and grab" before analysts go on leave |
| **December** | Year-End Review + Retro Hunt | Emerging groups, new TTPs | Review full year IOCs; test detections for new techniques |

---

## Monthly Hunt Specification Format

### February — Ransomware Pre-Positioning

**Theme Rationale**: Ransomware groups acquire access from Initial Access Brokers (IABs) and position themselves 2-4 weeks before encryption. February hunts focus on detecting this pre-positioning phase.

**Mandated Hunts (must complete all):**

| Hunt ID | Hypothesis | Primary Test | Data Source |
|---------|-----------|--------------|-------------|
| FEB-01 | Cobalt Strike beacons are present | Spectral analysis on conn intervals | Network |
| FEB-02 | Domain admin accounts accessed from non-standard hosts | Chi-square: host×account association | Auth logs |
| FEB-03 | Backup catalog enumeration preceding ransomware | Process anomaly (Z-score) | Endpoint |
| FEB-04 | External RDP enabled on servers | IQR on new RDP source IPs | Network |
| FEB-05 | VSS deletion commands in any environment | Indicator hunt (known commands) | Endpoint |

**Statistical Requirements for February:**
- Run Z-score analysis on all lateral movement metrics
- Apply change point detection to authentication event rates (detect onset of campaign)
- Compute Benford's Law on file access counts for database servers

**Sample Hunt FEB-01: Cobalt Strike Beacon Detection via Spectral Analysis**
```spl
index=network
| bucket _time span=1m
| stats count as conn_count by _time, src_ip, dest_ip
| sort src_ip dest_ip _time
| streamstats current=false window=1 last(_time) as prev_time by src_ip, dest_ip
| eval interval_sec = _time - prev_time
| where interval_sec > 0 AND interval_sec < 3600
| bin interval_sec span=5
| stats count as freq by src_ip, dest_ip, interval_sec
| eventstats max(freq) as max_freq by src_ip, dest_ip
| where freq = max_freq AND max_freq > 10
| eval dominant_period_min = round(interval_sec / 60, 1)
| eval beacon_score = case(
    interval_sec BETWEEN 50 AND 70, 95,
    interval_sec BETWEEN 240 AND 360, 90,
    interval_sec BETWEEN 55 AND 65, 98,
    true(), 70)
| where beacon_score > 80
| sort - beacon_score
| table src_ip, dest_ip, dominant_period_min, freq, beacon_score
```

---

### Data Source Requirements Matrix

| Hunt Type | Sysmon | WEL | Network Flows | DNS | Proxy | EDR | Auth | DLP | Cloud |
|-----------|--------|-----|---------------|-----|-------|-----|------|-----|-------|
| Hypothesis (APT) | Required | Required | Required | Required | Optional | Optional | Required | — | Optional |
| Anomaly (UEBA) | Optional | Required | Required | Required | Required | Optional | Required | Optional | Optional |
| Indicator (Hash) | Required | Optional | Optional | — | Optional | Required | — | — | — |
| Technique (ATT&CK) | Required | Required | Optional | Optional | Optional | Optional | Optional | — | — |
| Chain (Ransomware) | Required | Required | Required | Required | Required | Optional | Required | Optional | — |
| Cloud Compromise | — | — | Optional | Optional | Required | — | Required | — | Required |

**Minimum viable telemetry for hunt program:**
1. Sysmon with SwiftOnSecurity config (process create, network, registry, pipe)
2. Windows Security Event Log (4624, 4625, 4648, 4672, 4688, 4769)
3. DNS recursive queries
4. Outbound proxy/firewall flows with bytes
5. Authentication logs (Active Directory, VPN, cloud IdP)

---

## Hunt Output: Intelligence Loop

Every hunt — find or no-find — feeds back into the detection program:

```
Hunt Completed
├── FIND → 
│   ├── Incident Response (if active threat)
│   ├── Detection Rule Creation (SIGMA → Splunk → SIEM)
│   ├── IOC Dissemination (internal + ISAC sharing)
│   └── ATT&CK layer update (coverage gap → detection created)
│
└── NO FIND →
    ├── Document: "Hunted T1558.003 in 90-day window — not detected"
    ├── Validate: Confirm data sources collected and searchable
    ├── Update: DeTTECT visibility score for covered technique
    └── Schedule: Re-hunt at next cycle (quarterly or after new intel)
```

### Neo4j Hunt Chain Visualization
```cypher
// Store hunt chain results for graph analysis
MERGE (h:Hunt {id: "FEB-01-2024", theme: "ransomware-pre-positioning"})
MERGE (t:Technique {id: "T1071.001"})
MERGE (d:DataSource {name: "network_flows"})
MERGE (r:Rule {id: "beacon-spectral-v1"})

MERGE (h)-[:HUNTS_FOR]->(t)
MERGE (h)-[:USES_DATA]->(d)
MERGE (h)-[:PRODUCES]->(r)
MERGE (r)-[:DETECTS]->(t)

// Query: Which techniques have no hunt coverage this quarter?
MATCH (t:Technique)
WHERE NOT EXISTS((t)<-[:HUNTS_FOR]-(:Hunt {quarter: "2024-Q1"}))
  AND t.priority = "high"
RETURN t.id, t.name
ORDER BY t.priority
```
