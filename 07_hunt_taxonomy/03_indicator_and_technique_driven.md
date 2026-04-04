# Indicator-Driven & Technique-Driven Threat Hunts

---

## Part A: Indicator-Driven Hunts

Indicator-driven hunts search for known-bad artifacts: file hashes, IP addresses, domains, registry keys, or user-agent strings derived from threat intelligence. They are the fastest to execute and most precise — but limited to known threats. They complement hypothesis and anomaly hunts, not replace them.

### Indicator Categories

| Indicator Type | Staleness | Reliability | Sources |
|---------------|-----------|-------------|---------|
| File hash (MD5/SHA256) | Weeks-months | High | MISP, VirusTotal, ISAC feeds |
| IP address | Hours-days | Medium | Shodan, AbuseIPDB, sector ISACs |
| Domain/FQDN | Days-weeks | Medium-High | Passive DNS, URLhaus, OpenPhish |
| URL pattern | Days-weeks | Medium | PhishTank, URLhaus |
| Registry key | Months-years | High | SIGMA rules, MISP |
| Certificate SHA1 | Months | High | crt.sh, threat intel reports |
| Mutex name | Months | High | Malware sandbox reports |
| YARA rule | Variable | Very High | VirusTotal, ANY.RUN, Hybrid Analysis |

---

## Hunt 1: Malware Hash Correlation with Lateral Movement

### Scenario
Emotet malware hashes received from sector ISAC. Determine: (a) which hosts are infected, (b) have infected hosts performed lateral movement, (c) what is the blast radius?

### Phase 1: Hash Sweep
```spl
index=sysmon EventCode IN (1, 7, 11)
| eval hash_lower = lower(Hashes)
| lookup emotet_hashes.csv hash_value as hash_lower OUTPUT malware_family, variant, first_seen
| where isnotnull(malware_family)
| stats dc(ComputerName) as infected_hosts, values(ComputerName) as host_list,
        values(Image) as processes by malware_family, variant
| table malware_family, variant, infected_hosts, host_list, processes
```

### Phase 2: C2 Activity from Infected Hosts
```spl
index=network
| lookup emotet_infected_hosts.csv src_ip OUTPUT is_infected
| where is_infected = "yes"
| stats dc(dest_ip) as unique_c2, count as c2_sessions by src_ip
| where c2_sessions > 10
| lookup geoip.csv dest_ip OUTPUT country
| lookup threat_intel_ips.csv dest_ip OUTPUT c2_family
| table src_ip, unique_c2, c2_sessions, country, c2_family
```

### Phase 3: Lateral Movement from Infected Hosts
```spl
index=windows_security EventCode IN (4624, 4648) LogonType IN (3, 10)
| lookup emotet_infected_hosts.csv SubjectIpAddress as IpAddress OUTPUT is_infected
| where is_infected = "yes"
| stats count as lateral_logins, dc(ComputerName) as unique_targets,
        values(ComputerName) as targets by SubjectUserName, IpAddress
| where unique_targets > 2
| table SubjectUserName, IpAddress, unique_targets, targets, lateral_logins
```

### Phase 4: Secondary Payload Drop
```spl
index=sysmon EventCode=11
| lookup emotet_infected_hosts.csv ComputerName OUTPUT is_infected
| where is_infected = "yes"
| eval file_ext = lower(mvindex(split(TargetFilename, "."), -1))
| where file_ext IN ("exe", "dll", "ps1", "vbs", "js", "bat", "cmd", "hta")
| lookup file_reputation.csv TargetFilename OUTPUT reputation_score
| where reputation_score < 50 OR isnull(reputation_score)
| table _time, ComputerName, TargetFilename, reputation_score
```

### Statistical Blast Radius Estimation
Use binomial probability to estimate likelihood that an unscanned host is infected given known prevalence:
```
P(infected | not yet scanned) = k/n (infected proportion in scanned population)
95% CI: k/n ± 1.96 × √(k(n-k)/n³)
```

```spl
| stats count as n, sum(eval(if(is_infected="yes", 1, 0))) as k
| eval prevalence = round(k / n, 3)
| eval ci_margin = 1.96 * sqrt(k * (n-k) / pow(n, 3))
| eval ci_lower = round(prevalence - ci_margin, 3)
| eval ci_upper = round(prevalence + ci_margin, 3)
| eval unscanned_estimate = round(total_hosts * prevalence, 0)
| table k, n, prevalence, ci_lower, ci_upper, unscanned_estimate
```

---

## Hunt 2: Credential Compromise — Dark Web Hash Feed

### Scenario
Credential hashes for organizational email accounts were found in a breach dataset. Hunt for misuse indicators.

### Phase 1: Identify affected accounts and login anomalies
```spl
index=auth action=success
| lookup breached_accounts.csv user OUTPUT is_breached, breach_date
| where is_breached = "yes"
| bucket _time span=1d
| stats count as logins, dc(src_ip) as unique_src, dc(ComputerName) as unique_hosts,
        values(src_ip) as src_ips by _time, user
| eventstats avg(logins) as baseline_logins, stdev(logins) as std_logins by user
| eval login_z = (logins - baseline_logins) / std_logins
| where login_z > 2 OR unique_src > 3
| table _time, user, logins, unique_src, login_z
```

### Phase 2: Impossible travel detection
```spl
index=auth action=success
| lookup breached_accounts.csv user OUTPUT is_breached
| where is_breached = "yes"
| lookup geoip.csv src_ip OUTPUT city, country, lat, lon
| sort user _time
| streamstats current=false window=1 last(lat) as prev_lat, last(lon) as prev_lon,
              last(_time) as prev_time, last(city) as prev_city by user
| eval distance_km = 6371 * acos(sin(lat*pi()/180) * sin(prev_lat*pi()/180) +
                     cos(lat*pi()/180) * cos(prev_lat*pi()/180) *
                     cos((lon-prev_lon)*pi()/180))
| eval time_hr = (_time - prev_time) / 3600
| eval speed_kmh = distance_km / time_hr
| where speed_kmh > 900 AND time_hr > 0
| table _time, user, prev_city, city, distance_km, time_hr, speed_kmh
```

---

## Part B: Technique-Driven Hunts

Technique-driven hunts search for specific ATT&CK technique implementation patterns regardless of who is using them. No specific threat actor required — we hunt the behavior, not the actor.

---

## Hunt 3: T1566.001 — Spearphishing Attachment

### Observable Chain
```
Email delivery → attachment open → process spawned by Office app →
suspicious child process → network connection or persistence
```

### Multi-Source Hunt

**Phase 1: Suspicious email attachments delivered**
```spl
index=email_gateway
| eval ext = lower(mvindex(split(attachment_name, "."), -1))
| where ext IN ("exe", "scr", "bat", "cmd", "vbs", "js", "hta", "iso", "img",
                "docm", "xlsm", "xls", "doc") OR
        (ext IN ("zip", "rar", "7z") AND attachment_count = 1)
| eval suspicious_subject = if(match(lower(subject),
    "invoice|receipt|payment|urgent|action required|confirm|verify|security alert"), 1, 0)
| where suspicious_subject = 1
| stats count as emails, values(sender) as senders, dc(recipient) as unique_targets
  by attachment_name, ext
| sort - emails
| table attachment_name, ext, emails, unique_targets, senders
```

**Phase 2: Office application spawning suspicious children**
```spl
index=sysmon EventCode=1
ParentImage IN ("*\\WINWORD.EXE", "*\\EXCEL.EXE", "*\\POWERPNT.EXE", "*\\OUTLOOK.EXE",
               "*\\MSPUB.EXE", "*\\VISIO.EXE")
Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\wscript.exe", "*\\cscript.exe",
          "*\\mshta.exe", "*\\rundll32.exe", "*\\regsvr32.exe", "*\\certutil.exe",
          "*\\bitsadmin.exe", "*\\wmic.exe", "*\\msiexec.exe")
| stats count by ComputerName, User, ParentImage, Image, CommandLine
| sort - count
| eval risk = case(
    match(Image, "powershell|mshta|wscript"), "CRITICAL",
    match(Image, "cmd|wmic|msiexec"), "HIGH",
    true(), "MEDIUM")
| table ComputerName, User, Image, CommandLine, risk
```

**Phase 3: Network callback from Office-spawned process**
```spl
index=sysmon EventCode=3
| join ComputerName [
    search index=sysmon EventCode=1
    ParentImage IN ("*\\WINWORD.EXE", "*\\EXCEL.EXE", "*\\OUTLOOK.EXE")
    | stats count by ComputerName, ProcessId, Image
    | rename ProcessId as SourceProcessId
  ]
| where isnotnull(Image)
| where NOT (DestinationIp IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
             OR DestinationPort IN (80, 443, 8080))
| table _time, ComputerName, Image, DestinationIp, DestinationPort
```

---

## Hunt 4: T1021.001 — RDP Lateral Movement

### Observable Chain
```
Port 3389 scanning → successful RDP → post-RDP execution → next hop
```

```spl
index=network dest_port=3389
| bucket _time span=1h
| stats dc(dest_ip) as scanned_hosts, count as attempts by _time, src_ip
| where scanned_hosts > 5 OR attempts > 20

| append [
    search index=windows_security EventCode=4624 LogonType=10
    | stats count as rdp_logins, dc(ComputerName) as rdp_hosts by SubjectUserName, IpAddress
    | where rdp_hosts > 2
  ]

| append [
    search index=sysmon EventCode=1
    | join ComputerName [
        search index=windows_security EventCode=4624 LogonType=10
        | stats values(IpAddress) as rdp_src by ComputerName
      ]
    | where ParentImage IN ("*\\rdpclip.exe", "*\\explorer.exe")
    AND Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\net.exe")
    | table _time, ComputerName, rdp_src, Image, CommandLine
  ]
```

---

## Hunt 5: T1055 — Process Injection

### Technique Variants and Observables

| Injection Method | Sysmon Event | Key Fields |
|-----------------|--------------|-----------|
| CreateRemoteThread | Event 8 | SourceImage → TargetImage |
| VirtualAllocEx + WriteProcessMemory | Event 10 (ProcessAccess) | call_trace contains NtAllocate |
| SetWindowsHookEx | Event 1 | unusual parent DLL loading |
| AtomBombing | Event 10 | NtQueueApcThread in call trace |
| Process Hollowing | Event 8 + Event 1 | legitimate image, suspicious cmdline |

```spl
(index=sysmon EventCode=8
 TargetImage IN ("*\\svchost.exe", "*\\explorer.exe", "*\\lsass.exe",
                 "*\\notepad.exe", "*\\calc.exe", "*\\mspaint.exe")
 SourceImage IN ("*\\powershell.exe", "*\\cmd.exe", "*\\wscript.exe",
                 "*\\mshta.exe", "*\\rundll32.exe"))
OR
(index=sysmon EventCode=10
 TargetImage IN ("*\\lsass.exe", "*\\svchost.exe")
 CallTrace IN ("*NtAllocateVirtualMemory*", "*NtWriteVirtualMemory*",
               "*NtCreateRemoteThread*"))

| eval technique = case(
    EventCode=8, "CreateRemoteThread Injection",
    EventCode=10 AND match(CallTrace, "NtAllocate"), "VirtualAllocEx/WriteProcessMemory",
    true(), "Unknown Injection")
| stats count by ComputerName, SourceImage, TargetImage, technique
| sort - count
| table ComputerName, SourceImage, TargetImage, technique, count
```

---

## Hunt 6: T1134 — Token Impersonation / Access Token Manipulation

### Observables
- Low-privilege process accessing token of high-privilege process (Sysmon Event 10)
- `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` granted
- Service account performing actions outside its normal scope

```spl
index=sysmon EventCode=10
(CallTrace IN ("*SeImpersonatePrivilege*", "*ImpersonateLoggedOnUser*",
               "*DuplicateTokenEx*", "*SetThreadToken*"))
| lookup process_privilege_map.csv TargetImage OUTPUT expected_privilege_level
| where SourcePrivilegeLevel < expected_privilege_level
| stats count by ComputerName, SourceImage, TargetImage, SourceUser, TargetUser
| where SourceUser != TargetUser
| table ComputerName, SourceImage, TargetImage, SourceUser, TargetUser, count
```

---

## Indicator-to-Technique Bridge

When an indicator hunt finds a hit, immediately expand to technique coverage:

```
Malware hash found (indicator) →
  Check process parent (T1059: Command and Scripting)
  Check network connections (T1071: Application Layer Protocol)
  Check registry modifications (T1547: Boot/Logon Autostart)
  Check scheduled tasks (T1053: Scheduled Task/Job)
  Check lateral movement (T1021: Remote Services)
  → Build full technique chain for detection rule creation
```

### Integration: SIGMA Rule Generation from Hunt Results
```yaml
# Auto-generated from hunt findings
title: Office Application Spawning Suspicious Process
id: hunt-derived-001
status: experimental
description: Detects Office application spawning process execution tools
  found during T1566.001 hunt on 2024-Q1
author: hunt-automation
date: 2024-01-15
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\OUTLOOK.EXE'
    Image|endswith:
      - '\powershell.exe'
      - '\wscript.exe'
      - '\mshta.exe'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1566.001
  - attack.t1059.001
```
