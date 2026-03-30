# Module 2: Infrastructure Traffic Analysis

[← Module 1: AD Traffic Fundamentals](./module_01_ad_traffic_fundamentals.md) | [Module 3: Authentication Patterns →](./module_03_authentication_patterns.md)

---

## Module Overview

| Attribute | Detail |
|---|---|
| **Estimated Time** | 2 hours |
| **PEAK Phase** | Prepare → Explore → Analyze |
| **Data Sources** | Corelight `conn.log`; WinEvent 4624, 4688; Sysmon EID 1, 3 |
| **Prerequisites** | [Module 1: AD Traffic Fundamentals](./module_01_ad_traffic_fundamentals.md) |

### Learning Objectives

After completing this module you will be able to:

1. Identify the normal network and log signatures of SMB, WMI, RPC/DCOM, SCCM/ConfigMgr, and WinRM traffic.
2. Write SPL queries using Corelight `conn.log` to profile SMB connections and flag workstation-to-workstation lateral movement patterns.
3. Explain how WMI uses port 135 plus dynamic high ports and identify suspicious WMI activity in WinEvent 4688 and Sysmon.
4. Distinguish legitimate SCCM client traffic from rogue or hijacked SCCM behaviour.
5. Baseline WinRM destinations per source host and flag unusual PowerShell Remoting usage.

---

## Section 1: SMB Traffic Baselines

### What Generates SMB (TCP 445)?

Server Message Block (SMB) is used for Windows file sharing, printer sharing, and critical domain infrastructure. Understanding the *expected* direction and source of SMB connections is the foundation for detecting lateral movement.

| SMB Use Case | Normal Source → Destination | Frequency |
|---|---|---|
| Group Policy / SYSVOL | Workstation → DC (SYSVOL, NETLOGON shares) | At logon + periodic refresh (~90 min) |
| User home drives / file shares | Workstation → File server | Business hours, user-driven |
| DFS referrals | Client → DC or DFS namespace server | On share access |
| Print spooler | Workstation → Print server (TCP 445) | On print job submission |
| Admin shares (C$, ADMIN$, IPC$) | Admin workstation / jump box → target | Periodic, known admin hosts only |
| DC-to-DC | DC → DC (SYSVOL replication via DFS-R) | Background, low rate |

### Normal vs Abnormal SMB Flow

```mermaid
flowchart LR
    subgraph NORMAL_SMB["Normal SMB Patterns"]
        WS1[Workstation A] -->|"SMB — SYSVOL"| DC[Domain Controller]
        WS2[Workstation B] -->|"SMB — file share"| FS[File Server]
        ADMIN[Admin Jump Box] -->|"SMB — C$ / ADMIN$"| TARGET[Server]
    end

    subgraph ABNORMAL_SMB["Lateral Movement Indicators"]
        ATK[Compromised WS-A] -->|"SMB TCP 445\nworkstation→workstation"| VICTIM[WS-B]
        ATK2[Compromised WS-C] -->|"IPC$ + service create\npsexec pattern"| VICTIM2[WS-D]
    end

    style NORMAL_SMB fill:#1a3a2a,color:#ccc,stroke:#2d6a4f
    style ABNORMAL_SMB fill:#3a1a1a,color:#ccc,stroke:#6a2d2d
```

> **Key signal:** Workstation-to-workstation SMB (both source and destination IPs in the workstation subnet) is the most reliable lateral movement indicator in `conn.log`. Servers can communicate over SMB; workstations should not talk to each other over SMB in normal operation.

### SPL: Profile SMB Connections and Flag Workstation-to-Workstation

```spl
/* Baseline: all SMB traffic — understand who talks to whom over port 445 */
index=corelight sourcetype=corelight_conn id.resp_p=445 earliest=-7d
| stats count as smb_connections, sum(orig_bytes) as bytes_sent,
        dc(id.resp_h) as unique_dests by id.orig_h
| sort - smb_connections
| head 50
```

```spl
/* Detection: workstation-to-workstation SMB (adjust subnet CIDR to your environment) */
index=corelight sourcetype=corelight_conn id.resp_p=445 earliest=-1h
| where match(id.orig_h, "^10\.10\.") AND match(id.resp_h, "^10\.10\.")
| lookup asset_classification ip as id.resp_h OUTPUT asset_type as dest_type
| where dest_type = "workstation" OR isnull(dest_type)
| stats count as lateral_smb, values(id.resp_h) as targets by id.orig_h
| where lateral_smb > 2
| sort - lateral_smb
```

```spl
/* Flag IPC$ access — used in PsExec / service-based lateral movement */
index=wineventlog EventCode=5140 ShareName="\\\\*\\IPC$" earliest=-1h
| stats count, dc(IpAddress) as unique_sources by ShareName, SubjectUserName
| where count > 5
| sort - count
```

---

## Section 2: WMI Traffic

### How WMI Uses the Network

Windows Management Instrumentation (WMI) uses DCOM/RPC for remote operations. The initial connection always goes to **TCP port 135** (the DCOM endpoint mapper), which then negotiates a dynamic high port (typically 49152–65535) for the actual WMI traffic. This two-stage connection pattern is a reliable fingerprint.

| WMI Operation | Port Pattern | Normal Source |
|---|---|---|
| `wmic /node:X` | 135 → dynamic high port | Admin workstations, SCCM, monitoring |
| WMI query (PowerShell) | 135 → dynamic high port | Automation scripts, management tools |
| WMI subscription | 135 → dynamic high port | Legitimate monitoring; also used for persistence |
| SCCM hardware inventory | 135 → dynamic high port | SCCM site server → managed host |

### Normal vs Abnormal WMI Activity

| Normal WMI | Suspicious WMI |
|---|---|
| SCCM server → managed host | Workstation → workstation |
| Known monitoring tool (e.g., SolarWinds, Nagios host) → server | User workstation → DC |
| IT admin tool from jump box | Interactive `wmic.exe` spawned from `cmd.exe` / `powershell.exe` |
| Scheduled SCCM inventory window | WMI subscription created to run a payload (Sysmon EID 19/20/21) |

### WinEvent 4688: WMI Process Launches

WinEvent 4688 captures process creation with command-line arguments (if audit policy is configured). Look for:

```
Process Name: wmic.exe
Command Line: wmic /node:10.10.5.22 process call create "cmd.exe /c ..."
```

This pattern — `wmic.exe` with a `/node:` argument pointing to a remote host — indicates remote WMI execution, which is a common lateral movement technique.

### SPL: Detect Suspicious WMI Usage

```spl
/* WMI remote execution via wmic.exe — flag /node: usage against non-management hosts */
index=wineventlog EventCode=4688 earliest=-24h
| where match(lower(NewProcessName), "wmic\.exe")
  AND match(CommandLine, "(?i)/node:")
| eval target_host = replace(CommandLine, ".*?/node:([^\s]+).*", "\1")
| stats count, values(CommandLine) as cmds, dc(target_host) as unique_targets
        by SubjectUserName, ComputerName, target_host
| sort - unique_targets
```

```spl
/* Baseline: rare WMI consumers by host (processes spawned by WMI service) */
index=sysmon EventCode=1 earliest=-30d
| where match(ParentProcessName, "(?i)wmiprvse\.exe")
| stats count by process_name, host
| where count < 5
| sort count
```

```spl
/* Corelight: port 135 connections from unexpected sources (not known management IPs) */
index=corelight sourcetype=corelight_conn id.resp_p=135 earliest=-1h
| lookup management_hosts ip as id.orig_h OUTPUT is_management
| where isnull(is_management)
| stats count as rpc_connections, dc(id.resp_h) as unique_targets by id.orig_h
| where rpc_connections > 3
| sort - rpc_connections
```

---

## Section 3: RPC and DCOM Baselines

### RPC Traffic Pattern

RPC (Remote Procedure Call) underpins many Windows services: DC replication, WMI, DCOM, print spooler remote operations, and more. The traffic pattern is always:

1. Client connects to **TCP 135** (endpoint mapper) on the server.
2. Server returns a dynamic high port (49152+).
3. Client reconnects to the negotiated high port for the actual RPC call.

In Corelight `conn.log` you will see two distinct flows for every RPC interaction.

### Normal RPC Sources

| Source | Destination | Purpose |
|---|---|---|
| DC | DC | Directory replication (DRSUAPI), netlogon |
| SCCM site server | All managed hosts | Inventory, deployment, policy |
| Monitoring server | All managed hosts | WMI-based health checks |
| Admin jump box | Servers | Remote management |
| Print server | DCs | Spooler service calls |

### Flagging Non-Standard RPC Sources Calling DCs

```mermaid
flowchart LR
    DC1[DC-01] -->|"RPC — replication\nnormal"| DC2[DC-02]
    SCCM[SCCM Server] -->|"RPC — WMI inventory\nnormal"| WS[Workstation]
    MON[Monitoring Server] -->|"RPC — health check\nnormal"| SRV[Server]
    ATK[Compromised WS] -->|"RPC TCP 135 → DC\nanomalous — investigate"| DC3[DC-03]

    style ATK fill:#6a2d2d,color:#fff
    style DC3 fill:#6a2d2d,color:#fff
```

```spl
/* Baseline: who is connecting to DCs on port 135 */
index=corelight sourcetype=corelight_conn id.resp_p=135 earliest=-7d
| lookup dc_ip_list ip as id.resp_h OUTPUT is_dc
| where is_dc = "true"
| stats count by id.orig_h, id.resp_h
| sort - count
```

```spl
/* Flag: workstation-class hosts calling DC on RPC port */
index=corelight sourcetype=corelight_conn id.resp_p=135 earliest=-1h
| lookup dc_ip_list ip as id.resp_h OUTPUT is_dc
| lookup asset_classification ip as id.orig_h OUTPUT asset_type
| where is_dc = "true" AND asset_type = "workstation"
| stats count, dc(id.resp_h) as dc_targets by id.orig_h, asset_type
| sort - count
```

---

## Section 4: SCCM / ConfigMgr Traffic

### SCCM Communication Ports

Microsoft Endpoint Configuration Manager (SCCM/ConfigMgr) uses specific ports for client–management point communication:

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 80 | HTTP | Client → MP | Client policy download (if HTTP configured) |
| 443 | HTTPS | Client → MP | Client policy download (if HTTPS configured) |
| 8530 | HTTP | Client → WSUS/SUP | Software update point |
| 8531 | HTTPS | Client → WSUS/SUP | Software update point (TLS) |
| 10123 | TCP | MP → Client | Client notification (fast channel) |
| 135 + high | RPC | Site server → Client | Inventory, remote tools |

### Recognising Legitimate vs Rogue SCCM Behaviour

| Indicator | Legitimate SCCM | Rogue/Abuse Pattern |
|---|---|---|
| Source IP for port 8530/8531 | Only known SCCM MP/SUP IPs | Workstation or unknown server claiming to be MP |
| Client policy registration | All domain-joined hosts, staged rollout | Sudden burst of new client registrations |
| Software deployment | Known deployment windows; `ccmsetup.exe` parent | `ccmsetup.exe` spawned by `cmd.exe` / `powershell.exe` with unusual args |
| Content download | From known Distribution Point IPs | Content pulled from external IP |

```spl
/* Baseline: SCCM-related ports — who is talking to management points */
index=corelight sourcetype=corelight_conn earliest=-7d
| where id.resp_p IN (8530, 8531, 10123)
| stats count as connections, dc(id.orig_h) as unique_clients by id.resp_h, id.resp_p
| sort - connections
```

```spl
/* Flag: hosts connecting to SCCM ports that are not the known MP */
index=corelight sourcetype=corelight_conn earliest=-1h
| where id.resp_p IN (8530, 8531)
| lookup sccm_mp_list ip as id.resp_h OUTPUT is_known_mp
| where isnull(is_known_mp)
| stats count by id.orig_h, id.resp_h, id.resp_p
| sort - count
```

---

## Section 5: WinRM and PowerShell Remoting

### WinRM Default Ports

Windows Remote Management (WinRM) and PowerShell Remoting use:

| Port | Protocol | Default Use |
|---|---|---|
| **5985** | HTTP (SOAP/WSMan) | Default WinRM — plaintext transport layer |
| **5986** | HTTPS (SOAP/WSMan) | Secure WinRM — TLS transport layer |

> Note: Despite being labelled HTTP/HTTPS, WinRM traffic is not the same as web traffic. Corelight will log it in `conn.log` but not in `http.log` by default.

### Normal vs Attack-Tool WinRM Usage

| Normal WinRM | Attack Tool Usage |
|---|---|
| Admin jump box → servers (port 5985/5986) | Workstation → workstation on 5985 (`evil-winrm`) |
| Automation scripts from service account source hosts | Interactive sessions from compromised accounts |
| Known admin accounts from known source IPs | `Invoke-Command` / `Enter-PSSession` in attack chains |
| IT team during change windows | Outside business hours; new source IP never seen before |
| Destination: servers only | Destination: DCs (high value; unusual for WinRM) |

### SPL: Cardinality of WinRM Destinations per Source

```spl
/* Baseline: WinRM connection cardinality per source — how many unique targets does each host connect to? */
index=corelight sourcetype=corelight_conn earliest=-7d
| where id.resp_p IN (5985, 5986)
| stats dc(id.resp_h) as unique_winrm_targets, count as connections by id.orig_h
| sort - unique_winrm_targets
```

```spl
/* Detection: WinRM from non-admin workstations to multiple hosts */
index=corelight sourcetype=corelight_conn earliest=-1h
| where id.resp_p IN (5985, 5986)
| lookup asset_classification ip as id.orig_h OUTPUT asset_type, is_admin_host
| where asset_type = "workstation" AND NOT is_admin_host = "true"
| stats dc(id.resp_h) as unique_targets, values(id.resp_h) as targets by id.orig_h
| where unique_targets > 1
| sort - unique_targets
```

```spl
/* WinRM sessions correlated with Sysmon: wsmprovhost.exe (WinRM process) spawning children */
index=sysmon EventCode=1 earliest=-1h
| where match(ParentProcessName, "(?i)wsmprovhost\.exe")
| stats count, values(CommandLine) as cmds, dc(host) as unique_hosts by process_name
| sort - count
```

---

## Section 6: Traffic Pattern Comparison Table

| Protocol | Normal Source → Destination | Ports | Normal Use | Attack Tool / Technique | Attack Indicator |
|---|---|---|---|---|---|
| **SMB** | Workstation → DC, File Server | TCP 445 | SYSVOL, file shares, print | PsExec, Impacket SMBExec, CrackMapExec | Workstation→workstation SMB; IPC$ + 7045 service create |
| **WMI/DCOM** | SCCM, monitoring → managed hosts | TCP 135 + high | Inventory, health checks, SCCM | wmiexec (Impacket), `wmic /node:`, PowerShell WMI | Workstation→workstation 135; unusual `wmiprvse.exe` child procs |
| **RPC** | DCs, SCCM → managed hosts | TCP 135 + high | AD replication, remote services | DCSync, DCOM exec | Workstation→DC on 135; non-DC replication calls |
| **SCCM** | SCCM MP → clients | TCP 8530/8531, 10123 | Patch management, deployment | SharpSCCM, rogue SCCM NAA abuse | Unknown hosts on 8530; `ccmsetup.exe` from cmd/PS |
| **WinRM** | Admin jump box → servers | TCP 5985/5986 | Remote admin, PS Remoting | evil-winrm, Invoke-Command lateral movement | Workstation→workstation 5985; DC as WinRM target |

---

## Section 7: Practice Exercise

### Exercise: Find Non-Admin Workstations Making SMB Connections to Other Workstations

**Scenario:** Your SIEM fired an alert for lateral movement from a detection that had too many false positives. You need to tune it by first understanding the baseline, then write a precise query that flags only workstation-to-workstation SMB.

**Step 1 — Understand the full SMB landscape:**

```spl
index=corelight sourcetype=corelight_conn id.resp_p=445 earliest=-7d
| stats count by id.orig_h, id.resp_h
| lookup asset_classification ip as id.orig_h OUTPUT asset_type as src_type
| lookup asset_classification ip as id.resp_h OUTPUT asset_type as dst_type
| stats count by src_type, dst_type
| sort - count
```

*This gives you the cross-tab of all SMB flow types (workstation→server, server→server, workstation→workstation, etc.). Review it to understand your environment's baseline distribution.*

**Step 2 — Isolate workstation-to-workstation SMB with connection count threshold:**

```spl
index=corelight sourcetype=corelight_conn id.resp_p=445 earliest=-1h
| lookup asset_classification ip as id.orig_h OUTPUT asset_type as src_type
| lookup asset_classification ip as id.resp_h OUTPUT asset_type as dst_type
| where src_type = "workstation" AND dst_type = "workstation"
| stats count as smb_attempts, dc(id.resp_h) as unique_targets,
        values(id.resp_h) as target_hosts, sum(orig_bytes) as bytes_sent
        by id.orig_h, src_type
| where smb_attempts > 3
| sort - unique_targets
```

**Step 3 — Correlate with WinEvent 4624 to confirm successful authentication:**

```spl
index=wineventlog EventCode=4624 LogonType=3 earliest=-1h
| rename IpAddress as id.orig_h, ComputerName as dest_host
| join id.orig_h [
    search index=corelight sourcetype=corelight_conn id.resp_p=445 earliest=-1h
    | lookup asset_classification ip as id.orig_h OUTPUT asset_type as src_type
    | lookup asset_classification ip as id.resp_h OUTPUT asset_type as dst_type
    | where src_type = "workstation" AND dst_type = "workstation"
    | stats count by id.orig_h
    | where count > 3
    ]
| table _time, id.orig_h, dest_host, TargetUserName, LogonType, AuthenticationPackageName
| sort - _time
```

**Expected findings:** This three-step approach first establishes the full SMB pattern, then narrows to workstation-to-workstation, then confirms with auth events. True lateral movement will have both the `conn.log` evidence and matching 4624 Type 3 events.

---

## Module Summary

| Key Concept | What to Remember |
|---|---|
| SMB lateral movement | Workstation→workstation SMB (TCP 445) is the primary indicator. DCs and file servers are normal SMB destinations; peer workstations are not. |
| WMI network pattern | TCP 135 always first (endpoint mapper), then dynamic high port. Normal sources: SCCM, monitoring, admin hosts. |
| RPC baseline | Same 135→high-port pattern as WMI. Any workstation-class host calling a DC on 135 warrants investigation. |
| SCCM traffic | Ports 8530/8531 should only come from known MP/SUP IPs. Workstations are consumers, not providers, of SCCM services. |
| WinRM | Ports 5985/5986. Only admin jump boxes should have high `dc(id.resp_h)` for WinRM. Workstation-to-workstation WinRM is an attack tool signature. |

### Related Detection Use Cases

- [Lateral Movement](../03_detection_use_cases/05_lateral_movement.md) — SMB, WMI, WinRM-based lateral movement
- [Rogue Services / Processes](../03_detection_use_cases/09_rogue_services_processes.md) — Service creation via PsExec/WMI
- [Privilege Escalation](../03_detection_use_cases/06_privilege_escalation.md) — RPC-based privilege abuse

---

## Section 8: Windows Process Inventory — Normal Behaviour and LotL Abuse

Understanding what each key Windows process *should* look like is the foundation of Living off the Land (LotL) detection. Every process listed below is legitimate — attackers abuse them precisely because they are trusted and whitelisted.

### Key Windows Processes

| Process | Purpose | Normal Parent | Normal Children | LotL Abuse |
|---|---|---|---|---|
| `svchost.exe` | Hosts Windows services (one per service group) | `services.exe` | Service-specific (e.g. `dllhost.exe`, `conhost.exe`) | Attackers inject into or impersonate it; spawning `cmd.exe` or `powershell.exe` is anomalous |
| `lsass.exe` | Handles auth, stores Kerberos/NTLM creds | `wininit.exe` | None (should have no child processes) | Credential dumping (Mimikatz); LSASS spawning anything is an immediate red flag |
| `services.exe` | Service Control Manager | `wininit.exe` | `svchost.exe`, service binaries | Should only spawn service executables; spawning scripts is suspicious |
| `wininit.exe` | Windows init process | `smss.exe` | `lsass.exe`, `services.exe`, `lsm.exe` | Should never be re-created after boot; duplicate instances = injection |
| `csrss.exe` | Client/Server Runtime Subsystem | `smss.exe` | `conhost.exe` | Should have no network connections; rare children other than conhost are suspicious |
| `spoolsv.exe` | Print Spooler | `services.exe` | Printer driver DLLs | PrintNightmare exploit target; can be abused to execute arbitrary DLLs |
| `taskhost.exe` / `taskhostw.exe` | Hosts scheduled task DLLs | `svchost.exe` | Task-specific | Attackers create scheduled tasks that spawn from this — check the task definition |
| `msiexec.exe` | Windows Installer | Various (install triggers) | Installer child processes | Abused to side-load DLLs or execute payloads: `msiexec /q /i http://...` |
| `rundll32.exe` | Runs DLL exports | Various | `conhost.exe` | Extremely common LotL vector — `rundll32 comsvcs.dll MiniDump` (LSASS dump), `rundll32 javascript:...` |
| `regsvr32.exe` | Registers COM DLLs | Various | None expected | Squiblydoo: `regsvr32 /s /n /u /i:http://... scrobj.dll` — downloads and runs scripts |
| `mshta.exe` | Runs HTA files | Various | `cmd.exe`, `powershell.exe` | Abused to execute VBScript/JScript from URL: `mshta http://...` |
| `wscript.exe` / `cscript.exe` | Windows Script Host | Various | Script-spawned processes | Legitimate for admin scripts; suspicious when spawned by Office processes or from `%TEMP%` |
| `certutil.exe` | Certificate utility | Various | None | Abused to download files: `certutil -urlcache -split -f http://... out.exe` and decode base64 |
| `bitsadmin.exe` | Background Intelligent Transfer | Various | None | `bitsadmin /transfer` used to download attacker tooling |
| `wmic.exe` | WMI command-line | Various | WMI-spawned processes | `wmic process call create` for lateral movement; `wmic /node:X` for remote execution |

### Detecting Anomalous Process Chains

```spl
/* Flag processes spawned by Office apps — common macro execution chain */
index=sysmon EventCode=1 earliest=-24h
| where match(lower(ParentImage), "(?i)winword|excel|outlook|powerpnt|onenote")
| where match(lower(Image), "(?i)cmd\.exe|powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin")
| table _time, host, User, ParentImage, Image, CommandLine
| sort - _time
```

```spl
/* svchost spawning unexpected children — injection or rogue service indicator */
index=sysmon EventCode=1 earliest=-24h
| where match(lower(ParentImage), "svchost\.exe")
| where match(lower(Image), "(?i)cmd\.exe|powershell|wscript|mshta|rundll32|regsvr32|certutil")
| table _time, host, User, ParentImage, Image, CommandLine
```

```spl
/* lsass.exe spawning any child process — immediate red flag */
index=sysmon EventCode=1 earliest=-24h
| where match(lower(ParentImage), "lsass\.exe")
| table _time, host, User, ParentImage, Image, CommandLine
```

```spl
/* LotL: certutil or bitsadmin downloading from the internet */
index=sysmon EventCode=1 earliest=-24h
| where match(lower(Image), "(?i)certutil\.exe|bitsadmin\.exe")
| where match(CommandLine, "(?i)http://|https://|urlcache|transfer|download")
| table _time, host, User, Image, CommandLine
```

```spl
/* LotL: rundll32 executing from non-standard path or with suspicious arguments */
index=sysmon EventCode=1 earliest=-24h
| where match(lower(Image), "rundll32\.exe")
| where match(CommandLine, "(?i)javascript:|http://|comsvcs|pcwutl|advpack|ieadvpack")
    OR match(CommandLine, "(?i)%temp%|%appdata%|\\\\users\\\\")
| table _time, host, User, Image, CommandLine
```

---

## Section 9: WSUS and SCCM Distribution Points

### WSUS — Windows Server Update Services

WSUS is the patch management service used in most enterprise Windows environments. Understanding its traffic is essential because:
- Legitimate WSUS creates high-volume, predictable traffic that can mask exfiltration
- Attackers can exploit WSUS to deliver malicious updates (WSUSpendu, PyWSUS)
- Rogue WSUS servers can be set up via GPO poisoning or local registry modification

**Normal WSUS Traffic Pattern:**

| Direction | Ports | Frequency | Description |
|---|---|---|---|
| Client → WSUS server | TCP 8530 (HTTP) or 8531 (HTTPS) | Every 22 hours (default) + on demand | Client checks for updates |
| WSUS → Microsoft Update | TCP 443 | Nightly sync | Server pulls update metadata |
| Client → DP/WSUS | TCP 8530/8531 | During update window | Actual patch content download |

```spl
/* Baseline: who connects to port 8530/8531 and from where? */
index=corelight sourcetype=corelight_conn earliest=-7d
| where id.resp_p IN (8530, 8531)
| stats count AS connections, dc(id.orig_h) AS unique_clients
    BY id.resp_h, id.resp_p
| sort - connections
```

```spl
/* Anomaly: clients connecting to a WSUS server that is NOT in your known list */
index=corelight sourcetype=corelight_conn earliest=-1h
| where id.resp_p IN (8530, 8531)
| lookup wsus_server_list ip as id.resp_h OUTPUT is_known_wsus
| where isnull(is_known_wsus)
| stats count, dc(id.orig_h) AS unique_clients, values(id.orig_h) AS clients
    BY id.resp_h
| sort - count
```

```spl
/* WSUS abuse: suspicious process spawned by Windows Update (TrustedInstaller or wuauclt) */
index=sysmon EventCode=1 earliest=-24h
| where match(lower(ParentImage), "(?i)trustedinstaller|wuauclt|usocoreworker|musnotification")
| where NOT match(lower(Image), "(?i)tiworker|wusa|wuauclt|msiexec|setup|install")
| table _time, host, User, ParentImage, Image, CommandLine
```

### SCCM Distribution Points

Distribution Points (DPs) serve application and patch content to SCCM clients. Key characteristics:
- Clients connect via HTTP (80) or HTTPS (443) to the DP's IIS site — **same ports as web traffic**
- Content is served from `\SMS_DP$` share path
- Clients authenticate with their machine certificate or anonymous (less secure)
- DPs only serve content to domain-joined clients — connections from non-domain IPs are suspicious

```spl
/* Baseline: content downloads from DPs (HTTP GET from known DP IPs) */
index=corelight sourcetype=corelight_http earliest=-7d
| lookup sccm_dp_list ip as id.resp_h OUTPUT is_dp
| where is_dp = "true"
| where method="GET"
| where match(uri, "(?i)SMS_DP|Content|CCM_POST")
| stats count AS downloads, sum(response_body_len) AS bytes_delivered,
        dc(id.orig_h) AS unique_clients
    BY id.resp_h
| sort - bytes_delivered
```

```spl
/* Anomaly: non-domain hosts downloading from DPs, or DPs serving non-standard content */
index=corelight sourcetype=corelight_http earliest=-1h
| lookup sccm_dp_list ip as id.resp_h OUTPUT is_dp
| where is_dp = "true"
| where NOT match(uri, "(?i)SMS_DP|Content|CCM_POST|ccm_system|ccm_client")
| table _time, id.orig_h, id.resp_h, uri, method, status_code, response_body_len
```

---

## Section 10: Malicious IT Admin and Shadow IT Detection

### The Insider Admin Problem

Malicious or negligent IT administrators represent a uniquely difficult detection challenge because:
- All their actions use legitimate tools and credentials
- They have the access rights to perform the actions they take
- They can disable the very logging mechanisms used to detect them
- Change management records may not cover all their activity

The key insight is: **legitimate admin actions follow change management patterns — undocumented admin actions are anomalies regardless of how authorised the account is.**

### Audit Policy Modification (Disabling Logging)

```spl
/* EID 4719: System audit policy changed — one of the most critical admin abuse signals */
index=wineventlog EventCode=4719 earliest=-7d
| where NOT match(SubjectUserName, "\\$$")
| stats count, values(AuditPolicyChanges) AS policy_changes,
        values(ComputerName) AS affected_hosts
    BY SubjectUserName
| sort - count
```

```spl
/* Sysmon: auditpol.exe used to modify audit settings */
index=sysmon EventCode=1 earliest=-24h
| where match(lower(Image), "auditpol\.exe")
| where match(CommandLine, "(?i)/set|/clear|/disable|/remove")
| table _time, host, User, Image, CommandLine
```

### Task Sequences and Deployment Scripts Suppressing Logs

SCCM task sequences and deployment scripts can suppress Windows Event Log writes by:
- Disabling the Windows Event Log service (`net stop eventlog`)
- Modifying audit policy via `auditpol.exe`
- Clearing event logs (`wevtutil cl Security`)
- Setting log maximum size to minimum to trigger rapid overwrite

```spl
/* Detect log clearing or service stop targeting Windows Event Log */
index=wineventlog EventCode=1102 earliest=-30d
| stats count AS log_clears, values(SubjectUserName) AS clearers
    BY ComputerName
| sort - log_clears
```

```spl
/* Sysmon: commands that stop/disable the event log service */
index=sysmon EventCode=1 earliest=-24h
| where match(CommandLine, "(?i)(net|sc)\s+(stop|config|delete)\s+(eventlog|wecsvc|winrm)")
    OR match(CommandLine, "(?i)wevtutil\s+(cl|clear-log)")
    OR match(CommandLine, "(?i)set-service.*eventlog.*disabled")
| table _time, host, User, Image, CommandLine
```

```spl
/* Task sequences: ccmexec or smsswd running auditpol or wevtutil — suspicious in production */
index=sysmon EventCode=1 earliest=-30d
| where match(lower(ParentImage), "(?i)ccmexec|smsswd|tasksequence|smswd")
| where match(lower(Image), "(?i)auditpol|wevtutil|net\.exe|sc\.exe")
| table _time, host, User, ParentImage, Image, CommandLine
```

### Detecting Undocumented Admin Activity

Cross-reference admin actions against change management windows. If you maintain a lookup of approved change windows, flag admin-class operations performed outside those windows:

```spl
/* Admin actions outside of approved change windows */
index=wineventlog (EventCode=7045 OR EventCode=4728 OR EventCode=4720 OR EventCode=5136) earliest=-7d
| eval hour_of_day = tonumber(strftime(_time, "%H"))
| eval day_of_week = strftime(_time, "%A")
| eval in_change_window = if(
    (day_of_week IN ("Tuesday","Wednesday","Thursday") AND hour_of_day >= 22 AND hour_of_day <= 23)
    OR (day_of_week="Saturday" AND hour_of_day >= 6 AND hour_of_day <= 12),
    "YES", "NO"
  )
| where in_change_window="NO"
| eval event_desc = case(
    EventCode=7045, "Service installed: " + ServiceName,
    EventCode=4728, "User added to group: " + GroupName,
    EventCode=4720, "Account created: " + TargetUserName,
    EventCode=5136, "AD attribute changed: " + ObjectDN,
    true(), "EventCode " + EventCode
  )
| table _time, SubjectUserName, event_desc, ComputerName, in_change_window
| sort - _time
```

---

## Section 11: Splunk Lookup Build-Out

Lookups are the foundation of contextual detection in this repository. Without them, SPL queries cannot distinguish "workstation" from "server" or "known management host" from "rogue". This section provides the commands to populate them.

### Required Lookups

| Lookup File | Purpose | Key Fields |
|---|---|---|
| `asset_classification.csv` | Maps IPs to asset types | `ip`, `asset_type`, `hostname`, `is_admin_host` |
| `dc_list.csv` | All domain controller IPs/names | `ip`, `computername`, `is_dc` |
| `management_hosts.csv` | Known management/monitoring IPs | `ip`, `hostname`, `is_management` |
| `sccm_mp_list.csv` | SCCM Management Point IPs | `ip`, `hostname`, `is_known_mp` |
| `sccm_dp_list.csv` | SCCM Distribution Point IPs | `ip`, `hostname`, `is_dp` |
| `wsus_server_list.csv` | WSUS server IPs | `ip`, `hostname`, `is_known_wsus` |
| `unconstrained_delegation_hosts.csv` | Hosts with unconstrained delegation | `hostname`, `has_unconstrained` |

### Extracting Asset Data via PowerShell (AD Module)

```powershell
# Requires: Active Directory PowerShell module (RSAT)
# Run on a domain-joined host with read access to AD

# 1. Export all Domain Controllers
Get-ADDomainController -Filter * |
  Select-Object @{n='ip';e={$_.IPv4Address}},
                @{n='computername';e={$_.HostName}},
                @{n='is_dc';e={'true'}} |
  Export-Csv -Path .\dc_list.csv -NoTypeInformation

# 2. Export all computers with asset classification
Get-ADComputer -Filter * -Properties IPv4Address, OperatingSystem, Description |
  Select-Object @{n='ip';e={$_.IPv4Address}},
                @{n='hostname';e={$_.DNSHostName}},
                @{n='asset_type';e={
                    if ($_.OperatingSystem -match 'Server') { 'server' }
                    elseif ($_.OperatingSystem -match 'Windows 10|Windows 11') { 'workstation' }
                    else { 'unknown' }
                }},
                @{n='is_admin_host';e={
                    if ($_.Description -match 'jump|admin|mgmt') { 'true' } else { 'false' }
                }} |
  Export-Csv -Path .\asset_classification.csv -NoTypeInformation

# 3. Export unconstrained delegation computers
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
  Select-Object @{n='hostname';e={$_.DNSHostName}},
                @{n='has_unconstrained';e={'true'}} |
  Export-Csv -Path .\unconstrained_delegation_hosts.csv -NoTypeInformation

# 4. Export service accounts with SPNs (Kerberoastable targets)
Get-ADUser -Filter {ServicePrincipalName -ne "$null" -and Enabled -eq $true} `
  -Properties ServicePrincipalName, PasswordLastSet, MemberOf |
  Select-Object SamAccountName, PasswordLastSet,
                @{n='spns';e={$_.ServicePrincipalName -join '|'}} |
  Export-Csv -Path .\kerberoastable_accounts.csv -NoTypeInformation

# 5. Export accounts without Kerberos pre-authentication (AS-REP roastable)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} |
  Select-Object SamAccountName, DistinguishedName |
  Export-Csv -Path .\asrep_roastable.csv -NoTypeInformation
```

### Extracting SCCM Infrastructure via PowerShell

```powershell
# Requires: ConfigurationManager PowerShell module and SCCM Admin rights

# Import ConfigMgr module (path varies by CM version)
Import-Module "$env:SMS_ADMIN_UI_PATH\..\ConfigurationManager.psd1"
$SiteCode = (Get-PSDrive -PSProvider CMSite).Name
Set-Location "$SiteCode`:"

# Export Management Points
Get-CMManagementPoint |
  Select-Object @{n='hostname';e={$_.NetworkOSPath -replace '\\\\',''}},
                @{n='is_known_mp';e={'true'}} |
  Export-Csv -Path .\sccm_mp_list.csv -NoTypeInformation

# Export Distribution Points
Get-CMDistributionPoint |
  Select-Object @{n='hostname';e={$_.NetworkOSPath -replace '\\\\',''}},
                @{n='is_dp';e={'true'}} |
  Export-Csv -Path .\sccm_dp_list.csv -NoTypeInformation
```

### Extracting WSUS Servers via Registry/DNS

```powershell
# Query AD for WSUS GPO settings (WUServer value)
Get-GPRegistryValue -All -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" `
  -ValueName WUServer -ErrorAction SilentlyContinue |
  Select-Object @{n='wsus_url';e={$_.Value}} |
  ForEach-Object {
    [System.Net.Dns]::GetHostAddresses(([uri]$_.wsus_url).Host) |
      ForEach-Object { [PSCustomObject]@{ip=$_.IPAddressToString; is_known_wsus='true'} }
  } | Export-Csv -Path .\wsus_server_list.csv -NoTypeInformation
```

### Loading Lookups into Splunk

After generating the CSVs, upload them via the Splunk UI (`Settings → Lookups → Lookup table files`) or via the CLI:

```bash
# Copy CSVs to Splunk lookup directory
SPLUNK_HOME=/opt/splunk
APP=search   # or your custom app name

for f in asset_classification dc_list management_hosts sccm_mp_list \
         sccm_dp_list wsus_server_list unconstrained_delegation_hosts; do
  cp ./${f}.csv ${SPLUNK_HOME}/etc/apps/${APP}/lookups/
done

# Restart is not required for lookup files — they are read on demand
```

Define lookup definitions in `transforms.conf`:

```ini
# $SPLUNK_HOME/etc/apps/<app>/default/transforms.conf

[asset_classification]
filename = asset_classification.csv
case_sensitive_match = false

[dc_list]
filename = dc_list.csv
case_sensitive_match = false

[management_hosts]
filename = management_hosts.csv
case_sensitive_match = false

[sccm_mp_list]
filename = sccm_mp_list.csv
case_sensitive_match = false

[sccm_dp_list]
filename = sccm_dp_list.csv
case_sensitive_match = false

[wsus_server_list]
filename = wsus_server_list.csv
case_sensitive_match = false

[unconstrained_delegation_hosts]
filename = unconstrained_delegation_hosts.csv
case_sensitive_match = false
```

---

## Section 12: Splunk Data Model Configuration

### Why Data Models Matter

The Common Information Model (CIM) data models normalise field names across all data sources so that:
- Correlation searches (ES) work without source-specific SPL
- `tstats` can run at acceleration speed across terabytes of data
- Dashboards built against CIM work regardless of the underlying sourcetype

### Relevant CIM Data Models

| Data Model | Use Case | Key Sources |
|---|---|---|
| `Network_Traffic` | All Corelight conn.log detections | `corelight_conn` |
| `Authentication` | All WinEvent 4624/4625/4768/4769 | `wineventlog` |
| `Endpoint` | Sysmon EID 1/3/7/11, WinEvent 4688/7045 | `sysmon`, `wineventlog` |
| `Intrusion_Detection` | IDS/signature alerts | — |
| `DNS` | Corelight dns.log | `corelight_dns` |

### CIM Field Mappings: Corelight conn.log → Network_Traffic

Add to your Corelight TA's `props.conf` or in `$SPLUNK_HOME/etc/apps/<app>/default/props.conf`:

```ini
[corelight_conn]
EVAL-src = id.orig_h
EVAL-src_port = id.orig_p
EVAL-dest = id.resp_h
EVAL-dest_port = id.resp_p
EVAL-bytes_out = orig_bytes
EVAL-bytes_in = resp_bytes
EVAL-duration = duration
EVAL-transport = proto
EVAL-action = if(conn_state IN ("SF","S1","S2","S3"), "allowed", "blocked")
```

### CIM Field Mappings: WinEvent Authentication

```ini
[WinEventLog:Security]
EVAL-user = coalesce(SubjectUserName, TargetUserName)
EVAL-src = coalesce(IpAddress, WorkstationName)
EVAL-dest = ComputerName
EVAL-action = if(EventCode IN ("4624","4768","4769","4770"), "success", "failure")
EVAL-app = "Windows"
EVAL-authentication_method = AuthenticationPackageName
EVAL-logon_type = LogonType
```

### CIM Field Mappings: Sysmon EID 1 → Endpoint Processes

```ini
[XmlWinEventLog:Microsoft-Windows-Sysmon/Operational]
EVAL-process = Image
EVAL-process_id = ProcessId
EVAL-parent_process = ParentImage
EVAL-parent_process_id = ParentProcessId
EVAL-process_name = replace(Image, ".*\\\\", "")
EVAL-user = User
EVAL-dest = Computer
EVAL-cmdline = CommandLine
```

### Enabling Data Model Acceleration

In Splunk Web: `Settings → Data Models → [model name] → Edit Acceleration`

Or via `datamodels.conf`:

```ini
# $SPLUNK_HOME/etc/apps/<app>/default/datamodels.conf

[Network_Traffic]
acceleration = true
acceleration.earliest_time = -90d
acceleration.cron_schedule = */5 * * * *

[Authentication]
acceleration = true
acceleration.earliest_time = -90d
acceleration.cron_schedule = */5 * * * *

[Endpoint]
acceleration = true
acceleration.earliest_time = -90d
acceleration.cron_schedule = */5 * * * *
```

### Using `tstats` with Accelerated Data Models

Once acceleration is active, replace `stats` with `tstats` for orders-of-magnitude speed improvements:

```spl
/* tstats equivalent of: stats count BY src, dest, dest_port FROM conn.log */
| tstats summariesonly=true count AS conn_count,
         sum(All_Traffic.bytes_out) AS bytes_out
    FROM datamodel=Network_Traffic.All_Traffic
    WHERE All_Traffic.dest_port=445
    BY All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
    span=1h
| rename All_Traffic.* AS *
| sort - conn_count
```

---

[← Module 1: AD Traffic Fundamentals](./module_01_ad_traffic_fundamentals.md) | [Module 3: Authentication Patterns →](./module_03_authentication_patterns.md)
