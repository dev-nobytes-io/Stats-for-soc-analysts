# CIM Field Mapping Reference for Security Data Sources

The Common Information Model (CIM) defines standard field names that allow `tstats` searches to work across different data sources without modification. This file maps raw field names from Sysmon, Windows Security Event Log, Corelight/Zeek, and cloud sources to their CIM equivalents.

---

## CIM Data Model Overview for Security

```
Security-Relevant CIM Data Models:
├── Network_Traffic        ← Firewall, proxy, Zeek/Corelight conn logs
├── Authentication         ← Windows auth, VPN, cloud IdP sign-in
├── Endpoint
│   ├── Processes          ← Process create (Sysmon 1, WEL 4688)
│   ├── Filesystem         ← File create/modify/delete (Sysmon 11, 23)
│   ├── Registry           ← Registry changes (Sysmon 13, 14)
│   └── Services           ← Service install/start/stop
├── Intrusion_Detection    ← IDS/IPS alerts, EDR detections
├── Email                  ← Email gateway logs
├── Web                    ← Web proxy, WAF, CDN logs
├── Change                 ← CMDB changes, patch events
└── Risk                   ← Splunk Enterprise Security risk scores
```

---

## Network_Traffic Data Model

### Required CIM Fields

| CIM Field | Description | Example Value |
|-----------|-------------|--------------|
| `src` | Source IP address | `10.0.1.55` |
| `src_port` | Source port | `52341` |
| `dest` | Destination IP address | `198.51.100.7` |
| `dest_port` | Destination port | `443` |
| `transport` | Layer 4 protocol | `tcp`, `udp` |
| `action` | Allowed or blocked | `allowed`, `blocked` |
| `bytes_in` | Bytes received by src | `1024` |
| `bytes_out` | Bytes sent by src | `4096` |
| `duration` | Session duration in seconds | `45.2` |
| `packets_in` | Packets to src | `12` |
| `packets_out` | Packets from src | `8` |

### Corelight / Zeek conn.log Mapping

| Zeek Field | CIM Field | Notes |
|-----------|-----------|-------|
| `id.orig_h` | `src` | Originator IP |
| `id.orig_p` | `src_port` | Originator port |
| `id.resp_h` | `dest` | Responder IP |
| `id.resp_p` | `dest_port` | Responder port |
| `proto` | `transport` | tcp/udp/icmp |
| `orig_bytes` | `bytes_out` | Bytes from originator |
| `resp_bytes` | `bytes_in` | Bytes from responder |
| `duration` | `duration` | Session duration |
| `conn_state` | `action` | SF/S1=allowed, REJ/RSTO=blocked |
| `orig_pkts` | `packets_out` | |
| `resp_pkts` | `packets_in` | |

**props.conf for Corelight:**
```ini
[corelight_conn]
FIELDALIAS-src       = id.orig_h AS src
FIELDALIAS-src_port  = id.orig_p AS src_port
FIELDALIAS-dest      = id.resp_h AS dest
FIELDALIAS-dest_port = id.resp_p AS dest_port
FIELDALIAS-transport = proto AS transport
FIELDALIAS-bytes_out = orig_bytes AS bytes_out
FIELDALIAS-bytes_in  = resp_bytes AS bytes_in
FIELDALIAS-packets_out = orig_pkts AS packets_out
FIELDALIAS-packets_in  = resp_pkts AS packets_in
EVAL-action = case(
    conn_state IN ("SF","S1","RSTO","RSTR","OTH"), "allowed",
    conn_state IN ("REJ","RSTOS0","RSTRH","SH","SHR","RSTOS0"), "blocked",
    true(), "unknown")
EVAL-app = service
```

### Palo Alto Firewall Mapping

| PA Field | CIM Field |
|---------|-----------|
| `src_ip` | `src` |
| `sport` | `src_port` |
| `dst_ip` | `dest` |
| `dport` | `dest_port` |
| `proto` | `transport` |
| `bytes_sent` | `bytes_out` |
| `bytes_received` | `bytes_in` |
| `elapsed` | `duration` |
| `action` | `action` (already CIM) |
| `application` | `app` |

### tstats for Network_Traffic

```spl
| tstats count AS flows,
         sum(Network_Traffic.bytes_out) AS bytes_out,
         dc(Network_Traffic.dest_port) AS unique_ports,
         dc(Network_Traffic.dest) AS unique_dests
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE Network_Traffic.action=allowed
    NOT Network_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
    NOT Network_Traffic.dest_port IN (80, 443)
  BY Network_Traffic.src _time span=1h
| rename Network_Traffic.src AS src_ip
```

---

## Authentication Data Model

### Required CIM Fields

| CIM Field | Description | Example |
|-----------|-------------|---------|
| `src` | Source IP / hostname attempting auth | `10.0.1.22` |
| `dest` | Target system | `dc01.corp.local` |
| `user` | Username | `jsmith` |
| `action` | Result | `success`, `failure` |
| `app` | Application being authenticated to | `Windows`, `VPN`, `Office365` |
| `signature` | Event type description | `An account was logged on` |
| `logon_type` | Windows logon type | `3` (network), `10` (remote interactive) |

### Windows Security Event Log Mapping

| WEL Field | CIM Field | Event Codes |
|-----------|-----------|------------|
| `IpAddress` | `src` | 4624, 4625, 4648 |
| `ComputerName` | `dest` | All |
| `TargetUserName` | `user` | 4624, 4625 |
| `SubjectUserName` | `user` (for 4648) | 4648 |
| `LogonType` | `logon_type` | 4624, 4625 |
| `EventCode=4624` | `action=success` | |
| `EventCode=4625` | `action=failure` | |
| `ProcessName` | `app` | 4624 |
| `KeyLength` | `signature_extra` | 4769 (Kerberos) |
| `TicketEncryptionType` | `ticket_encryption_type` | 4769 |

**props.conf for Windows Security Log:**
```ini
[WinEventLog:Security]
FIELDALIAS-src          = IpAddress AS src
FIELDALIAS-dest         = ComputerName AS dest
FIELDALIAS-user_4624    = TargetUserName AS user
FIELDALIAS-logon_type   = LogonType AS logon_type
FIELDALIAS-app          = ProcessName AS app
EVAL-action = case(
    EventCode IN (4624,4648,4768,4776), "success",
    EventCode IN (4625,4771,4772,4773), "failure",
    true(), "unknown")
EVAL-signature = case(
    EventCode=4624, "Successful Logon",
    EventCode=4625, "Failed Logon",
    EventCode=4648, "Logon with Explicit Credentials",
    EventCode=4769, "Kerberos Service Ticket Requested",
    EventCode=4771, "Kerberos Pre-Authentication Failed",
    EventCode=4776, "NTLM Authentication",
    EventCode=4672, "Special Privileges Assigned",
    true(), "Unknown Auth Event")
```

**eventtypes.conf:**
```ini
[windows_auth]
search = source="WinEventLog:Security" EventCode IN (4624,4625,4648,4768,4769,4771,4776)
[windows_kerberos]
search = source="WinEventLog:Security" EventCode IN (4768,4769,4770,4771)
```

**tags.conf:**
```ini
[eventtype=windows_auth]
authentication = enabled
[eventtype=windows_kerberos]
authentication = enabled
kerberos = enabled
```

### Azure AD / Entra ID Sign-In Log Mapping

| Entra Field | CIM Field |
|------------|-----------|
| `ipAddress` | `src` |
| `resourceDisplayName` | `dest` |
| `userPrincipalName` | `user` |
| `status.errorCode` (0=success) | `action` |
| `clientAppUsed` | `app` |
| `deviceDetail.operatingSystem` | `os` |
| `location.countryOrRegion` | `src_country` |

**tstats for Authentication:**
```spl
| tstats count AS auth_count,
         dc(Authentication.dest) AS unique_targets,
         dc(Authentication.src) AS unique_sources
  FROM datamodel=Authentication
  WHERE Authentication.action=failure
  BY Authentication.user _time span=1h
| rename Authentication.user AS user
| where auth_count > 20
```

---

## Endpoint Data Model

### Endpoint.Processes — Required CIM Fields

| CIM Field | Description | Sysmon Source | WEL 4688 Source |
|-----------|-------------|--------------|----------------|
| `dest` | Host where process ran | `ComputerName` | `ComputerName` |
| `user` | User context | `User` | `SubjectUserName` |
| `process` | Full command line | `CommandLine` | `CommandLine` |
| `process_name` | Executable filename | derived from `Image` | derived from `NewProcessName` |
| `process_id` | PID | `ProcessId` | `NewProcessId` |
| `process_hash` | File hash | `Hashes` | n/a (use Sysmon) |
| `parent_process` | Parent command line | `ParentCommandLine` | `ParentProcessName` |
| `parent_process_name` | Parent executable name | derived from `ParentImage` | derived from `ParentProcessName` |
| `parent_process_id` | Parent PID | `ParentProcessId` | `ProcessId` |

**props.conf for Sysmon (EventCode=1):**
```ini
[source::XmlWinEventLog:Microsoft-Windows-Sysmon/Operational]
FIELDALIAS-dest              = ComputerName AS dest
FIELDALIAS-user              = User AS user
FIELDALIAS-process           = CommandLine AS process
FIELDALIAS-process_id        = ProcessId AS process_id
FIELDALIAS-parent_process    = ParentCommandLine AS parent_process
FIELDALIAS-parent_process_id = ParentProcessId AS parent_process_id
EVAL-process_name     = mvindex(split(Image, "\\"), -1)
EVAL-process_path     = Image
EVAL-parent_process_name = mvindex(split(ParentImage, "\\"), -1)
EVAL-process_hash     = mvindex(split(Hashes, ","), 0)
```

**eventtypes.conf:**
```ini
[sysmon_process_create]
search = source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
```

**tags.conf:**
```ini
[eventtype=sysmon_process_create]
process = enabled
endpoint = enabled
```

**tstats for processes:**
```spl
| tstats count AS exec_count,
         dc(Endpoint.Processes.user) AS unique_users,
         dc(Endpoint.Processes.dest) AS host_count,
         values(Endpoint.Processes.process_hash) AS hashes
  FROM datamodel=Endpoint.Processes
  WHERE earliest=-24h
  BY Endpoint.Processes.process_name
| rename Endpoint.Processes.process_name AS process_name
| where host_count < 3
| eval prevalence_tier = case(host_count=1, "singleton", host_count <= 5, "rare", true(), "common")
```

### Endpoint.Filesystem — Required CIM Fields

| CIM Field | Description | Sysmon Events |
|-----------|-------------|--------------|
| `dest` | Host | ComputerName |
| `user` | User creating/modifying | User |
| `file_path` | Full file path | TargetFilename |
| `file_name` | Filename only | derived from TargetFilename |
| `file_hash` | Hash | Hashes (Event 11 from Sysmon 15+) |
| `action` | created/modified/deleted | Event 11=created, 23=deleted |
| `file_size` | File size in bytes | n/a from Sysmon (use EDR or WEL) |

**props.conf:**
```ini
[source::XmlWinEventLog:Microsoft-Windows-Sysmon/Operational]
EVAL-file_name = mvindex(split(TargetFilename, "\\"), -1)
EVAL-file_path = TargetFilename
EVAL-action    = case(EventCode=11, "created", EventCode=23, "deleted", EventCode=2, "modified", true(), "unknown")
```

**eventtypes.conf:**
```ini
[sysmon_file_create]
search = source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (11, 23, 2)
```

**tags.conf:**
```ini
[eventtype=sysmon_file_create]
endpoint = enabled
filesystem = enabled
```

### Endpoint.Registry — Required CIM Fields

| CIM Field | Description | Sysmon Events |
|-----------|-------------|--------------|
| `dest` | Host | ComputerName |
| `user` | User | User |
| `registry_path` | Full registry key path | TargetObject |
| `registry_key_name` | Key name only | derived from TargetObject |
| `registry_value_name` | Value name | Details (Event 13) |
| `registry_value_data` | Value data | Details |
| `action` | created/modified/deleted | Event 12=created/deleted, 13=modified |

**tstats for Registry (persistence hunting):**
```spl
| tstats count AS mod_count,
         values(Endpoint.Registry.registry_value_data) AS values_seen
  FROM datamodel=Endpoint.Registry
  WHERE earliest=-24h
    Endpoint.Registry.registry_path IN (
      "*\\CurrentVersion\\Run*",
      "*\\CurrentVersion\\RunOnce*",
      "*\\Winlogon*",
      "*\\Image File Execution Options*",
      "*\\AppInit_DLLs*"
    )
  BY Endpoint.Registry.dest Endpoint.Registry.user Endpoint.Registry.registry_path
| rename Endpoint.Registry.dest AS host,
         Endpoint.Registry.user AS user,
         Endpoint.Registry.registry_path AS reg_path
| lookup known_persistence_keys.csv reg_path OUTPUT is_known_good
| where is_known_good != "yes"
| sort - mod_count
```

---

## Web Data Model

### Required CIM Fields

| CIM Field | Description | Squid/Proxy Source |
|-----------|-------------|-------------------|
| `src` | Client IP | `src_ip` |
| `dest` | Destination hostname | `site` or `url` |
| `url` | Full URL | `url` |
| `http_method` | HTTP method | `method` |
| `status` | HTTP status code | `status` |
| `bytes_in` | Response bytes | `bytes_in` |
| `bytes_out` | Request bytes | `bytes_out` |
| `http_user_agent` | User-Agent string | `useragent` |
| `url_domain` | Domain extracted from URL | derived from `url` |
| `action` | allowed/blocked | derived from status |

**tstats for Web (user-agent anomaly):**
```spl
| tstats count AS request_count,
         dc(Web.url_domain) AS unique_domains,
         dc(Web.src) AS unique_src
  FROM datamodel=Web
  WHERE earliest=-7d
  BY Web.http_user_agent
| rename Web.http_user_agent AS user_agent
| where request_count < 5 AND isnotnull(user_agent)
| eval suspicious = if(
    match(user_agent, "python-requests|go-http|curl|wget|libwww|java|perl|ruby|axios"),
    "SCRIPTED CLIENT", "RARE UA")
| sort request_count
```

---

## Intrusion_Detection Data Model

### Required CIM Fields

| CIM Field | Description |
|-----------|-------------|
| `src` | Attack source |
| `dest` | Attack target |
| `signature` | Alert/signature name |
| `severity` | Alert severity |
| `category` | Threat category |
| `ids_type` | IDS type (network/host) |
| `vendor_product` | Source product |

**tstats for IDS alerts:**
```spl
| tstats count AS alert_count,
         dc(IDS_Attacks.dest) AS targets_hit,
         dc(IDS_Attacks.src) AS attack_sources
  FROM datamodel=Intrusion_Detection.IDS_Attacks
  WHERE earliest=-24h
  BY IDS_Attacks.signature IDS_Attacks.severity _time span=1h
| rename IDS_Attacks.signature AS signature, IDS_Attacks.severity AS severity
| where alert_count > 10
| eventstats avg(alert_count) AS mean_alerts, stdev(alert_count) AS std_alerts
  BY signature
| eval zscore = (alert_count - mean_alerts) / std_alerts
| where zscore > 2.5
| sort - alert_count
```

---

## CIM Compliance Verification Queries

### Check Data Model Coverage

```spl
| datamodel Authentication Authentication search
| stats count BY sourcetype
| sort - count
```

### Verify Field Population Rate

```spl
| tstats count AS events,
         count(Authentication.src) AS has_src,
         count(Authentication.user) AS has_user,
         count(Authentication.action) AS has_action
  FROM datamodel=Authentication
  WHERE earliest=-24h
| eval src_coverage   = round(100 * has_src   / events, 1)
| eval user_coverage  = round(100 * has_user  / events, 1)
| eval action_coverage = round(100 * has_action / events, 1)
| table events, src_coverage, user_coverage, action_coverage
```

### Identify Uncategorized Sourcetypes

```spl
index=* earliest=-1h
| stats count BY sourcetype
| join sourcetype
  [ rest /services/data/models
  | mvexpand objects
  | spath input=objects path=fields{} output=field_list
  | stats count BY title ]
| where isnull(title)
| sort - count
| rename count AS events_last_hour
| table sourcetype, events_last_hour
```

---

## Quick Reference: CIM Field Equivalents Across Sources

| Concept | Network_Traffic | Authentication | Endpoint.Processes | Web |
|---------|----------------|---------------|-------------------|-----|
| Source entity | `src` | `src` | `dest` (host) | `src` |
| Destination | `dest` | `dest` | `process_name` | `url_domain` |
| User context | n/a | `user` | `user` | n/a |
| Volume metric | `bytes_out` | n/a | n/a | `bytes_in` |
| Count | n/a | n/a | n/a | n/a |
| Success/fail | `action` | `action` | n/a | `status` |
| Protocol/app | `transport`, `app` | `app` | n/a | `http_method` |
