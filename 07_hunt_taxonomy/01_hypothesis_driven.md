# Hypothesis-Driven Threat Hunts

Hypothesis-driven hunts start with a specific, testable premise about attacker behavior before touching data. The hypothesis is grounded in threat intelligence, attacker TTPs, or observed environmental conditions. This is the most efficient hunt type — you know what you're looking for before you start searching.

**Hypothesis structure**: "I believe [threat actor / technique] is [active / targeting / present] because [intelligence trigger], and I will find evidence in [data source] by looking for [observable indicator]."

---

## Hunt Framework: Specific Threat Group Attribution

### Process Flow

```
1. Threat Intelligence Trigger
   ↓ (new campaign report, sector advisory, internal IOC hit)
2. ATT&CK Technique Mapping
   ↓ (map actor TTP profile to technique IDs)
3. DeTTECT Coverage Analysis
   ↓ (identify which techniques have coverage gaps vs. blind spots)
4. Hunt Hypothesis Formulation
   ↓ (specific, falsifiable statement)
5. Data Source Identification
   ↓ (which logs contain observable evidence)
6. SPL/Detection Query Development
   ↓ (implement detection logic)
7. Evidence Review & Triage
   ↓ (analyst review of hits)
8. Find / No-Find Documentation
   ↓ (either escalate or document absence of evidence)
9. Detection Rule Creation
   (convert confirmed TTPs to permanent detections)
```

---

## Example Hunt 1: SolarWinds Sunburst — APT29/Cozy Bear

### Hypothesis
"APT29 is active in our environment following the SolarWinds supply chain compromise. We will find evidence of SUNBURST implant activity through anomalous child processes spawned by SolarWinds.BusinessLayerHost.exe and outbound HTTPS to C2 domains."

### ATT&CK Techniques
| Technique | ID | Observable |
|-----------|-----|-----------|
| Supply Chain Compromise | T1195.003 | SolarWinds process spawning malicious children |
| Command and Scripting Interpreter | T1059.001 | PowerShell spawned by SolarWinds parent |
| Ingress Tool Transfer | T1105 | wget/curl/bcp downloading stage-2 |
| Scheduled Task/Job | T1053.005 | Persistence via scheduled task |
| Application Layer Protocol: HTTPS | T1071.001 | C2 over HTTPS to avsvmcloud domain |
| Domain Generation Algorithms | T1568.002 | DGA subdomain at avsvmcloud.com |
| Masquerading | T1036 | Malicious file named like legitimate SolarWinds component |

### DeTTECT Coverage Gap Analysis
```
Low-coverage techniques requiring hunt focus:
- T1195.003: No supply chain monitoring → prioritize parent process analysis
- T1568.002: DGA detection gap → prioritize DNS entropy analysis
- T1036: Limited process integrity monitoring → hash validation needed
```

### Data Sources Required
- Windows Security Event Log (4688 — process creation with command line)
- Sysmon (Event 1: process create, Event 3: network, Event 7: image load, Event 13: registry)
- DNS proxy logs
- Firewall/proxy egress logs

### Hunt Queries

**Phase 1: Identify SolarWinds hosts and anomalous child processes**
```spl
index=sysmon EventCode=1
ParentImage IN ("*\\SolarWinds.BusinessLayerHost.exe",
               "*\\SolarWinds.BusinessLayerHostx64.exe")
| eval child = lower(Image)
| where NOT match(child, "solarwinds") AND NOT match(child, "orion")
| stats count by ComputerName, ParentImage, Image, CommandLine, ParentCommandLine
| sort - count
| lookup process_reputation.csv Image OUTPUT is_known_good
| where is_known_good != "yes"
| table ComputerName, Image, CommandLine, count
```

**Phase 2: DNS queries to known SUNBURST C2 pattern**
```spl
index=dns
| rex field=query "(?<subdomain>[a-z0-9]{16,32})\.avsvmcloud\.com"
| where isnotnull(subdomain)
| stats count, values(src_ip) as sources, dc(src_ip) as unique_src by subdomain
| lookup known_sunburst_subdomains.csv subdomain OUTPUT is_ioc
| eval threat = if(isnotnull(is_ioc), "CONFIRMED IOC", "SUSPICIOUS DGA")
| table subdomain, sources, unique_src, threat
```

**Phase 3: Network beaconing to high-reputation-but-compromised infrastructure**
```spl
index=proxy
| rex field=url "https?://(?<fqdn>[^/]+)"
| where match(fqdn, "avsvmcloud\.com|databasegalore\.com|deftsecurity\.com|digitalcollege\.org")
| stats count, dc(src_ip) as unique_src, values(src_ip) as hosts by fqdn, _time
| bucket _time span=1h
| sort - count
| table _time, fqdn, unique_src, hosts
```

**Phase 4: Scheduled task persistence**
```spl
index=sysmon EventCode=1
(CommandLine="*schtasks*" OR Image="*\\schtasks.exe")
| eval cmd_lower = lower(CommandLine)
| where match(cmd_lower, "create") AND match(cmd_lower, "(solarwinds|orion)")
| stats count by ComputerName, CommandLine, ParentImage, User
| table ComputerName, User, CommandLine
```

### Pivot Indicators
If any query returns results, pivot to:
1. Full timeline for affected host (24-48h window around first hit)
2. Lateral movement from affected host (auth events, SMB sessions)
3. Memory dump for SUNBURST process (Volatility: malfind, pslist)
4. Network packet capture from affected host to C2 IP

### Find/No-Find Criteria
| Finding | Action |
|---------|--------|
| SolarWinds child process anomaly | Immediate IR — isolate host, escalate to CIRT |
| DNS queries to avsvmcloud pattern | Confirm with proxy logs, then IR |
| No findings | Document hunt, confirm SolarWinds hosts inventoried, schedule re-hunt quarterly |

---

## Example Hunt 2: Lateral Movement Chain — Kerberoasting to Crown Jewel Access

### Hypothesis
"An attacker with initial foothold in a workstation has performed Kerberoasting to obtain service account credentials and is now using them for lateral movement toward high-value servers."

### ATT&CK Kill Chain
```
T1078.002 (Valid Accounts: Domain Accounts)
    → T1558.003 (Steal or Forge Tickets: Kerberoasting)
    → T1087.002 (Account Discovery: Domain Account)
    → T1021.002 (Remote Services: SMB/Windows Admin Shares)
    → T1021.001 (Remote Services: Remote Desktop Protocol)
    → T1005 (Data from Local System — crown jewel access)
```

### Statistical Tie-in
Apply Chi-square test to determine whether Kerberos ticket requests are statistically independent of time-of-day. Automated Kerberoasting creates a non-random distribution — requests cluster in burst patterns inconsistent with human activity.

### Hunt Queries

**Phase 1: Kerberoasting signature (Event 4769 — RC4 encryption for non-machine accounts)**
```spl
index=windows_security EventCode=4769
TicketEncryptionType=0x17
| rex field=ServiceName "(?<svc>[^$]+)$"
| where NOT match(ServiceName, "\$$")
| stats count as ticket_requests by AccountName, ServiceName, ClientAddress, _time
| bucket _time span=1h
| where ticket_requests > 3
| sort - ticket_requests
| table _time, AccountName, ServiceName, ClientAddress, ticket_requests
```

**Phase 2: Post-Kerberoasting LDAP enumeration**
```spl
index=windows_security EventCode=4662
ObjectServer=DS
| where match(Properties, "(?i)(servicePrincipalName|memberOf|adminCount)")
| stats count as ldap_queries, dc(ObjectName) as unique_objects by SubjectUserName, IpAddress
| where ldap_queries > 20
| sort - ldap_queries
| table SubjectUserName, IpAddress, ldap_queries, unique_objects
```

**Phase 3: Lateral movement from Kerberoasted account**
```spl
index=windows_security EventCode=4624 LogonType IN (3, 10)
| stats count as logins, dc(ComputerName) as unique_targets, values(ComputerName) as targets
  by SubjectUserName, IpAddress
| where unique_targets > 3
| join SubjectUserName [
    search index=windows_security EventCode=4769 TicketEncryptionType=0x17
    | stats count by AccountName
    | rename AccountName as SubjectUserName
  ]
| table SubjectUserName, IpAddress, unique_targets, targets
```

**Phase 4: Chain correlation — Kerberoasting → Lateral movement time window**
```spl
index=windows_security EventCode=4769 TicketEncryptionType=0x17
| eval roast_time = _time
| join AccountName [
    search index=windows_security EventCode=4624 LogonType=3
    | eval login_time = _time
    | rename SubjectUserName as AccountName
  ]
| where login_time > roast_time AND login_time < roast_time + 7200
| eval time_delta_min = round((login_time - roast_time) / 60, 1)
| stats min(time_delta_min) as first_lateral_move_min, dc(ComputerName) as hosts_accessed
  by AccountName
| where first_lateral_move_min < 120
| table AccountName, first_lateral_move_min, hosts_accessed
```

### Evidence Correlation Matrix
| Phase | Event IDs | Key Field | Threshold |
|-------|-----------|-----------|-----------|
| Kerberoasting | 4769 | EncType=0x17, non-machine | > 3 in 1 hour |
| LDAP enumeration | 4662 | SPN/adminCount queries | > 20 unique objects |
| Lateral movement | 4624 LogonType 3 | unique_targets | > 3 hosts |
| Chain link | Time correlation | roast_time to first login | < 2 hours |

---

## DeTTECT Integration Pattern

```yaml
# dettect_hunt_mapping.yaml
name: "Hypothesis Hunt - APT29 SolarWinds"
techniques:
  - technique_id: T1195.003
    detection_score: 0        # No current coverage
    hunt_priority: critical
    hunt_query: "sunburst_child_process.spl"
  - technique_id: T1568.002
    detection_score: 1        # Limited coverage
    hunt_priority: high
    hunt_query: "dga_dns_detection.spl"
  - technique_id: T1053.005
    detection_score: 3        # Moderate coverage
    hunt_priority: medium
    hunt_query: "scheduled_task_persistence.spl"
data_sources:
  - sysmon: required
  - dns_logs: required
  - proxy_logs: required
  - windows_security: required
```

---

## Neo4j Graph Query: Lateral Movement Chain Correlation

```cypher
// Find attack chain: Kerberoasting → LDAP → Lateral Movement
MATCH path = (src:Host)-[:KERBEROASTED]->(svc:ServiceAccount)
             -[:LDAP_ENUMERATED]->(domain:Domain)
             -[:LATERAL_MOVED_TO]->(target:Host)
WHERE target.tier = "tier0"  // Crown jewel hosts
  AND ALL(r IN relationships(path) WHERE r.timestamp > datetime() - duration('P7D'))
RETURN src.name, svc.name, target.name,
       [r in relationships(path) | r.timestamp] as timeline
ORDER BY timeline[0] DESC
```

---

## Tracecat Automation Pattern

```python
# tracecat_hypothesis_hunt.py
from tracecat import Workflow, Action

workflow = Workflow("hypothesis_hunt_apt29")

# Phase 1: IOC seed from threat intel
action1 = Action(
    "search_sunburst_processes",
    query=SUNBURST_CHILD_PROCESS_SPL,
    schedule="daily",
    output="sunburst_hits"
)

# Phase 2: Expand to network indicators
action2 = Action(
    "dns_c2_correlation",
    query=DGA_DNS_SPL,
    trigger_on=action1.has_results,
    output="dns_c2_hits"
)

# Phase 3: Alert and escalate
action3 = Action(
    "create_incident",
    trigger_on=action2.has_results,
    severity="critical",
    playbook="sunburst_ir_playbook"
)

workflow.add_sequence([action1, action2, action3])
```
