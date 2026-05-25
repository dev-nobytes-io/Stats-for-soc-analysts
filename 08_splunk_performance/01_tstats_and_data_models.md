# tstats and Accelerated Data Models

`tstats` is the highest-performance search command in Splunk. It queries pre-built **data model acceleration summaries** — columnar indexes stored on disk — instead of scanning raw event data. For large-scale statistical hunting across billions of events, `tstats` is the only viable approach.

---

## Architecture: Why tstats Exists

```
Raw event search (stats):
  Indexer → decompress raw events → extract fields → filter → ship to SH → aggregate
  Cost: O(events_in_time_range) × CPU_per_event

tstats search:
  Indexer → read pre-built columnar summary → aggregate pre-extracted fields → ship to SH
  Cost: O(summary_buckets) — typically 10-100× faster
```

### When tstats is Required vs Optional

| Scenario | Use tstats? | Reason |
|----------|------------|--------|
| Hunt across 90 days of network data | **Required** | Raw scan would take hours |
| Scheduled detection running every 5 min on last 15 min | Optional | Small window, fast either way |
| Statistical baseline over 30 days | **Required** | tstats makes it sub-minute |
| Ad-hoc investigation on 1 host, last 1 hour | Skip | Faster to write raw SPL |
| Real-time dashboard populating every 30s | **Required** | Keeps dashboard responsive |
| MLTK model training on 60-day dataset | **Required** | Feature engineering at scale |

---

## Data Model Fundamentals

A **data model** is a structured schema that maps raw, source-specific field names into a common vocabulary. Splunk's **Common Information Model (CIM)** provides the schema definitions.

### Data Model → Object → Field Hierarchy

```
Data Model: Network_Traffic
└── Object: All_Traffic (root dataset)
    ├── Required fields: src, dest, src_port, dest_port, transport, action, bytes_in, bytes_out
    ├── Constraint: tag=network tag=communicate
    └── Child Object: Allowed_Traffic
        └── Constraint: action=allowed
        └── Child Object: Blocked_Traffic
            └── Constraint: action=blocked

Data Model: Authentication
└── Object: Authentication (root dataset)
    ├── Required fields: src, dest, user, action, app
    ├── Constraint: tag=authentication
    └── Child Object: Default_Authentication
        └── Constraint: action=success OR action=failure

Data Model: Endpoint
├── Object: Processes
│   ├── Required: dest, user, process, process_name, process_id, parent_process
│   └── Constraint: tag=process
├── Object: Filesystem
│   ├── Required: dest, user, file_path, file_name, action
│   └── Constraint: tag=endpoint tag=filesystem
└── Object: Registry
    ├── Required: dest, registry_path, registry_key_name, action
    └── Constraint: tag=endpoint tag=registry
```

### Enabling Data Model Acceleration

Data model acceleration must be enabled for `tstats` to run against it. Without acceleration, `tstats` falls back to raw search (slower) or fails.

**Check acceleration status:**
```spl
| rest /services/data/models
| table title, acceleration, acceleration.earliest_time, acceleration.cron_schedule
```

**Key acceleration settings** (`datamodels.conf`):
```ini
[Network_Traffic]
acceleration = true
acceleration.earliest_time = -30d
acceleration.cron_schedule = */5 * * * *
acceleration.max_time = 3600

[Authentication]
acceleration = true
acceleration.earliest_time = -90d
acceleration.cron_schedule = */5 * * * *

[Endpoint]
acceleration = true
acceleration.earliest_time = -30d
acceleration.cron_schedule = */10 * * * *
```

---

## tstats Syntax Reference

### Basic Syntax

```spl
| tstats [prestats=t] <stats-functions>
  FROM datamodel=<DataModel>.<Object>
  [WHERE <filter>]
  [BY <fields>]
  [GROUPBY <fields>]
  [span=<timespan>]
```

### Key Parameters

| Parameter | Purpose | Example |
|-----------|---------|---------|
| `prestats=t` | Used in subsearches for join operations | `\| tstats prestats=t count BY src` |
| `FROM datamodel=X.Y` | Target data model object | `FROM datamodel=Network_Traffic.All_Traffic` |
| `WHERE` | Filter using CIM fields | `WHERE All_Traffic.action=allowed` |
| `BY` | Group by fields | `BY All_Traffic.src All_Traffic.dest` |
| `span=` | Time bucketing | `span=1h` |
| `fillnull value=0` | Fill missing time buckets | Appended after tstats |

### Field Prefixing Rule

Fields in `tstats` are prefixed with their object name. You **must** use the prefix in `WHERE` and `BY`, but can rename in `eval` afterward.

```spl
| tstats count AS conn_count,
         sum(Network_Traffic.bytes_out) AS total_bytes_out,
         dc(Network_Traffic.dest) AS unique_dests
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE Network_Traffic.action=allowed
  BY Network_Traffic.src _time
  span=1h
| rename Network_Traffic.src AS src_ip
```

---

## Core tstats Patterns for Security

### Pattern 1: Time-Bucketed Aggregation

The most common pattern — compute stats per entity per time window:

```spl
| tstats count AS conn_count,
         sum(Network_Traffic.bytes_out) AS bytes_out,
         dc(Network_Traffic.dest_port) AS unique_ports,
         dc(Network_Traffic.dest) AS unique_dests
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE Network_Traffic.action=allowed
    NOT Network_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
  BY Network_Traffic.src _time
  span=1h
| rename Network_Traffic.src AS src_ip
| sort 0 src_ip _time
```

### Pattern 2: Multi-Object Join via `appendcols`

Join authentication data with network data for the same entity:

```spl
| tstats count AS auth_count,
         dc(Authentication.dest) AS unique_auth_targets
  FROM datamodel=Authentication
  WHERE Authentication.action=success
  BY Authentication.src _time span=1h
| rename Authentication.src AS src_ip

| appendcols
  [ tstats sum(Network_Traffic.bytes_out) AS bytes_out
    FROM datamodel=Network_Traffic.All_Traffic
    BY Network_Traffic.src _time span=1h
  | rename Network_Traffic.src AS src_ip ]

| fillnull value=0
```

### Pattern 3: Subsearch with prestats

Efficient filtering using a subpopulation:

```spl
| tstats count AS auth_count
  FROM datamodel=Authentication
  WHERE Authentication.action=failure
    [search index=asset_inventory is_privileged=true
     | fields src_ip
     | rename src_ip AS Authentication.src]
  BY Authentication.src Authentication.dest _time span=1h
| rename Authentication.src AS src, Authentication.dest AS dest
```

### Pattern 4: Differential Analysis (Before/After Comparison)

```spl
| tstats count AS current_count
  FROM datamodel=Endpoint.Processes
  WHERE earliest=-24h latest=now
  BY Endpoint.Processes.dest Endpoint.Processes.process_name
| rename Endpoint.Processes.dest AS host,
         Endpoint.Processes.process_name AS process

| join type=outer host process
  [ tstats count AS baseline_count
    FROM datamodel=Endpoint.Processes
    WHERE earliest=-30d latest=-24h
    BY Endpoint.Processes.dest Endpoint.Processes.process_name
  | rename Endpoint.Processes.dest AS host,
           Endpoint.Processes.process_name AS process ]

| fillnull value=0
| eval delta = current_count - baseline_count
| eval pct_change = round(100 * (current_count - baseline_count) / (baseline_count + 1), 1)
| where current_count > 0 AND baseline_count = 0
| eval verdict = "FIRST SEEN IN 30 DAYS"
| sort - current_count
```

### Pattern 5: `tstats` + `stats` Pipeline

Use `tstats` for heavy lifting, `stats` for second-pass aggregation:

```spl
| tstats count AS hourly_count
  FROM datamodel=Network_Traffic.All_Traffic
  BY Network_Traffic.src Network_Traffic.dest _time span=1h
| rename Network_Traffic.src AS src, Network_Traffic.dest AS dest

| stats avg(hourly_count) AS mean_conn,
        stdev(hourly_count) AS std_conn,
        max(hourly_count) AS peak_conn,
        count AS hours_observed
  BY src dest

| eval zscore = (peak_conn - mean_conn) / std_conn
| where zscore > 3 AND hours_observed > 24
| sort - zscore
```

---

## Data Model Acceleration: CIM Compliance Requirements

For `tstats` to work, your data **must be CIM-compliant**: events must have the correct tags and field names. This is achieved via field aliases, field extractions, and event type tagging in props.conf and tags.conf.

### Making Sysmon CIM-Compliant for Endpoint.Processes

**props.conf:**
```ini
[WinEventLog:Microsoft-Windows-Sysmon/Operational]
FIELDALIAS-process_name  = Image AS process_path
FIELDALIAS-process_id    = ProcessId AS process_id
FIELDALIAS-parent        = ParentImage AS parent_process
FIELDALIAS-dest          = ComputerName AS dest
FIELDALIAS-user          = User AS user
EVAL-process_name        = mvindex(split(Image, "\\"), -1)
EVAL-process             = CommandLine
```

**eventtypes.conf:**
```ini
[sysmon_process_create]
search = source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
```

**tags.conf:**
```ini
[eventtype=sysmon_process_create]
process = enabled
endpoint = enabled
```

### Making Windows Security Log CIM-Compliant for Authentication

**props.conf:**
```ini
[WinEventLog:Security]
FIELDALIAS-src    = IpAddress AS src
FIELDALIAS-dest   = ComputerName AS dest
FIELDALIAS-user   = TargetUserName AS user
EVAL-action       = case(EventCode=4624, "success", EventCode=4625, "failure", true(), "unknown")
EVAL-app          = "Windows"
```

**eventtypes.conf:**
```ini
[windows_auth_success]
search = source="WinEventLog:Security" EventCode=4624
[windows_auth_failure]
search = source="WinEventLog:Security" EventCode=4625
```

**tags.conf:**
```ini
[eventtype=windows_auth_success]
authentication = enabled
[eventtype=windows_auth_failure]
authentication = enabled
```

### Making Corelight/Zeek CIM-Compliant for Network_Traffic

**props.conf:**
```ini
[corelight_conn]
FIELDALIAS-src       = id.orig_h AS src
FIELDALIAS-src_port  = id.orig_p AS src_port
FIELDALIAS-dest      = id.resp_h AS dest
FIELDALIAS-dest_port = id.resp_p AS dest_port
FIELDALIAS-transport = proto AS transport
FIELDALIAS-bytes_out = orig_bytes AS bytes_out
FIELDALIAS-bytes_in  = resp_bytes AS bytes_in
FIELDALIAS-duration  = duration AS duration
EVAL-action          = if(conn_state IN ("S1","SF","RSTO","RSTR"), "allowed", "blocked")
```

**tags.conf:**
```ini
[eventtype=corelight_conn]
network = enabled
communicate = enabled
```

---

## Performance Benchmarks: tstats vs stats

Approximate performance ratios at scale (your environment will vary):

| Time Range | Events | `stats` Duration | `tstats` Duration | Speedup |
|-----------|--------|-----------------|------------------|---------|
| Last 1 hour | 5M | ~15s | ~2s | 7× |
| Last 24 hours | 120M | ~8 min | ~20s | 24× |
| Last 7 days | 840M | ~55 min | ~2 min | 27× |
| Last 30 days | 3.6B | ~4 hrs | ~8 min | 30× |
| Last 90 days | 10.8B | timeout | ~25 min | ∞ |

**Rule of thumb**: Use `tstats` for any search covering > 1 day of high-volume data sources (network, endpoint).

---

## Troubleshooting tstats

### Common Errors and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `Error in 'tstats': Invalid field` | Field not in data model | Check CIM compliance; use `datamodel` command to inspect available fields |
| `No results` | Acceleration not built yet | Check `\| rest /services/data/models` for acceleration status; wait for build |
| `No acceleration data found` | Acceleration disabled or earliest_time too recent | Enable acceleration, extend `earliest_time` |
| Field returns wrong values | Field alias conflict | Check props.conf for duplicate FIELDALIAS |
| Slow tstats | Acceleration not covering the time range | Extend `acceleration.earliest_time` |

### Verify Data Model Field Availability

```spl
| datamodel Network_Traffic All_Traffic search
| head 5
| table src, dest, src_port, dest_port, bytes_out, action
```

### Check How Many Events Are Accelerated

```spl
| tstats count FROM datamodel=Network_Traffic.All_Traffic
| appendcols
  [ search index=network | stats count AS raw_count ]
| eval pct_accelerated = round(count / raw_count * 100, 1)
| table count, raw_count, pct_accelerated
```
