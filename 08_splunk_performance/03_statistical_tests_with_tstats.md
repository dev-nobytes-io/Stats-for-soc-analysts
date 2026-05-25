# Statistical Tests Implemented with tstats

This file provides production-scale rewrites of the statistical tests from `06_statistical_tests/` using `tstats` against accelerated data models. Each test shows:
- The naive `index=*` version (good for investigation, small time windows)
- The `tstats` version (required for 30-90 day baselines, scheduled detections, dashboards)

---

## Pattern Reference: tstats vs Raw Search

| Use Case | Raw SPL (`index=`) | tstats Version |
|----------|-------------------|----------------|
| Last 1 hour, one host | ✅ Use raw — faster to write | Overkill |
| Last 24 hours, all hosts | ✅ Either works | Preferred for speed |
| Last 30 days baseline | ❌ Too slow | ✅ Required |
| Scheduled every 5 min | ❌ Expensive at scale | ✅ Required |
| Ad-hoc hunt, small scope | ✅ Raw — no data model needed | Overkill |
| MLTK model training | ❌ Times out | ✅ Required |

---

## 1. Z-Score — Network Traffic Anomaly

### Naive Version (development/investigation)
```spl
index=network
| bucket _time span=1h
| stats count AS conn_count, sum(bytes_out) AS bytes_out
  BY _time, src_ip
| eventstats avg(conn_count) AS mu_conn, stdev(conn_count) AS std_conn
             avg(bytes_out) AS mu_bytes, stdev(bytes_out) AS std_bytes
  BY src_ip
| eval z_conn = (conn_count - mu_conn) / std_conn
| eval z_bytes = (bytes_out - mu_bytes) / std_bytes
| where z_conn > 3 OR z_bytes > 3
```

### tstats Version (production / 30-day baseline)
```spl
| tstats count AS conn_count,
         sum(Network_Traffic.bytes_out) AS bytes_out,
         dc(Network_Traffic.dest) AS unique_dests
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE Network_Traffic.action=allowed
    NOT Network_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
  BY Network_Traffic.src _time span=1h
| rename Network_Traffic.src AS src_ip

| eventstats avg(conn_count) AS mu_conn,    stdev(conn_count) AS std_conn,
             avg(bytes_out) AS mu_bytes,    stdev(bytes_out) AS std_bytes,
             avg(unique_dests) AS mu_dests, stdev(unique_dests) AS std_dests
  BY src_ip

| eval z_conn  = if(std_conn  > 0, (conn_count  - mu_conn)  / std_conn,  0)
| eval z_bytes = if(std_bytes > 0, (bytes_out   - mu_bytes) / std_bytes, 0)
| eval z_dests = if(std_dests > 0, (unique_dests - mu_dests) / std_dests, 0)
| eval composite_z = (abs(z_conn) + abs(z_bytes) + abs(z_dests)) / 3

| where composite_z > 2.5 AND conn_count > 5
| sort - composite_z
| lookup asset_inventory.csv src_ip OUTPUT hostname, owner, dept
| table _time, src_ip, hostname, owner, dept,
        conn_count, bytes_out, unique_dests,
        z_conn, z_bytes, z_dests, composite_z
```

### Scheduled Detection Version (runs every 15 minutes)
```spl
| tstats count AS conn_count, sum(Network_Traffic.bytes_out) AS bytes_out
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE earliest=-15m
  BY Network_Traffic.src _time span=15m
| rename Network_Traffic.src AS src_ip

| join type=left src_ip
  [ inputlookup network_baseline_30d.csv
  | fields src_ip, mu_conn, std_conn, mu_bytes, std_bytes ]

| eval z_conn  = if(std_conn  > 0, (conn_count  - mu_conn)  / std_conn,  0)
| eval z_bytes = if(std_bytes > 0, (bytes_out   - mu_bytes) / std_bytes, 0)
| where z_conn > 3 OR z_bytes > 3
| eval alert_body = "Z-score anomaly: " . src_ip . " z_conn=" . round(z_conn,2) . " z_bytes=" . round(z_bytes,2)
```

**Baseline builder** (runs nightly, saves to lookup):
```spl
| tstats count AS conn_count, sum(Network_Traffic.bytes_out) AS bytes_out
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE earliest=-30d latest=-1d
  BY Network_Traffic.src _time span=1h
| rename Network_Traffic.src AS src_ip
| stats avg(conn_count) AS mu_conn, stdev(conn_count) AS std_conn,
        avg(bytes_out)  AS mu_bytes, stdev(bytes_out)  AS std_bytes
  BY src_ip
| outputlookup network_baseline_30d.csv
```

---

## 2. IQR Outlier Detection — Authentication

### tstats Version
```spl
| tstats count AS login_count
  FROM datamodel=Authentication
  WHERE Authentication.action=success
  BY Authentication.user Authentication.src _time span=1h
| rename Authentication.user AS user, Authentication.src AS src_ip

| stats avg(login_count) AS mean,
        perc25(login_count) AS q1,
        perc75(login_count) AS q3
  BY user

| eval iqr = q3 - q1
| eval upper_fence = q3 + 3 * iqr
| eval lower_fence = max(0, q1 - 1.5 * iqr)

| join user
  [ tstats count AS current_logins
    FROM datamodel=Authentication
    WHERE Authentication.action=success earliest=-24h
    BY Authentication.user _time span=24h
  | rename Authentication.user AS user ]

| where current_logins > upper_fence
| eval excess = current_logins - upper_fence
| sort - excess
| table user, current_logins, q1, q3, upper_fence, excess
```

---

## 3. MAD (Median Absolute Deviation) — Process Execution

### tstats Version
```spl
| tstats count AS exec_count
  FROM datamodel=Endpoint.Processes
  WHERE earliest=-30d
  BY Endpoint.Processes.dest Endpoint.Processes.process_name _time span=1h
| rename Endpoint.Processes.dest AS host,
         Endpoint.Processes.process_name AS process_name

| eventstats median(exec_count) AS med_count BY host, process_name
| eval abs_dev = abs(exec_count - med_count)
| eventstats median(abs_dev) AS mad BY host, process_name

| eval mod_zscore = if(mad > 0, 0.6745 * abs(exec_count - med_count) / mad, 0)
| where abs(mod_zscore) > 3.5

| tstats count AS current_exec
  FROM datamodel=Endpoint.Processes
  WHERE earliest=-1h
  BY Endpoint.Processes.dest Endpoint.Processes.process_name
| rename Endpoint.Processes.dest AS host, Endpoint.Processes.process_name AS process_name

| join host process_name
  [ previous results ]

| eval verdict = "Process execution MAD anomaly: score=" . round(mod_zscore,2)
| sort - mod_zscore
| table host, process_name, current_exec, med_count, mod_zscore
```

---

## 4. Benford's Law — File Size Anomaly Detection

### tstats Version
```spl
| tstats count, values(Endpoint.Filesystem.file_size) AS sizes
  FROM datamodel=Endpoint.Filesystem
  WHERE earliest=-7d
  BY Endpoint.Filesystem.dest Endpoint.Filesystem.file_path
| rename Endpoint.Filesystem.dest AS host

| mvexpand sizes
| eval file_size = tonumber(sizes)
| where file_size > 0
| eval leading_digit = tonumber(substr(tostring(floor(file_size)), 1, 1))
| where leading_digit >= 1 AND leading_digit <= 9

| stats count AS observed BY host, leading_digit
| eventstats sum(observed) AS N BY host

| eval expected_pct = case(
    leading_digit=1, 0.301, leading_digit=2, 0.176, leading_digit=3, 0.125,
    leading_digit=4, 0.097, leading_digit=5, 0.079, leading_digit=6, 0.067,
    leading_digit=7, 0.058, leading_digit=8, 0.051, leading_digit=9, 0.046)
| eval expected = N * expected_pct
| eval chi_sq = pow(observed - expected, 2) / expected

| stats sum(chi_sq) AS total_chi BY host
| where total_chi > 15.507
| sort - total_chi
| eval verdict = "Benford violation — possible artificial file generation"
| table host, total_chi, verdict
```

---

## 5. Change Point Detection (CUSUM) — Authentication Rate

### tstats Version
```spl
| tstats count AS auth_count
  FROM datamodel=Authentication
  WHERE earliest=-30d
  BY _time span=1h
| sort _time

| eventstats avg(auth_count) AS mu, stdev(auth_count) AS sigma

| eval k = 0.5 * sigma
| eval h = 5 * sigma

| streamstats window=1000 sum(eval(auth_count - mu - k)) AS cusum_raw
| eval cusum = max(0, cusum_raw)
| where cusum > h

| eval alert_time = strftime(_time, "%Y-%m-%d %H:%M")
| eval deviation_sigma = round((auth_count - mu) / sigma, 2)
| table _time, alert_time, auth_count, mu, cusum, h, deviation_sigma
```

---

## 6. Pearson Correlation — Beaconing Pattern

Pearson correlation identifies hosts where connection_count and bytes_out are nearly perfectly correlated — a sign of automated, scripted behavior.

### tstats Version
```spl
| tstats count AS conn_count, sum(Network_Traffic.bytes_out) AS bytes_out
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE earliest=-7d
  BY Network_Traffic.src Network_Traffic.dest _time span=1h
| rename Network_Traffic.src AS src, Network_Traffic.dest AS dest

| eventstats avg(conn_count) AS mean_x, avg(bytes_out) AS mean_y BY src, dest
| eval dev_x = conn_count - mean_x
| eval dev_y = bytes_out - mean_y
| eval cross = dev_x * dev_y
| eval sq_x = dev_x * dev_x
| eval sq_y = dev_y * dev_y

| stats sum(cross) AS num, sum(sq_x) AS denom_x, sum(sq_y) AS denom_y,
        count AS n
  BY src, dest

| eval pearson_r = num / sqrt(denom_x * denom_y)
| where abs(pearson_r) > 0.95 AND n > 48
| eval verdict = if(pearson_r > 0.95, "AUTOMATED PATTERN — possible beacon", "inverse correlation")
| sort - abs(pearson_r)
| table src, dest, pearson_r, n, verdict
```

---

## 7. Isolation Forest via tstats Feature Preparation

`tstats` can't run the Isolation Forest algorithm directly (that requires MLTK), but it does the feature engineering at scale before MLTK processes the results.

### Production Pipeline: tstats → MLTK Isolation Forest
```spl
| tstats count AS conn_count,
         sum(Network_Traffic.bytes_out) AS bytes_out,
         sum(Network_Traffic.bytes_in) AS bytes_in,
         dc(Network_Traffic.dest) AS unique_dests,
         dc(Network_Traffic.dest_port) AS unique_ports,
         dc(Network_Traffic.src_port) AS unique_src_ports
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE earliest=-1d
    NOT Network_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
  BY Network_Traffic.src
| rename Network_Traffic.src AS src_ip

| eval bytes_ratio = if(bytes_in > 0, bytes_out / bytes_in, bytes_out)
| eval port_diversity = unique_ports / max(conn_count, 1)

| fit StandardScaler conn_count bytes_out bytes_ratio unique_dests port_diversity
| fit IsolationForest
    conn_count_scaled bytes_out_scaled bytes_ratio_scaled
    unique_dests_scaled port_diversity_scaled
    n_estimators=200 contamination=0.03
    into network_isoforest_daily

| where predicted_anomaly = -1
| sort - anomaly_score
| lookup asset_inventory.csv src_ip OUTPUT hostname, owner, dept, asset_class
| table src_ip, hostname, owner, dept,
        conn_count, bytes_out, unique_dests, anomaly_score
```

### Model Refresh Pattern (daily rebuild)
```spl
| tstats [same feature engineering as above] WHERE earliest=-30d
| fit StandardScaler ...
| fit IsolationForest ... into network_isoforest_daily
```

---

## 8. K-Means Clustering — User Behavior Segmentation

### tstats Feature Build + K-Means
```spl
| tstats count AS event_count,
         dc(Authentication.dest) AS unique_systems,
         dc(Authentication.src) AS unique_src_ips
  FROM datamodel=Authentication
  WHERE earliest=-30d
  BY Authentication.user _time span=1d
| rename Authentication.user AS user

| eval hour = tonumber(strftime(_time, "%H"))
| eval is_off_hours = if(hour < 7 OR hour > 19, 1, 0)
| stats sum(event_count) AS total_events,
        avg(unique_systems) AS avg_systems,
        avg(unique_src_ips) AS avg_src_ips,
        sum(is_off_hours) AS off_hours_days,
        count AS days_active
  BY user

| eval off_hours_ratio = off_hours_days / max(days_active, 1)
| eval events_per_day = total_events / max(days_active, 1)

| fit StandardScaler total_events avg_systems avg_src_ips off_hours_ratio events_per_day
| fit KMeans k=5
    total_events_scaled avg_systems_scaled avg_src_ips_scaled off_hours_ratio_scaled
    events_per_day_scaled
    into user_behavior_clusters_30d

| where cluster_distance > 3
| lookup hr_data.csv user OUTPUT dept, title, manager
| sort - cluster_distance
| table user, dept, title, cluster, cluster_distance,
        total_events, avg_systems, off_hours_ratio
```

---

## 9. First-Seen Detection with tstats

Track new entities (processes, destinations, users) that have never appeared in the 30-day baseline window.

### New External Destination Detection
```spl
| tstats dc(Network_Traffic.src) AS src_count
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE earliest=-30d latest=-1d
    NOT Network_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
  BY Network_Traffic.dest
| rename Network_Traffic.dest AS dest
| eval seen_in_baseline = 1
| outputlookup dest_baseline_30d.csv

| tstats count AS conn_count, values(Network_Traffic.src) AS sources
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE earliest=-24h
    NOT Network_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
  BY Network_Traffic.dest
| rename Network_Traffic.dest AS dest

| lookup dest_baseline_30d.csv dest OUTPUT seen_in_baseline
| where isnull(seen_in_baseline)
| lookup geoip.csv dest OUTPUT country, asn_org
| lookup threat_intel.csv dest OUTPUT threat_category, confidence
| eval is_threat = if(isnotnull(threat_category), "KNOWN THREAT", "FIRST SEEN")
| sort - conn_count
| table dest, conn_count, sources, country, asn_org, is_threat, threat_category
```

### New Process on Endpoint
```spl
| tstats dc(Endpoint.Processes.dest) AS host_count
  FROM datamodel=Endpoint.Processes
  WHERE earliest=-30d latest=-1d
  BY Endpoint.Processes.process_name
| rename Endpoint.Processes.process_name AS process_name
| eval baseline_seen = 1
| outputlookup process_baseline_30d.csv

| tstats count AS exec_count, dc(Endpoint.Processes.dest) AS host_count,
         values(Endpoint.Processes.dest) AS hosts
  FROM datamodel=Endpoint.Processes
  WHERE earliest=-24h
  BY Endpoint.Processes.process_name Endpoint.Processes.process_hash
| rename Endpoint.Processes.process_name AS process_name,
         Endpoint.Processes.process_hash AS hash

| lookup process_baseline_30d.csv process_name OUTPUT baseline_seen
| where isnull(baseline_seen)
| lookup file_reputation.csv hash OUTPUT vt_score, malware_family
| eval risk = case(
    isnotnull(malware_family), "CONFIRMED MALWARE",
    vt_score > 5, "HIGH RISK",
    vt_score > 0, "SUSPICIOUS",
    true(), "NEW UNSEEN PROCESS")
| sort - exec_count
| table process_name, hash, exec_count, host_count, hosts, vt_score, risk
```

---

## 10. Lateral Movement Detection — Multi-Model tstats Join

This is the production version of the Kerberoasting → lateral movement chain hunt from `07_hunt_taxonomy/01_hypothesis_driven.md`.

```spl
| tstats count AS kerberoast_tickets
  FROM datamodel=Authentication
  WHERE Authentication.signature="4769" Authentication.ticket_encryption_type="0x17"
    NOT Authentication.dest_nt_domain="*$"
    earliest=-24h
  BY Authentication.user Authentication.src _time span=1h
| rename Authentication.user AS user, Authentication.src AS src_ip
| eval stage = "kerberoasting"

| appendcols
  [ tstats count AS lateral_logins, dc(Authentication.dest) AS unique_targets
    FROM datamodel=Authentication
    WHERE Authentication.action=success Authentication.logon_type IN (3, 10)
      earliest=-24h
    BY Authentication.user _time span=1h
  | rename Authentication.user AS user ]

| eventstats max(kerberoast_tickets) AS peak_roast BY user
| where peak_roast > 3 AND lateral_logins > 0 AND unique_targets > 2

| join type=left user
  [ tstats count AS priv_use
    FROM datamodel=Authentication
    WHERE Authentication.signature=4672
    BY Authentication.user
  | rename Authentication.user AS user ]

| eval chain_score = kerberoast_tickets * 2 + lateral_logins + unique_targets * 3
    + if(isnotnull(priv_use), 10, 0)
| where chain_score > 15
| sort - chain_score
| table user, src_ip, kerberoast_tickets, lateral_logins, unique_targets, priv_use, chain_score
```

---

## Summary: Choosing the Right SPL Pattern

```
Decision tree for statistical test implementation:

Time window > 24h, high-volume source (network/endpoint)?
├── YES → Use tstats FROM datamodel=
│         └── Then eventstats / streamstats for per-entity stats
└── NO  → Use index=* search
          └── Then stats / eventstats as normal

Need running stats (Z-score per new event as it arrives)?
├── YES → streamstats window=N (running baseline)
└── NO  → eventstats (full-window baseline)

Need session/chain grouping?
├── Session key exists (conn_id, session_id) → stats by session_id
└── No session key → transaction (expensive — last resort)

Need to compare now vs. 30-day history?
├── Two-pass: tstats baseline → outputlookup → tstats current → join
└── Or: tstats with time comparison in BY clause + eval

Need multi-source correlation (auth + network + endpoint)?
├── tstats each source → appendcols (same time bins + entity key)
└── Or: join on entity key (user, src_ip, hostname)
```
