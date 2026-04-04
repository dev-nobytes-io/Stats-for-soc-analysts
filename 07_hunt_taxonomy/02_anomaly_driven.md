# Anomaly-Driven Threat Hunts

Anomaly-driven hunts start from the data, not from a specific hypothesis. Statistical or ML-based methods surface deviations from established baselines. The hunt question is: "What in our environment behaves differently from everything else, and why?" This approach catches threats that have no known signature.

**Strength**: Detects novel techniques, zero-days, and sophisticated actors who avoid known IOCs.
**Weakness**: Generates initial false positives that require expert triage; requires mature baseline data.

---

## Baseline Deviation Detection

### Statistical Framework

Before hunting anomalies, baselines must be established and maintained:

```
Baseline hierarchy:
1. Population baseline (all entities)       → catch gross outliers
2. Peer group baseline (similar entities)   → catch relative outliers
3. Individual baseline (entity history)     → catch behavioral shift
4. Composite baseline (multi-metric)        → catch multi-dimensional anomalies
```

**Baseline time windows:**
| Environment | Minimum Baseline | Recommended | Seasonal refresh |
|------------|-----------------|-------------|-----------------|
| Network traffic | 14 days | 30 days | Quarterly |
| User behavior | 21 days | 60 days | Semi-annual |
| Host process | 7 days | 21 days | Monthly |
| Cloud API | 14 days | 30 days | Quarterly |

---

## Hunt 1: Statistical Baseline Deviation — Data Exfiltration Detection

### Hypothesis-Free Starting Point
"I will identify hosts whose outbound data transfer in the past 24 hours is statistically anomalous relative to their personal and peer baselines."

### Statistical Tests Applied
| Metric | Test | Threshold |
|--------|------|-----------|
| Bytes out per host/day | Z-score + MAD | Z > 3 AND ModZ > 3.5 |
| Unique external destinations | IQR | > Q3 + 3×IQR |
| Session count | Z-score | Z > 2.5 |
| Session duration | IQR | > Q3 + 1.5×IQR |

### Multi-Stage Hunt Query

**Stage 1: Individual host anomaly scoring**
```spl
index=network direction=outbound NOT dest_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
| bucket _time span=1d
| stats
    sum(bytes_out) as daily_bytes,
    dc(dest_ip) as unique_dests,
    count as sessions,
    avg(duration) as avg_duration
  by _time, src_ip

| eventstats
    avg(daily_bytes) as mu_bytes, stdev(daily_bytes) as std_bytes,
    avg(unique_dests) as mu_dests, stdev(unique_dests) as std_dests
  by src_ip

| eval z_bytes = (daily_bytes - mu_bytes) / std_bytes
| eval z_dests = (unique_dests - mu_dests) / std_dests

| eval abs_dev_bytes = abs(daily_bytes - mu_bytes)
| eventstats median(abs_dev_bytes) as mad_bytes by src_ip
| eval modz_bytes = 0.6745 * abs_dev_bytes / mad_bytes

| eval p25_dests = percentile(unique_dests, 25)
| eval p75_dests = percentile(unique_dests, 75)
| eval iqr_dests = p75_dests - p25_dests
| eval iqr_flag = if(unique_dests > p75_dests + 3 * iqr_dests, 1, 0)

| where (z_bytes > 3 AND modz_bytes > 3.5) OR (z_dests > 3 AND iqr_flag = 1)

| eval anomaly_score = round((abs(z_bytes) + abs(z_dests)) / 2, 2)
| sort - anomaly_score
| table _time, src_ip, daily_bytes, unique_dests, z_bytes, modz_bytes, anomaly_score
```

**Stage 2: Enrich anomalous hosts with context**
```spl
[results from Stage 1]
| lookup asset_inventory.csv src_ip OUTPUT hostname, owner, dept, asset_class
| lookup geoip_data.csv dest_ip OUTPUT dest_country, dest_asn
| eval bytes_gb = round(daily_bytes / 1073741824, 2)
| where bytes_gb > 0.1
| table _time, src_ip, hostname, owner, dept, bytes_gb, unique_dests, dest_country, anomaly_score
| sort - bytes_gb
```

**Stage 3: Peer group comparison (same department)**
```spl
index=network direction=outbound
| stats sum(bytes_out) as daily_bytes by src_ip
| lookup asset_inventory.csv src_ip OUTPUT dept
| eventstats avg(daily_bytes) as dept_mean, stdev(daily_bytes) as dept_std by dept
| eval dept_z = (daily_bytes - dept_mean) / dept_std
| where dept_z > 3
| sort - dept_z
| table src_ip, dept, daily_bytes, dept_mean, dept_z
```

---

## Hunt 2: ML-Based Process Behavior Anomaly

### Approach
Train an Isolation Forest on 30 days of process execution telemetry. Score all processes in the current 24-hour window. Flag processes with anomaly score > 0.7.

### Feature Engineering
```spl
index=sysmon EventCode=1
| bucket _time span=1h
| stats
    count as exec_count,
    dc(User) as unique_users,
    dc(ParentImage) as unique_parents,
    dc(CommandLine) as unique_cmdlines,
    dc(CurrentDirectory) as unique_dirs
  by _time, host, Image

| eval process_name = lower(mvindex(split(Image, "\\"), -1))

| eventstats
    avg(exec_count) as mu_exec, stdev(exec_count) as std_exec,
    avg(unique_parents) as mu_parents
  by process_name

| eval z_exec = (exec_count - mu_exec) / std_exec
| eval parent_diversity_score = unique_parents / mu_parents

| where z_exec > 2 OR parent_diversity_score > 3
| sort - z_exec
| table _time, host, Image, exec_count, z_exec, unique_parents, parent_diversity_score
```

**MLTK Implementation:**
```spl
| inputlookup process_baseline_features.csv
| fit IsolationForest
    exec_count unique_users unique_parents unique_cmdlines unique_dirs
    n_estimators=200 contamination=0.05
    into process_isoforest

index=sysmon EventCode=1 earliest=-24h
| [same feature engineering as above]
| apply process_isoforest
| where predicted_anomaly = -1
| sort - anomaly_score
| lookup process_reputation.csv process_name OUTPUT known_legit lolbins_flag
| table _time, host, Image, anomaly_score, lolbins_flag
```

### Post-ML Triage Decision Tree
```
Anomaly flagged →
├── Is it a LOLBin (living-off-the-land)? → HIGH priority
│   └── Check parent process, CommandLine for abuse patterns
├── Is it a new process (first seen < 7 days)? → MEDIUM priority
│   └── Verify hash against reputation feed
├── Is the execution count spike sudden? → Check change point
│   └── Apply CUSUM to process execution time series
└── Is the anomaly isolated or widespread?
    ├── Isolated (1 host) → possible targeted compromise
    └── Widespread (>5 hosts) → possible worm/campaign
```

---

## Hunt 3: User Behavior Anomaly (UEBA)

### Feature Set for User Behavior Baseline
```
Per-user daily features:
- login_hour_mean, login_hour_std    (when do they log in)
- unique_systems_accessed           (how many hosts)
- off_hours_ratio                   (% of activity after hours)
- data_volume_z                     (relative to personal baseline)
- new_system_ratio                  (ratio of first-seen systems)
- failed_auth_count                 (authentication failures)
- privilege_use_count               (sudo/admin events)
- external_destination_count        (unique external IPs contacted)
```

**K-Means Clustering for Peer Group Anomaly Detection:**
```spl
| inputlookup ueba_features_30d.csv
| fit StandardScaler login_hour_std unique_systems off_hours_ratio data_volume_z
| fit KMeans k=6 scaled_*
    into user_behavior_clusters

index=auth earliest=-24h
| [feature engineering]
| apply user_behavior_clusters
| lookup user_behavior_clusters model OUTPUT cluster_centroid_distance
| where cluster_centroid_distance > 3
| join user [search index=hr_data | table user, dept, title, employment_status]
| where employment_status = "active"
| sort - cluster_centroid_distance
| table user, dept, title, cluster, cluster_centroid_distance, unique_systems, off_hours_ratio
```

---

## Anomaly Hunt: Calibration and Tuning

### False Positive Management
```
Week 1: High FP rate expected (20-40%) — triage and document
Week 2: Tune thresholds based on confirmed benign patterns
Week 3: Implement exclusions for known-benign anomalies (backup jobs, patch runs)
Week 4: Stable operational FPR target (< 5 actionable anomalies/day)
```

**Exclusion Pattern:**
```spl
| where NOT (
    (dept="IT_OPS" AND _time >= strptime("22:00","%H:%M") AND _time <= strptime("06:00","%H:%M"))
    OR (owner="SCCM_SERVICE" AND Image="*\\ccmexec.exe")
    OR (known_backup_host=1 AND bytes_out > 1073741824)
  )
```

### Statistical Validation of Hunt Results
After triage, run Chi-square test to validate whether flagged entities actually over-represent confirmed threats:

```spl
| stats count as flagged by is_confirmed_threat
| eval expected_threat_rate = 0.05
| eventstats sum(flagged) as N
| eval expected = N * if(is_confirmed_threat=1, expected_threat_rate, 1-expected_threat_rate)
| eval chi_component = pow(flagged - expected, 2) / expected
| stats sum(chi_component) as chi_sq
| eval hunt_effectiveness = if(chi_sq > 3.841, "ANOMALIES OVER-REPRESENT THREATS", "no significant lift")
```
