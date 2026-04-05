# Streaming Commands Deep Dive

Streaming commands execute **per-event** as events flow through the search pipeline. They do not require the full result set to be available before executing — making them memory-efficient and capable of computing running state (history, lag values, cumulative sums) that distributed commands cannot.

Understanding when to use streaming vs. distributed commands is the difference between a 2-second search and a 20-minute one.

---

## Pipeline Architecture: Where Commands Run

```
Search Pipeline:
┌─────────────────────────────────────────────────────────────────┐
│ INDEXERS                                                         │
│  ├── Raw event scan / tstats read                               │
│  ├── Streaming commands execute HERE (distributed streaming)    │
│  │    eval, rex, where, fields, rename, head, tail              │
│  └── Partial aggregation for distributable commands             │
│       stats (partial), timechart (partial)                      │
└────────────────────┬────────────────────────────────────────────┘
                     │ Partial results shipped to Search Head
┌────────────────────▼────────────────────────────────────────────┐
│ SEARCH HEAD                                                      │
│  ├── Final aggregation (stats, timechart, chart)                │
│  ├── Search-head-only streaming commands                        │
│  │    streamstats, eventstats, accum, autoregress               │
│  └── Post-processing (sort, dedup, lookup, outputlookup)        │
└─────────────────────────────────────────────────────────────────┘
```

### Command Execution Location Reference

| Command | Runs On | Distributable? | Note |
|---------|---------|---------------|------|
| `eval` | Indexers + SH | Yes | Most filters run on indexers |
| `rex` | Indexers + SH | Yes | Field extraction runs early |
| `where` | Indexers + SH | Yes | Filter as early as possible |
| `fields` | Indexers + SH | Yes | Reduces data shipped to SH |
| `stats` | Indexers (partial) + SH (merge) | Yes | Distributable aggregation |
| `timechart` | Indexers (partial) + SH (merge) | Yes | |
| `chart` | Indexers (partial) + SH (merge) | Yes | |
| `streamstats` | **Search Head only** | No | Requires ordered result set |
| `eventstats` | **Search Head only** | No | Requires full result set |
| `accum` | **Search Head only** | No | Running totals |
| `autoregress` | **Search Head only** | No | Lagged values |
| `transaction` | **Search Head only** | No | Session grouping |
| `predict` | **Search Head only** | No | Time series modeling |
| `anomalydetection` | **Search Head only** | No | ML-based detection |

**Performance implication**: Commands that run only on the search head require all events to be shipped there first. For large datasets, this means maximally filtering with `where`, `eval`, `fields`, and `tstats` **before** hitting search-head-only commands.

---

## `streamstats` — Running Statistics

`streamstats` computes statistics over a **sliding window** of events ordered by time (or another field). Each event is annotated with statistics computed over the preceding N events.

### Syntax

```spl
| streamstats [window=N] [current=t|f] [global=t|f] [reset_on_change=field]
              <stats-functions>
              [by <groupby-fields>]
```

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `window=N` | entire history | Use last N events for calculation |
| `current=t` | true | Include current event in window |
| `global=t` | true | One stream for all events (not per-group) |
| `reset_on_change=field` | none | Reset window when field value changes |

### Pattern 1: Moving Average for Smoothed Alerting

```spl
index=network
| bucket _time span=1h
| stats count AS conn_count BY _time, src_ip
| sort src_ip _time
| streamstats window=24 avg(conn_count) AS sma_24h,
              stdev(conn_count) AS std_24h
  BY src_ip
| eval upper_band = sma_24h + 2 * std_24h
| eval lower_band = max(0, sma_24h - 2 * std_24h)
| eval band_breach = if(conn_count > upper_band OR conn_count < lower_band, 1, 0)
| where band_breach = 1
| table _time, src_ip, conn_count, sma_24h, upper_band, lower_band
```

### Pattern 2: Lag / Lead Values for Change Detection

```spl
index=auth
| bucket _time span=1h
| stats count AS login_count BY _time, user
| sort user _time
| streamstats current=false window=1 last(_time) AS prev_time,
              last(login_count) AS prev_count
  BY user
| eval time_delta_h = (_time - prev_time) / 3600
| eval count_delta = login_count - prev_count
| eval rate_of_change = count_delta / time_delta_h
| where abs(rate_of_change) > 50
| table _time, user, login_count, prev_count, rate_of_change
```

### Pattern 3: Cumulative Sum for Exfiltration Threshold

```spl
index=network direction=outbound
| sort src_ip _time
| streamstats sum(bytes_out) AS cumulative_bytes BY src_ip
| where cumulative_bytes > 1073741824
| dedup src_ip
| eval threshold_crossed_gb = round(cumulative_bytes / 1073741824, 2)
| lookup asset_inventory.csv src_ip OUTPUT owner, dept
| table src_ip, owner, dept, threshold_crossed_gb
```

### Pattern 4: Running Z-Score (Online Anomaly Detection)

A running Z-score uses streamstats to maintain a live mean and std across the history window — no need for a separate baseline pass:

```spl
index=dns
| bucket _time span=5m
| stats count AS query_count BY _time, src_ip
| sort src_ip _time
| streamstats window=288 avg(query_count) AS running_mean,
              stdev(query_count) AS running_std
  current=false BY src_ip
| eval zscore = if(running_std > 0, (query_count - running_mean) / running_std, 0)
| where zscore > 3 AND query_count > 10
| eval alert_msg = "DNS spike: " . query_count . " queries vs baseline " . round(running_mean,1)
| table _time, src_ip, query_count, running_mean, zscore, alert_msg
```

### Pattern 5: Session-Aware Running Stats (`reset_on_change`)

Reset the running window whenever the entity (user, host) changes — useful for per-session statistics:

```spl
index=proxy
| sort user _time
| streamstats window=50 avg(bytes) AS session_avg_bytes,
              count AS request_num
  reset_on_change=user BY user
| eval is_outlier = if(bytes > session_avg_bytes * 5 AND request_num > 10, 1, 0)
| where is_outlier = 1
| table _time, user, bytes, session_avg_bytes, request_num
```

---

## `eventstats` — Group Statistics Added Back to Each Event

`eventstats` computes statistics over the **full result set** (or group) and annotates **every event** with those statistics. Unlike `stats` (which collapses), `eventstats` preserves all events while adding population-level context to each row.

### Key Difference: stats vs eventstats

```spl
| stats avg(bytes) AS mean_bytes BY src_ip
→ One row per src_ip

| eventstats avg(bytes) AS mean_bytes BY src_ip
→ All original events retained, each annotated with mean_bytes for its src_ip
```

### Pattern 1: Per-Entity Z-Score Without Pre-Aggregation

```spl
index=network direction=outbound
| eventstats avg(bytes_out) AS mu BY src_ip,
             stdev(bytes_out) AS sigma BY src_ip
| eval zscore = (bytes_out - mu) / sigma
| where zscore > 3
| table _time, src_ip, bytes_out, mu, sigma, zscore
```

### Pattern 2: Peer Group Comparison

```spl
index=auth action=success
| lookup user_dept.csv user OUTPUT dept
| eventstats avg(count) AS dept_avg_logins,
             stdev(count) AS dept_std_logins
  BY dept
| stats count AS login_count BY user, dept
| eval dept_zscore = (login_count - dept_avg_logins) / dept_std_logins
| where dept_zscore > 2.5
| table user, dept, login_count, dept_avg_logins, dept_zscore
```

### Pattern 3: Proportion and Percentile Enrichment

```spl
index=endpoint EventCode=4688
| stats count BY host, process_name
| eventstats sum(count) AS total_procs BY host
| eval pct_of_host = round(100 * count / total_procs, 1)
| eventstats perc95(pct_of_host) AS p95_pct
| where pct_of_host > p95_pct
| table host, process_name, count, pct_of_host, p95_pct
```

### Pattern 4: Rank Within Group

```spl
index=network
| stats sum(bytes_out) AS total_bytes BY src_ip, dest_ip
| sort - total_bytes
| eventstats count AS total_pairs
| streamstats count AS rank
| eval pct_rank = round(100 * rank / total_pairs, 1)
| where pct_rank <= 5
| eval verdict = "Top 5% by bytes — investigate"
| table rank, src_ip, dest_ip, total_bytes, pct_rank
```

---

## `transaction` — Session Grouping

`transaction` groups sequential events into sessions based on field values and time thresholds. Produces one row per session with duration, event count, and all combined field values.

### Syntax

```spl
| transaction <groupby-fields>
  [startswith=<search>] [endswith=<search>]
  [maxspan=<timespan>] [maxpause=<timespan>]
  [maxevents=N] [keepevents=t|f] [keeporphans=t|f]
```

**Warning**: `transaction` is expensive — it runs on the search head, buffers all events, and is O(n²) for session assembly. Prefer `stats ... by session_id` when a session key exists.

### Pattern 1: Brute Force Session Detection

```spl
index=auth action=failure
| transaction src maxspan=10m maxpause=30s
| where eventcount > 20
| eval duration_min = round(duration / 60, 1)
| table _time, src, eventcount, duration_min, user
```

### Pattern 2: Lateral Movement Session Chain

```spl
index=windows_security EventCode=4624 LogonType IN (3, 10)
| transaction SubjectUserName maxspan=4h maxpause=30m
| where mvcount(split(ComputerName, "\n")) > 3
| eval hosts_accessed = mvcount(split(ComputerName, "\n"))
| eval first_host = mvindex(split(ComputerName, "\n"), 0)
| eval last_host = mvindex(split(ComputerName, "\n"), -1)
| table _time, SubjectUserName, hosts_accessed, first_host, last_host, duration
```

### When to Use transaction vs stats

```
Use transaction when:
  - No session key exists and you need to infer sessions from time gaps
  - You need the raw events within each session (keepevents=t)
  - Start/end markers define session boundaries (startswith/endswith)

Use stats when:
  - A session_id, conn_id, or similar key already exists
  - You only need aggregate stats (count, duration, bytes) per session
  - Dataset is large (> 1M events) — stats is dramatically faster
```

---

## `eval` — Field Computation and Conditional Logic

`eval` is a streaming command that runs on indexers — making it one of the cheapest operations in the pipeline. Master `eval` patterns to minimize downstream processing.

### Security-Specific eval Patterns

**Pattern 1: Entropy calculation for DGA/DNS tunnel detection**
```spl
index=dns
| eval query_len = len(query)
| eval char_count = query_len
| eval entropy = 0
| eval chars = "abcdefghijklmnopqrstuvwxyz0123456789-."
| foreach char IN (a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,0,1,2,3,4,5,6,7,8,9,-) [
    eval freq_$$FIELD$$ = (len(query) - len(replace(query, "$$FIELD$$", ""))) / query_len
    | eval entropy = entropy - if(freq_$$FIELD$$ > 0, freq_$$FIELD$$ * log(freq_$$FIELD$$, 2), 0)
  ]
| where entropy > 3.5 AND query_len > 20
| table _time, src_ip, query, query_len, entropy
```

**Pattern 2: Temporal feature extraction**
```spl
index=auth
| eval hour = tonumber(strftime(_time, "%H"))
| eval dow = strftime(_time, "%w")
| eval is_business_hours = if(dow IN (1,2,3,4,5) AND hour >= 8 AND hour <= 17, 1, 0)
| eval is_overnight = if(hour >= 22 OR hour <= 5, 1, 0)
| eval time_risk_score = case(
    is_overnight=1, 3,
    is_business_hours=0, 2,
    true(), 0)
| stats avg(time_risk_score) AS avg_time_risk, count AS events BY user
| where avg_time_risk > 1.5
```

**Pattern 3: Composite scoring**
```spl
| eval score = 0
| eval score = score + if(zscore > 3, 30, if(zscore > 2, 15, 0))
| eval score = score + if(unique_dests > 50, 25, if(unique_dests > 20, 10, 0))
| eval score = score + if(is_new_process=1, 20, 0)
| eval score = score + if(off_hours=1, 15, 0)
| eval score = score + if(failed_auth_spike=1, 10, 0)
| eval risk_tier = case(score >= 70, "CRITICAL", score >= 40, "HIGH",
                        score >= 20, "MEDIUM", true(), "LOW")
| where risk_tier IN ("CRITICAL", "HIGH")
| sort - score
```

---

## `autoregress` — Lagged Values for Time Series

`autoregress` adds previous values of a field as new fields on the current event. Useful for AR model implementation, rate-of-change, and inter-event interval calculation.

### Syntax

```spl
| autoregress <field> [AS <newname>] [p=N]
```

Creates fields `<field>_p1`, `<field>_p2`, ..., `<field>_pN` for lags 1 through N.

### Pattern 1: AR(1) Residual Anomaly Detection

```spl
index=network
| bucket _time span=1h
| stats count AS conn_count BY _time, src_ip
| sort src_ip _time
| autoregress conn_count AS conn_lag p=1
| eval ar_predicted = conn_lag_p1
| eval residual = conn_count - ar_predicted
| eventstats avg(residual) AS mean_resid,
             stdev(residual) AS std_resid
  BY src_ip
| eval resid_z = (residual - mean_resid) / std_resid
| where abs(resid_z) > 2.5 AND conn_count > 10
| table _time, src_ip, conn_count, ar_predicted, residual, resid_z
```

### Pattern 2: Connection Interval for Beacon Detection

```spl
index=network
| sort src_ip dest_ip _time
| autoregress _time AS time_lag p=1
| eval interval_sec = _time - time_lag_p1
| where interval_sec > 0 AND interval_sec < 7200
| stats avg(interval_sec) AS mean_interval,
        stdev(interval_sec) AS interval_jitter,
        count AS observations
  BY src_ip, dest_ip
| eval cv = interval_jitter / mean_interval
| where observations > 20 AND cv < 0.1
| eval verdict = "LOW-JITTER BEACON: interval=" . round(mean_interval/60,1) . " min, CV=" . round(cv,3)
| sort cv
```

---

## `accum` — Cumulative Sum

`accum` computes a running cumulative sum. Useful for exfiltration detection and waterfall charts.

```spl
index=network src_ip="10.0.2.44" direction=outbound
| sort _time
| accum bytes_out AS cumulative_exfil
| eval cumulative_gb = round(cumulative_exfil / 1073741824, 3)
| eval milestone = case(
    cumulative_gb > 10, "10GB THRESHOLD EXCEEDED",
    cumulative_gb > 1, "1GB threshold exceeded",
    true(), null())
| where isnotnull(milestone)
| table _time, bytes_out, cumulative_gb, milestone
```

---

## `predict` — Time Series Forecasting

`predict` applies forecasting algorithms to a time series field, generating predicted values and confidence intervals. Anomalies are observations outside the confidence interval.

### Algorithms

| Algorithm | Best For | Handles Seasonality |
|-----------|---------|-------------------|
| `LL` (Local Level) | Slow drift, no seasonality | No |
| `LLT` (Local Level Trend) | Trending data | No |
| `LLP` (Local Level Periodic) | Seasonal without trend | Yes |
| `LLP5` | Weekly + daily seasonality | Yes (5-period) |
| `ARIMA` | Complex autocorrelation | Configurable |

### Pattern 1: Authentication Anomaly Detection with Forecast

```spl
index=auth
| timechart span=1h count AS login_count
| predict login_count algorithm=LLP5
    future_timespan=24
    holdback=168
    upper95=upper95
    lower95=lower95
| eval outside_ci = if(login_count > upper95 OR login_count < lower95, 1, 0)
| where outside_ci = 1
| eval deviation = round(abs(login_count - predicted(login_count)) / stdev(login_count), 2)
| table _time, login_count, "predicted(login_count)", upper95, lower95, deviation
```

### Pattern 2: Detecting Trend Changes with Holdback Validation

```spl
index=network
| timechart span=1d sum(bytes_out) AS daily_bytes
| predict daily_bytes algorithm=LLT
    holdback=30
    upper95=upper_bound
    lower95=lower_bound
| eval anomaly = if(daily_bytes > upper_bound, "HIGH_ANOMALY",
                   if(daily_bytes < lower_bound, "LOW_ANOMALY", "normal"))
| where anomaly != "normal"
| eval excess_gb = round(abs(daily_bytes - predicted(daily_bytes)) / 1073741824, 2)
```

---

## Pipeline Optimization Checklist

Order your pipeline to minimize data moved to the search head:

```
✅ IDEAL PIPELINE ORDER:

1. index/sourcetype filter        ← Indexer: eliminates entire buckets
2. earliest/latest time range     ← Indexer: time-range pruning
3. keyword filter (WHERE clause)  ← Indexer: bloom filter lookup
4. eval (simple field compute)    ← Indexer: per-event, cheap
5. where (post-eval filter)       ← Indexer: reduces event count shipped
6. fields (keep only needed)      ← Indexer: reduces data volume shipped
7. stats / timechart              ← Distributed: partial on indexers, merge on SH
8. eventstats                     ← Search Head: needs full result set
9. streamstats                    ← Search Head: sequential processing
10. eval (post-aggregate compute) ← Search Head: cheap, per row
11. sort / head                   ← Search Head: final ordering
12. lookup / outputlookup         ← Search Head: enrichment
```

```
❌ COMMON ANTI-PATTERNS:

| transaction ...                 ← Expensive; use stats if session key exists
| stats ... | stats ...          ← Double aggregation; combine into one stats
| search field=value             ← After stats: use where instead
| sort 0 ...                     ← Sorts everything; use head N after sort for large sets
| eval ... | where isnull(eval)  ← Use where NOT match() or fieldformat instead
```
