# Univariate Statistical Tests for Threat Hunting

Univariate tests analyze a single variable in isolation to identify anomalous observations. In threat hunting, this translates to flagging individual events, hosts, users, or processes that deviate from expected behavior without requiring correlation with other variables.

---

## 1. Z-Score (Standard Score)

### What It Analyzes
Measures how many standard deviations an observation is from the population mean. Assumes normal distribution of the baseline population.

### Formula
```
z = (x - μ) / σ

where:
  x = observed value
  μ = population mean
  σ = population standard deviation
```

### Outputs
- Z-score per observation (continuous float)
- Flagged entities exceeding threshold (typically |z| > 2.5 or 3.0)
- Ranked list of outliers

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Numeric series | Event counts, byte volumes, login frequencies |
| Threshold | Float | Typically 2.5–3.0 for security use cases |
| Output | Float per record | Standardized deviation score |
| Flagged | Boolean | True if |z| > threshold |

### Assumptions
- Data is approximately normally distributed
- Mean and standard deviation are stable (no significant drift)
- Sample size ≥ 30 for reliable estimates
- Observations are independent

### Limitations
- Sensitive to outliers in the baseline (outliers inflate σ, masking anomalies)
- Fails with multimodal or heavily skewed distributions
- A single extreme value can shift μ and σ, reducing sensitivity
- Does not work well with small populations (< 30 entities)

### Cybersecurity Use Case
**Detecting Beaconing and Abnormal Connection Frequencies**

A host making 847 outbound connections in an hour when the organizational baseline is μ=12, σ=8 yields z=104 — an extreme outlier indicating automated C2 beaconing.

Also applicable to:
- Login attempt frequency spikes (brute force)
- DNS query volume anomalies (DGA/tunneling)
- Data transfer volume outliers (exfiltration)
- Process execution rate deviations (worm propagation)

### Splunk SPL Examples

**Basic Z-Score on DNS Query Volume**
```spl
index=dns
| bucket _time span=1h
| stats count as dns_count by _time, src_ip
| eventstats avg(dns_count) as mean_count, stdev(dns_count) as std_count
| eval zscore = (dns_count - mean_count) / std_count
| where zscore > 3
| sort - zscore
| table _time, src_ip, dns_count, zscore
```

**Z-Score on Authentication Events (Brute Force Detection)**
```spl
index=auth action=failure
| bucket _time span=1h
| stats count as fail_count by _time, src_ip, user
| eventstats avg(fail_count) as mean_fail, stdev(fail_count) as std_fail by user
| eval zscore = (fail_count - mean_fail) / std_fail
| where zscore > 2.5 AND fail_count > 10
| eval risk_score = round(zscore * 10, 1)
| sort - risk_score
| table _time, src_ip, user, fail_count, zscore, risk_score
```

**Z-Score on Outbound Data Volume (Exfiltration)**
```spl
index=network direction=outbound
| bucket _time span=1h
| stats sum(bytes_out) as total_bytes by _time, src_ip
| eventstats avg(total_bytes) as mean_bytes, stdev(total_bytes) as std_bytes by src_ip
| eval zscore = (total_bytes - mean_bytes) / std_bytes
| where zscore > 3
| eval bytes_mb = round(total_bytes / 1048576, 2)
| sort - zscore
```

---

## 2. Median Absolute Deviation (MAD)

### What It Analyzes
A robust alternative to Z-score that uses the median instead of the mean. Resistant to outliers in the baseline, making it more reliable when the data itself may contain anomalies.

### Formula
```
MAD = median(|xi - median(X)|)

Modified Z-score:
Mi = 0.6745 * (xi - median(X)) / MAD

Flag if |Mi| > 3.5 (Iglewicz & Hoaglin threshold)
```

### Outputs
- MAD value for the dataset
- Modified Z-score per observation
- Flagged records exceeding threshold

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Numeric series | Any security metric |
| Constant | 0.6745 | Scaling factor for consistency with normal distribution |
| Threshold | Float | Typically 3.5 for security contexts |
| Output | Float per record | Modified Z-score |

### Assumptions
- Symmetric distribution preferred (but more robust than Z-score for asymmetric data)
- MAD > 0 (degenerate if more than half values are identical)
- Works best when the majority of observations are legitimate

### Limitations
- If MAD = 0 (e.g., most values are 0 with sparse spikes), test breaks — requires fallback
- Slower to compute than Z-score at scale
- Less interpretable for stakeholders unfamiliar with the metric

### Cybersecurity Use Case
**Process Execution Anomaly Detection**

When baselining process execution counts per host, a few hosts with worm activity would inflate the standard deviation in a Z-score calculation. MAD remains anchored to the median, catching the anomalous hosts without the baseline being corrupted by them.

Ideal for:
- User logon hour anomalies (insider threat)
- Service account activity spikes
- Failed authentication counts across accounts
- File access rate outliers in DLP contexts

### Splunk SPL Examples

**MAD-Based Anomaly Detection on Login Hours**
```spl
index=auth action=success
| eval hour = strftime(_time, "%H")
| stats count as login_count by user, hour
| eventstats median(login_count) as med_count by user
| eval abs_dev = abs(login_count - med_count)
| eventstats median(abs_dev) as mad by user
| eval modified_zscore = if(mad > 0, 0.6745 * (login_count - med_count) / mad, 0)
| where abs(modified_zscore) > 3.5
| sort - modified_zscore
| table user, hour, login_count, modified_zscore
```

**MAD on Process Execution Frequency**
```spl
index=endpoint EventCode=4688
| bucket _time span=1h
| stats count as proc_count by _time, host, process_name
| eventstats median(proc_count) as med by host, process_name
| eval abs_dev = abs(proc_count - med)
| eventstats median(abs_dev) as mad by host, process_name
| eval mod_zscore = if(mad > 0, 0.6745 * (proc_count - med) / mad, 0)
| where abs(mod_zscore) > 3.5
| table _time, host, process_name, proc_count, mod_zscore
```

---

## 3. Interquartile Range (IQR)

### What It Analyzes
Defines the middle 50% of data (Q3 - Q1) and flags observations below Q1 - 1.5×IQR or above Q3 + 1.5×IQR as outliers. Non-parametric and robust to distributional assumptions.

### Formula
```
IQR = Q3 - Q1

Lower fence = Q1 - 1.5 × IQR
Upper fence = Q3 + 1.5 × IQR

For stricter detection (extreme outliers):
Lower fence = Q1 - 3.0 × IQR
Upper fence = Q3 + 3.0 × IQR
```

### Outputs
- Q1, Q3, IQR values
- Upper and lower fence values
- Boolean flag per observation
- Count of outliers

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Numeric series | Security metric of interest |
| Multiplier | Float | 1.5 (mild) or 3.0 (extreme) outliers |
| Output | Boolean per record | True if outside fence |
| Supplemental | Float | Distance beyond fence |

### Assumptions
- No distributional assumption required
- Works with skewed data
- Requires sufficient data points to compute stable quartiles (n ≥ 20)

### Limitations
- Percentile calculation can be inconsistent across tools (different interpolation methods)
- Does not capture the magnitude of the deviation beyond the fence
- Both tails treated symmetrically — may miss asymmetric threat patterns

### Cybersecurity Use Case
**Network Port Scan Detection**

Port scan activity creates connection attempts to many unique ports. IQR on unique_ports_per_src per hour catches scanners without requiring a parametric assumption about what "normal" port diversity looks like.

Also used for:
- Packet size anomalies (small-packet floods, large exfil packets)
- Session duration outliers (long-lived C2 sessions)
- User file access volume (DLP/insider)
- API call rate anomalies (abuse detection)

### Splunk SPL Examples

**IQR on Unique Destination Ports (Port Scan)**
```spl
index=network
| bucket _time span=1h
| stats dc(dest_port) as unique_ports by _time, src_ip
| eventstats perc25(unique_ports) as q1, perc75(unique_ports) as q3 by _time
| eval iqr = q3 - q1
| eval upper_fence = q3 + 1.5 * iqr
| eval lower_fence = q1 - 1.5 * iqr
| where unique_ports > upper_fence
| eval excess = unique_ports - upper_fence
| sort - excess
| table _time, src_ip, unique_ports, upper_fence, excess
```

**IQR on Session Duration (Long-lived C2)**
```spl
index=network
| eval duration_sec = end_time - start_time
| stats avg(duration_sec) as avg_dur by src_ip, dest_ip
| eventstats perc25(avg_dur) as q1, perc75(avg_dur) as q3
| eval iqr = q3 - q1
| eval upper_fence = q3 + 3.0 * iqr
| where avg_dur > upper_fence
| eval duration_hr = round(avg_dur / 3600, 2)
| sort - avg_dur
```

---

## 4. Grubbs' Test

### What It Analyzes
Formally tests whether the maximum or minimum value in a dataset is a statistically significant outlier. Uses a t-distribution to compute a critical value for the test statistic.

### Formula
```
G = max(|xi - x̄|) / s

Critical value: G_critical = ((n-1)/√n) * √(t²α/(2n),n-2 / (n-2 + t²α/(2n),n-2))

Reject H0 (no outlier) if G > G_critical

where:
  n = sample size
  s = sample standard deviation
  tα = t-distribution critical value at significance level α
```

### Outputs
- G statistic
- Critical value at chosen significance level
- Binary decision: outlier or not
- P-value

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Numeric series | Security metric, single population |
| Alpha | Float | Significance level (0.05 typical) |
| Output | Float | G test statistic |
| Decision | Boolean | True if significant outlier detected |

### Assumptions
- Data must be approximately normally distributed
- Tests one outlier at a time (not designed for multiple outliers)
- Requires n ≥ 6 for meaningful results

### Limitations
- Masking problem: multiple outliers can hide each other (use iteratively)
- Assumes normality — fails on heavily skewed security data without transformation
- Only tests the single most extreme value; must be applied iteratively for multiple outliers
- Not suitable for small groups (< 6 observations)

### Cybersecurity Use Case
**Identifying the Single Most Anomalous Entity**

When investigating a specific user population (e.g., all administrators), Grubbs identifies the single most statistically deviant entity — the account with the most anomalous authentication volume. Useful for prioritizing investigation in a defined peer group.

### Splunk SPL Examples

**Grubbs' Approximation on Admin Login Volume**
```spl
index=auth action=success user_group=admin
| stats count as login_count by user
| eventstats avg(login_count) as mean, stdev(login_count) as std, count as n
| eval G = abs(login_count - mean) / std
| eval G_critical = (n - 1) / sqrt(n) * 0.9812
| where G > G_critical
| sort - G
| table user, login_count, G, G_critical
```

---

## 5. Benford's Law

### What It Analyzes
In naturally occurring datasets, the leading digit d occurs with frequency log₁₀(1 + 1/d). Significant deviation from this distribution indicates artificial construction, manipulation, or anomalous generation patterns.

### Formula
```
P(d) = log₁₀(1 + 1/d)   for d ∈ {1, 2, 3, 4, 5, 6, 7, 8, 9}

Expected frequencies:
  1: 30.1%   2: 17.6%   3: 12.5%   4: 9.7%
  5: 7.9%    6: 6.7%    7: 5.8%    8: 5.1%   9: 4.6%

Chi-square goodness of fit:
χ² = Σ (Observed - Expected)² / Expected
df = 8, reject if χ² > 15.507 at α=0.05
```

### Outputs
- Observed vs. expected frequency per digit (1–9)
- Chi-square statistic and p-value
- Deviation plot per digit
- Flag for datasets violating Benford's distribution

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Numeric dataset | Transaction amounts, file sizes, IP addresses, timestamps |
| Min Sample | Integer | ≥ 1000 records for reliable test |
| Output | Float | Chi-square statistic |
| P-value | Float | Probability under null hypothesis |
| Flag | Boolean | True if p < 0.05 |

### Assumptions
- Dataset spans multiple orders of magnitude
- Values are not constrained to a fixed range
- Data is naturally generated (not rounded or pre-processed)
- Sample size ≥ 1000 for stable frequency estimates

### Limitations
- Fails on data with a fixed range (e.g., percentages 0–100, ports 1–1024)
- Not applicable to randomly assigned values (IP addresses, hashes)
- Can produce false positives on legitimate multi-modal distributions
- Sensitive to sample composition — mixing different processes invalidates the test

### Cybersecurity Use Case
**Financial Fraud and Insider Threat in Expense/Transaction Data**

Employees submitting expense reports just under approval thresholds (e.g., $4,999.99) create an overrepresentation of leading digit 4 that violates Benford's Law. Similarly, malware generating random-looking C2 traffic may produce packet sizes or timing values that fail the Benford test.

Also useful for:
- Detecting round-number DNS TTL manipulation
- Identifying scripted file size generation (malware dropping payloads)
- Flagging anomalous timestamp clustering in log manipulation
- Testing authenticity of network flow datasets

### Splunk SPL Examples

**Benford's Law on File Sizes (Malware Payload Detection)**
```spl
index=endpoint EventCode=11
| where file_size > 0
| eval leading_digit = tonumber(substr(tostring(file_size), 1, 1))
| where leading_digit >= 1 AND leading_digit <= 9
| stats count as observed by leading_digit
| eval total = 6582
| eval expected_pct = case(
    leading_digit=1, 0.301,
    leading_digit=2, 0.176,
    leading_digit=3, 0.125,
    leading_digit=4, 0.097,
    leading_digit=5, 0.079,
    leading_digit=6, 0.067,
    leading_digit=7, 0.058,
    leading_digit=8, 0.051,
    leading_digit=9, 0.046)
| eval expected = round(total * expected_pct, 0)
| eval chi_component = (observed - expected) * (observed - expected) / expected
| stats sum(chi_component) as chi_square
| eval significant = if(chi_square > 15.507, "ANOMALOUS", "NORMAL")
```

**Benford's Law on Transaction Amounts (Insider Financial Fraud)**
```spl
index=financial_transactions
| where amount > 0
| eval leading_digit = tonumber(substr(tostring(floor(amount)), 1, 1))
| where leading_digit >= 1 AND leading_digit <= 9
| stats count as observed by leading_digit
| eventstats sum(observed) as N
| eval expected_pct = case(
    leading_digit=1, 0.301, leading_digit=2, 0.176,
    leading_digit=3, 0.125, leading_digit=4, 0.097,
    leading_digit=5, 0.079, leading_digit=6, 0.067,
    leading_digit=7, 0.058, leading_digit=8, 0.051,
    leading_digit=9, 0.046)
| eval expected = N * expected_pct
| eval deviation_pct = round(100 * (observed - expected) / expected, 1)
| eval chi_sq = (observed - expected) * (observed - expected) / expected
| table leading_digit, observed, expected, deviation_pct, chi_sq
| addcoltotals chi_sq
```

---

## Summary: Univariate Test Selection Guide

| Threat Scenario | Recommended Test | Why |
|----------------|-----------------|-----|
| Beaconing (connection frequency) | Z-Score | Normal-ish distribution, fast compute |
| Login anomalies with dirty baseline | MAD | Robust to outliers in baseline |
| Port scanning (unique port count) | IQR | Non-parametric, skewed data |
| Single worst offender in peer group | Grubbs | Formal single-outlier test |
| Scripted data generation (file sizes) | Benford's Law | Detects artificial construction patterns |
| Mixed approach — high confidence | Z-Score + MAD ensemble | Cross-validate both scores |
