# Bivariate Statistical Tests for Threat Hunting

Bivariate tests measure the relationship between two variables. In threat hunting, this identifies correlated behaviors (e.g., lateral movement correlating file access with authentication events), detects anomalous associations that indicate compromise, or validates that two metrics expected to correlate actually do.

---

## 1. Pearson Correlation

### What It Analyzes
Measures the linear relationship between two continuous variables. Produces a coefficient r ∈ [-1, 1] where ±1 = perfect linear relationship and 0 = no linear relationship.

### Formula
```
r = Σ[(xi - x̄)(yi - ȳ)] / √[Σ(xi - x̄)² × Σ(yi - ȳ)²]

Significance test:
t = r√(n-2) / √(1-r²)
df = n - 2
```

### Outputs
- Correlation coefficient r ∈ [-1, 1]
- P-value for significance test
- 95% confidence interval for r

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input X | Numeric continuous | Variable 1 (e.g., bytes sent) |
| Input Y | Numeric continuous | Variable 2 (e.g., connection count) |
| Output | Float [-1, 1] | Pearson r coefficient |
| P-value | Float | Significance probability |

### Assumptions
- Both variables are continuous and normally distributed
- Linear relationship between variables
- No significant outliers (sensitive to extreme values)
- Homoscedasticity (constant variance across range)

### Limitations
- Measures only linear relationships — misses nonlinear associations
- Sensitive to outliers (a single extreme pair can dominate)
- Correlation ≠ causation
- Not appropriate for ordinal or categorical data

### Cybersecurity Use Case
**Correlating C2 Beaconing Metrics**

Legitimate web traffic shows strong positive correlation between connection_count and bytes_transferred. Beaconing traffic shows near-perfect correlation (r ≈ 0.99) with very low variance — a sign of automated, scripted behavior. Conversely, high byte volume with low connection count indicates large single-session transfers (exfiltration).

Also useful for:
- Correlating CPU usage with network activity (cryptominer detection)
- Correlating failed logins with successful logins across time (credential stuffing)
- Identifying anomalous host pairs where behavior metrics diverge from expected correlation

### Splunk SPL Examples

**Pearson Correlation: Connection Count vs Bytes (Beaconing)**
```spl
index=network
| bucket _time span=1h
| stats count as conn_count, sum(bytes) as total_bytes by _time, src_ip
| eventstats avg(conn_count) as mean_x, avg(total_bytes) as mean_y,
             stdev(conn_count) as std_x, stdev(total_bytes) as std_y by src_ip
| eval dev_x = conn_count - mean_x
| eval dev_y = total_bytes - mean_y
| eval cross_prod = dev_x * dev_y
| eval sq_x = dev_x * dev_x
| eval sq_y = dev_y * dev_y
| stats sum(cross_prod) as sum_xy, sum(sq_x) as sum_x2, sum(sq_y) as sum_y2 by src_ip
| eval pearson_r = sum_xy / sqrt(sum_x2 * sum_y2)
| where abs(pearson_r) > 0.95
| sort - pearson_r
| table src_ip, pearson_r
```

---

## 2. Spearman Rank Correlation

### What It Analyzes
Non-parametric correlation based on ranks rather than raw values. Measures monotonic relationships (not just linear). More robust than Pearson for security data with non-normal distributions.

### Formula
```
rs = 1 - (6 × Σd²i) / (n(n²-1))

where di = rank(xi) - rank(yi)

For tied ranks, use Pearson formula applied to ranks.
```

### Outputs
- Spearman ρ (rho) ∈ [-1, 1]
- P-value
- Rank comparison table

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input X | Ordinal or continuous | Any rankable security metric |
| Input Y | Ordinal or continuous | Second rankable metric |
| Output | Float [-1, 1] | Spearman ρ coefficient |

### Assumptions
- Variables are at least ordinal
- Monotonic (but not necessarily linear) relationship
- No assumption of normality

### Limitations
- Less powerful than Pearson when normality holds
- Sensitive to a high proportion of tied ranks
- Still assumes monotonic relationship — misses non-monotonic patterns

### Cybersecurity Use Case
**Lateral Movement Progression Analysis**

During lateral movement, attackers typically visit hosts in order of increasing privilege or proximity to the crown jewel. Spearman correlation between visit_sequence and host_privilege_tier reveals whether an actor is systematically escalating — a monotonic pattern that Pearson would miss if the escalation is non-linear.

### Splunk SPL Examples

**Spearman on Privilege Escalation Sequence**
```spl
index=auth action=success
| sort _time
| streamstats count as visit_seq by src_user
| lookup host_privilege_tier.csv hostname OUTPUT tier
| stats list(visit_seq) as seq_list, list(tier) as tier_list by src_user
| eval n = mvcount(seq_list)
| eval rank_diff_sq = mvmap(seq_list, (seq_list - tier_list) * (seq_list - tier_list))
| eval sum_d2 = sum(rank_diff_sq)
| eval spearman = 1 - (6 * sum_d2) / (n * (n*n - 1))
| where spearman > 0.7 AND n > 5
| sort - spearman
```

---

## 3. Kendall's Tau

### What It Analyzes
Non-parametric rank correlation measuring concordant vs. discordant pairs. More robust than Spearman with small samples or many tied ranks. Tau ∈ [-1, 1].

### Formula
```
τ = (P - Q) / √[(P + Q + T)(P + Q + U)]

where:
  P = number of concordant pairs
  Q = number of discordant pairs
  T = pairs tied on X only
  U = pairs tied on Y only

Simplified (no ties): τ = (P - Q) / (n(n-1)/2)
```

### Outputs
- Kendall τ ∈ [-1, 1]
- P-value
- Count of concordant/discordant pairs

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Ordinal/continuous pairs | Two ranked security metrics |
| Output | Float [-1, 1] | Kendall tau |
| P-value | Float | Significance of association |

### Assumptions
- Variables are at least ordinal
- No assumption of normality or linearity
- Appropriate for small samples (n < 30)

### Limitations
- Computationally O(n²) — slow for large datasets
- τ values typically smaller in magnitude than Pearson r (different scale)
- Interpretation less intuitive than Pearson

### Cybersecurity Use Case
**Small-Sample Threat Actor Behavior Consistency**

With small CTI datasets (e.g., 8 observed intrusions by a threat actor), Kendall's tau validates whether attack timing correlates with target industry tier across the limited sample set.

### Splunk SPL Example

```spl
index=threat_intel
| stats count as incidents by industry_tier, attack_hour
| sort industry_tier
| streamstats count as rank_x by industry_tier
| sort attack_hour
| streamstats count as rank_y by attack_hour
| eval concordant = if(rank_x > rank_y, 1, 0)
| stats sum(concordant) as P, count as total
| eval Q = total - P
| eval tau = (P - Q) / (total * (total - 1) / 2)
| table tau, P, Q
```

---

## 4. Chi-Square Test of Independence

### What It Analyzes
Tests whether two categorical variables are independent. Measures whether the observed frequency distribution differs significantly from what would be expected if the variables were unrelated.

### Formula
```
χ² = Σ (Oij - Eij)² / Eij

where:
  Oij = observed frequency in cell (i,j)
  Eij = expected frequency = (row total × column total) / grand total

df = (rows - 1)(columns - 1)

Reject H0 (independence) if χ² > critical value
```

### Outputs
- Chi-square statistic
- P-value
- Degrees of freedom
- Contingency table with observed and expected frequencies
- Cramér's V (effect size)

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Two categorical variables | e.g., user_group × auth_outcome |
| Output | Float | Chi-square statistic |
| P-value | Float | < 0.05 indicates association |
| Effect Size | Float | Cramér's V ∈ [0, 1] |

### Assumptions
- Random sampling
- Expected frequency ≥ 5 in at least 80% of cells
- Observations are independent
- Variables are categorical (nominal or ordinal)

### Limitations
- No directionality (only tests association, not which way)
- Sensitive to sample size — large N can flag trivial associations as significant
- Requires sufficient expected frequencies — fails with sparse contingency tables
- Effect size (Cramér's V) needed alongside p-value for practical significance

### Cybersecurity Use Case
**Detecting Targeted Phishing Campaigns by Department**

Chi-square tests whether phishing click rates are independent of department. If IT receives 2% click rate and Finance receives 38%, chi-square will flag this as a non-random pattern — indicating either targeted spear-phishing or a department-specific control gap.

Also useful for:
- Testing association between time-of-day and failed auth (targeted attacks vs. opportunistic)
- Validating whether malware families associate with specific victim industries
- Detecting whether data access patterns correlate with user privilege tier

### Splunk SPL Examples

**Chi-Square: Phishing Click Rate by Department**
```spl
index=email_security action IN (clicked, no_click)
| stats count as observed by dept, action
| eventstats sum(observed) as row_total by dept
| eventstats sum(observed) as col_total by action
| eventstats sum(observed) as grand_total
| eval expected = (row_total * col_total) / grand_total
| eval chi_component = (observed - expected) * (observed - expected) / expected
| stats sum(chi_component) as chi_square, count as cells
| eval df = 1
| eval critical_value = 3.841
| eval significant = if(chi_square > critical_value, "YES - Association Detected", "NO")
| table chi_square, df, significant
```

**Chi-Square: Auth Failure Association with Time Bucket**
```spl
index=auth action=failure
| eval time_bucket = case(
    (tonumber(strftime(_time,"%H")) >= 0 AND tonumber(strftime(_time,"%H")) < 6), "overnight",
    (tonumber(strftime(_time,"%H")) >= 6 AND tonumber(strftime(_time,"%H")) < 18), "business_hours",
    true(), "evening")
| stats count as observed by src_ip_class, time_bucket
| eventstats sum(observed) as row_total by src_ip_class
| eventstats sum(observed) as col_total by time_bucket
| eventstats sum(observed) as grand_total
| eval expected = (row_total * col_total) / grand_total
| eval chi_component = pow(observed - expected, 2) / expected
| stats sum(chi_component) as chi_sq
| eval significant = if(chi_sq > 9.488, "SIGNIFICANT (df=4, p<0.05)", "not significant")
```

---

## 5. Point-Biserial Correlation

### What It Analyzes
Measures the relationship between a binary variable (0/1) and a continuous variable. Mathematically equivalent to Pearson r when one variable is dichotomous.

### Formula
```
rpb = (M1 - M0) / sn × √(n1 × n0 / n²)

where:
  M1 = mean of continuous variable for group 1
  M0 = mean of continuous variable for group 0
  sn = standard deviation of continuous variable
  n1, n0 = sample sizes for each group
  n = total sample size
```

### Outputs
- rpb ∈ [-1, 1]
- P-value (same as independent samples t-test)
- Effect size interpretation

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input X | Binary (0/1) | Group membership (e.g., compromised vs. clean) |
| Input Y | Continuous | Metric value (e.g., session duration) |
| Output | Float [-1, 1] | Point-biserial correlation |

### Assumptions
- Binary variable is dichotomous
- Continuous variable is approximately normally distributed within each group
- Independence of observations

### Limitations
- Only meaningful when the binary split is theoretically meaningful
- Sensitive to unequal group sizes
- Does not capture nonlinear relationships

### Cybersecurity Use Case
**Identifying Metrics that Discriminate Compromised vs. Clean Hosts**

During incident response, point-biserial correlation quantifies how strongly each observable metric (bytes_out, unique_dest_count, failed_auth_count) correlates with confirmed compromise status. This prioritizes which indicators are most predictive for future detections.

### Splunk SPL Example

```spl
index=endpoint
| lookup compromised_hosts.csv hostname OUTPUT is_compromised
| eval compromised = if(is_compromised="yes", 1, 0)
| stats avg(bytes_out) as M1 by compromised
| appendcols [search index=endpoint | stats stdev(bytes_out) as std, count as n]
| eval rpb = (M1_1 - M1_0) / std * sqrt((n1 * n0) / (n * n))
| table rpb
```

---

## Summary: Bivariate Test Selection Guide

| Scenario | Test | Reason |
|----------|------|--------|
| Two continuous metrics, normal data | Pearson | Most powerful for linear relationships |
| Non-normal or ordinal metrics | Spearman | Rank-based, robust |
| Small sample, many ties | Kendall's Tau | Best for n < 30 |
| Two categorical variables | Chi-Square | Tests independence |
| Binary group vs. continuous metric | Point-Biserial | IOC discrimination |
| Validating threat actor behavioral patterns | Kendall's Tau | Handles small CTI datasets |
