# Hypothesis Tests & Statistical Inference for Threat Hunting

Hypothesis tests determine whether observed differences or associations are statistically significant or likely due to chance. In security operations, they validate whether a change in behavior (before/after a control, between groups) is real or noise — preventing both false escalations and missed detections.

---

## Normality Prerequisites

Before selecting a parametric test, validate the normality assumption.

### Shapiro-Wilk Test

**What It Analyzes**: Tests whether a sample comes from a normally distributed population.

**Formula**:
```
W = (Σᵢ aᵢ x₍ᵢ₎)² / Σᵢ (xᵢ - x̄)²

where:
  x₍ᵢ₎ = i-th order statistic (sorted values)
  aᵢ  = constants derived from normal distribution order statistics

H₀: data is normally distributed
Reject H₀ if p < 0.05 (data is NOT normal → use non-parametric tests)
```

**Output**: W statistic ∈ (0,1], p-value. W close to 1 = data is approximately normal.

**Cybersecurity Use Case**: Before running a t-test on connection_count differences between infected and clean hosts, Shapiro-Wilk confirms whether the parametric test is valid. Security data is frequently non-normal (heavy tails, zero-inflation) — Shapiro-Wilk guides the analyst toward Mann-Whitney U when normality fails.

**Limitation**: Highly sensitive with large n (n > 5000) — even trivial deviations from normality produce p < 0.05. For large samples, supplement with Q-Q plot inspection.

**Splunk SPL**:
```spl
index=network
| stats count as conn_count by src_ip
| eventstats avg(conn_count) as mu, stdev(conn_count) as sigma
| eval z = (conn_count - mu) / sigma
| eval expected_normal = if(z > 0, 0.5 + 0.5 * erf(z / sqrt(2)), 0.5 - 0.5 * erf(abs(z) / sqrt(2)))
| sort conn_count
| streamstats count as rank
| eventstats count as n
| eval theoretical = rank / (n + 1)
| eval qq_deviation = abs(expected_normal - theoretical)
| stats max(qq_deviation) as max_dev, avg(qq_deviation) as avg_dev
| eval normality_verdict = if(max_dev < 0.1, "APPROXIMATELY_NORMAL", "NON_NORMAL - USE_NONPARAMETRIC")
```

---

## Parametric Tests (assume normality)

### 1. One-Sample T-Test

**What It Analyzes**: Whether a sample mean differs significantly from a known or hypothesized population mean.

**Formula**:
```
t = (x̄ - μ₀) / (s / √n)

df = n - 1
Two-tailed: reject H₀ if |t| > t_critical(α/2, n-1)

95% CI for mean: x̄ ± t_critical × (s / √n)
```

**Outputs**: t-statistic, p-value, 95% CI for sample mean, Cohen's d (effect size).

**Input/Output Specification**:
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Numeric sample | Sample observations |
| μ₀ | Float | Hypothesized baseline mean |
| Output | Float | t-statistic |
| P-value | Float | Probability under H₀ |
| Decision | Boolean | True if |t| > critical value |

**Assumptions**: Data approximately normal; observations independent; n ≥ 30 or known to be normal.

**Limitations**: Sensitive to outliers; assumes normality (use Wilcoxon signed-rank for non-normal data); two-tailed test halves effective α.

**Cybersecurity Use Case**: Testing whether average session duration during a suspected incident window (x̄ = 847s) differs from the established baseline (μ₀ = 420s). If p < 0.05, the difference is statistically significant — supporting the hypothesis of anomalous activity.

**Splunk SPL**:
```spl
index=network src_ip="10.0.5.22"
| bucket _time span=1h
| stats avg(duration) as avg_dur, count as n, stdev(duration) as s
| eval mu_0 = 420
| eval t_stat = (avg_dur - mu_0) / (s / sqrt(n))
| eval t_critical = 1.96
| eval significant = if(abs(t_stat) > t_critical, "SIGNIFICANT", "not significant")
| eval effect_size_d = abs(avg_dur - mu_0) / s
| table avg_dur, n, t_stat, t_critical, significant, effect_size_d
```

---

### 2. Two-Sample T-Test (Independent Samples)

**What It Analyzes**: Whether two independent groups have the same population mean. Compares a metric between two distinct groups.

**Formula**:
```
Pooled variance (equal variance assumed):
sp² = [(n₁-1)s₁² + (n₂-1)s₂²] / (n₁+n₂-2)
t = (x̄₁ - x̄₂) / (sp × √(1/n₁ + 1/n₂))
df = n₁ + n₂ - 2

Welch's t-test (unequal variance — preferred):
t = (x̄₁ - x̄₂) / √(s₁²/n₁ + s₂²/n₂)
df = Welch-Satterthwaite approximation
```

**Cybersecurity Use Case**: Comparing data transfer volume between confirmed-compromised hosts and clean hosts. If the mean difference is significant (p < 0.05), the metric is a valid discriminator for detection rules.

**Splunk SPL**:
```spl
index=endpoint
| lookup compromised_hosts.csv hostname OUTPUT status
| stats avg(bytes_out) as mean_bytes, stdev(bytes_out) as std_bytes, count as n by status
| eval se = std_bytes / sqrt(n)
| appendcols [search index=endpoint | lookup compromised_hosts.csv hostname OUTPUT status
              | stats avg(bytes_out) as mean_bytes_clean by status where status=clean]
| eval t_stat = (mean_bytes_compromised - mean_bytes_clean) /
                sqrt(pow(std_bytes_compromised,2)/n_comp + pow(std_bytes_clean,2)/n_clean)
| eval significant = if(abs(t_stat) > 1.96, "YES", "NO")
| table status, mean_bytes, t_stat, significant
```

---

### 3. Paired T-Test

**What It Analyzes**: Whether observations differ before and after a paired intervention. Each "before" observation is matched to an "after" observation for the same entity.

**Formula**:
```
d_i = x_after_i - x_before_i
t = d̄ / (s_d / √n)
df = n - 1

where d̄ = mean of differences, s_d = std dev of differences
```

**Cybersecurity Use Case**: Measuring whether deploying a new detection rule significantly changed alert volume per analyst. Each analyst is paired before/after — controls for individual variation in workload.

**Splunk SPL**:
```spl
index=analyst_metrics
| eval period = if(_time < strptime("2024-06-01","%Y-%m-%d"), "before", "after")
| stats avg(alerts_worked) as avg_alerts by analyst, period
| xyseries analyst period avg_alerts
| eval diff = after - before
| eventstats avg(diff) as mean_diff, stdev(diff) as std_diff, count as n
| eval t_stat = mean_diff / (std_diff / sqrt(n))
| eval significant = if(abs(t_stat) > 2.306, "YES (p<0.05, df=8)", "NO")
| table analyst, before, after, diff, t_stat, significant
```

---

### 4. One-Way ANOVA

**What It Analyzes**: Whether three or more independent groups have the same population mean. The F-test partitions total variance into between-group and within-group components.

**Formula**:
```
SS_between = Σnᵢ(x̄ᵢ - x̄)²
SS_within  = Σᵢ Σⱼ (xᵢⱼ - x̄ᵢ)²

MS_between = SS_between / (k-1)
MS_within  = SS_within / (N-k)

F = MS_between / MS_within
df₁ = k-1,  df₂ = N-k

Reject H₀ (all means equal) if F > F_critical(α, k-1, N-k)
```

**Outputs**: F-statistic, p-value, ANOVA table (SS, df, MS per source), η² (effect size).

**Assumptions**: Normality within each group; homogeneity of variance (test with Levene); independence.

**Cybersecurity Use Case**: Testing whether mean incident resolution time differs across four severity levels (Low, Medium, High, Critical). Significant F-test confirms severity meaningfully predicts MTTR — validating the severity taxonomy.

**Splunk SPL**:
```spl
index=incidents status=resolved
| stats avg(resolution_hr) as mean_r, count as n, stdev(resolution_hr) as std_r by severity
| eventstats avg(resolution_hr) as grand_mean
| eval ss_between = n * pow(mean_r - grand_mean, 2)
| stats sum(ss_between) as SS_between, sum(eval((n-1)*pow(std_r,2))) as SS_within,
        sum(n) as N, count as k
| eval df_between = k - 1
| eval df_within = N - k
| eval MS_between = SS_between / df_between
| eval MS_within = SS_within / df_within
| eval F = MS_between / MS_within
| eval F_critical = 2.84
| eval significant = if(F > F_critical, "YES - means differ by severity", "NO")
| table F, F_critical, significant
```

---

## Variance Equality Check

### Levene's Test

**What It Analyzes**: Tests equality of variance across groups. A prerequisite check for ANOVA and the two-sample t-test to determine whether to use pooled or Welch's variant.

**Formula**:
```
Robust Levene (using medians — Brown-Forsythe variant):
Zij = |Xij - median(Xi)|

F = [(N-k) Σnᵢ(Z̄ᵢ - Z̄)²] / [(k-1) ΣΣ(Zij - Z̄ᵢ)²]

H₀: σ₁² = σ₂² = ... = σₖ²
Reject if F > F_critical → use Welch correction
```

**Cybersecurity Use Case**: Before comparing connection counts between endpoint groups (workstations vs. servers), Levene's test reveals whether variance is equal. Servers inherently have higher variance — Levene catches this, directing the analyst to Welch's t-test which doesn't assume equal variance.

**Splunk SPL**:
```spl
index=network
| stats count as conn_count by src_ip, host_type
| eventstats median(conn_count) as med by host_type
| eval zij = abs(conn_count - med)
| stats avg(zij) as mean_zij, count as n, stdev(zij) as std_zij by host_type
| eventstats avg(zij) as grand_mean_z
| eval ss_between = n * pow(mean_zij - grand_mean_z, 2)
| stats sum(ss_between) as SS_b, sum(eval((n-1)*pow(std_zij,2))) as SS_w,
        sum(n) as N, count as k
| eval F = (SS_b / (k-1)) / (SS_w / (N-k))
| eval equal_variance = if(F < 4.0, "YES - use pooled t-test", "NO - use Welch t-test")
| table F, equal_variance
```

---

## Non-Parametric Tests (no normality assumption)

### 5. Mann-Whitney U Test (Wilcoxon Rank-Sum)

**What It Analyzes**: Non-parametric alternative to the two-sample t-test. Tests whether one group tends to have higher values than another based on ranks. Robust to skewed distributions and outliers.

**Formula**:
```
Combine and rank all N = n₁ + n₂ observations.

U₁ = n₁n₂ + n₁(n₁+1)/2 - R₁
U₂ = n₁n₂ + n₂(n₂+1)/2 - R₂
U = min(U₁, U₂)

For large samples (n > 20):
z = (U - n₁n₂/2) / √(n₁n₂(n₁+n₂+1)/12)

Effect size: r = z / √N
```

**Cybersecurity Use Case**: Comparing DNS query counts between DGA-infected and clean hosts. DNS data is heavily right-skewed (most hosts make few queries; some make thousands). Mann-Whitney ranks the observations and tests whether the DGA group consistently ranks higher — without assuming normal distribution.

**Splunk SPL**:
```spl
index=dns
| stats count as dns_count by src_ip
| lookup infected_hosts.csv src_ip OUTPUT infected
| eval group = if(infected="yes", "infected", "clean")
| sort dns_count
| streamstats count as rank
| stats sum(eval(if(group="infected", rank, 0))) as R1,
        count(eval(if(group="infected", 1, null()))) as n1,
        count(eval(if(group="clean", 1, null()))) as n2
| eval U1 = n1*n2 + n1*(n1+1)/2 - R1
| eval U2 = n1*n2 - U1
| eval U = min(U1, U2)
| eval z = (U - n1*n2/2) / sqrt(n1*n2*(n1+n2+1)/12)
| eval p_approx = if(abs(z) > 1.96, "p<0.05 SIGNIFICANT", "not significant")
| eval effect_r = abs(z) / sqrt(n1+n2)
| table U, z, p_approx, effect_r
```

---

### 6. Wilcoxon Signed-Rank Test

**What It Analyzes**: Non-parametric paired test. Ranks the absolute differences between paired observations and tests whether positive and negative differences are balanced.

**Formula**:
```
1. Compute d_i = x_after_i - x_before_i
2. Rank |d_i|, excluding ties where d_i = 0
3. T+ = sum of ranks for positive d_i
   T- = sum of ranks for negative d_i
4. T = min(T+, T-)
5. Reject H₀ if T ≤ critical value (table lookup)
```

**Cybersecurity Use Case**: Testing whether a new WAF rule significantly reduced SQL injection attempts per web server. Each server is paired before/after. Non-parametric because injection counts are count data (non-normal, zero-heavy).

**Splunk SPL**:
```spl
index=waf
| eval period = if(_time < strptime("2024-06-01","%Y-%m-%d"), "before", "after")
| stats sum(sqli_events) as count by server, period
| xyseries server period count
| eval diff = after - before
| where diff != 0
| eval abs_diff = abs(diff)
| sort abs_diff
| streamstats count as rank
| eval signed_rank = if(diff > 0, rank, -rank)
| stats sum(eval(if(signed_rank > 0, signed_rank, 0))) as T_plus,
        sum(eval(if(signed_rank < 0, abs(signed_rank), 0))) as T_minus
| eval T = min(T_plus, T_minus)
| eval T_critical = 8
| eval significant = if(T <= T_critical, "YES - WAF rule effective", "NO")
| table T, T_critical, significant
```

---

### 7. Kruskal-Wallis Test

**What It Analyzes**: Non-parametric alternative to one-way ANOVA. Tests whether three or more independent groups come from the same distribution, based on ranks.

**Formula**:
```
H = [12 / (N(N+1))] × Σᵢ [Rᵢ²/nᵢ] - 3(N+1)

where:
  N = total observations
  Rᵢ = sum of ranks in group i
  nᵢ = sample size of group i

df = k - 1
Reject H₀ if H > χ²_critical(α, k-1)
```

**Cybersecurity Use Case**: Comparing network anomaly scores across five data centers without assuming scores are normally distributed within each location. Kruskal-Wallis reveals whether any data center consistently produces higher anomaly scores — indicating either localized threats or misconfigured monitoring.

**Splunk SPL**:
```spl
index=network
| stats avg(anomaly_score) as score by src_ip, datacenter
| sort score
| streamstats count as rank
| stats sum(rank) as R, count as n by datacenter
| eventstats sum(n) as N
| eval H_term = pow(R, 2) / n
| stats sum(H_term) as sum_term, first(N) as N, count as k
| eval H = (12 / (N * (N+1))) * sum_term - 3*(N+1)
| eval chi2_critical_df4 = 9.488
| eval significant = if(H > chi2_critical_df4, "YES - datacenters differ", "NO")
| table H, chi2_critical_df4, significant
```

---

### 8. Fisher's Exact Test

**What It Analyzes**: Association between two binary variables in a 2×2 contingency table. Produces an exact p-value using the hypergeometric distribution — valid for any sample size, especially small samples where chi-square is unreliable.

**Formula**:
```
For 2×2 table with cell counts a, b, c, d:
        | Event+ | Event- | Total
Group A |   a    |   b    | a+b
Group B |   c    |   d    | c+d
Total   |  a+c   |  b+d   |  N

P = C(a+b, a) × C(c+d, c) / C(N, a+c)

p-value = sum of P for all tables as extreme or more extreme than observed
```

**Cybersecurity Use Case**: With only 15 endpoint agents tested: does patching status associate with compromise outcome? Chi-square requires expected cell counts ≥ 5 — with 15 total observations this fails. Fisher's exact test handles the small-sample scenario correctly.

**Splunk SPL**:
```spl
index=endpoint_inventory
| stats count by patch_status, compromised
| xyseries patch_status compromised count
| eval a = 'yes'_patched, b = 'no'_patched
| eval c = 'yes'_unpatched, d = 'no'_unpatched
| eval N = a + b + c + d
| eval log_p = lgamma(a+b+1) + lgamma(c+d+1) + lgamma(a+c+1) + lgamma(b+d+1)
             - lgamma(N+1) - lgamma(a+1) - lgamma(b+1) - lgamma(c+1) - lgamma(d+1)
| eval p_exact = exp(log_p)
| eval or = (a * d) / (b * c)
| eval significant = if(p_exact < 0.05, "YES", "NO")
| table a, b, c, d, p_exact, or, significant
```

---

### 9. Kolmogorov-Smirnov (K-S) Test

**What It Analyzes**: Tests whether a sample follows a specified reference distribution, or whether two samples come from the same distribution. Sensitive to differences anywhere in the distribution (not just the mean).

**Formula**:
```
One-sample K-S (vs. reference distribution F₀):
D = max_x |Fn(x) - F₀(x)|

Two-sample K-S (comparing two empirical distributions):
D = max_x |F₁(x) - F₂(x)|

Reject H₀ if D > D_critical(α, n)
Critical values: D_critical ≈ 1.36 / √n for α=0.05
```

**Cybersecurity Use Case**: Testing whether packet inter-arrival times follow a uniform distribution (expected for random traffic). Beaconing traffic shows a distribution with a sharp spike at the beacon interval — the K-S test detects this departure from uniformity even when the spike is subtle.

Also used for: validating that a security model's predicted probabilities match the empirical distribution of outcomes (calibration check).

**Splunk SPL**:
```spl
index=network src_ip="10.0.1.55"
| sort _time
| streamstats current=false window=1 last(_time) as prev_time
| eval interval = _time - prev_time
| where interval > 0
| sort interval
| streamstats count as rank
| eventstats count as n
| eval empirical_cdf = rank / n
| eval min_interval = 0
| eval max_interval = 3600
| eval uniform_cdf = (interval - min_interval) / (max_interval - min_interval)
| eval ks_component = abs(empirical_cdf - uniform_cdf)
| stats max(ks_component) as D, first(n) as n
| eval D_critical = 1.36 / sqrt(n)
| eval result = if(D > D_critical, "NON-UNIFORM - possible beacon", "uniform distribution")
| table D, D_critical, result
```

---

## Multiple Comparisons Control

### 10. Bonferroni Correction

**What It Analyzes**: Controls the family-wise error rate (FWER) when conducting multiple simultaneous hypothesis tests. Without correction, m tests at α=0.05 gives 1-(0.95)^m probability of at least one false positive.

**Formula**:
```
Bonferroni: α_adjusted = α / m

Reject individual test H₀ if p_i < α / m

Example: 20 tests, α=0.05 → α_adjusted = 0.0025

Holm-Bonferroni (more powerful):
Sort p-values: p₁ ≤ p₂ ≤ ... ≤ m
Reject H₀_i if pᵢ < α / (m - i + 1)

Benjamini-Hochberg FDR (less conservative):
Reject H₀_i if pᵢ ≤ (i/m) × q
  where q = desired false discovery rate (e.g., 0.05)
```

**Cybersecurity Use Case**: Running Z-score anomaly tests across 50 network metrics simultaneously. Without correction, you'd expect ~2-3 false positives by chance. Bonferroni correction tightens the threshold, ensuring that flagged metrics represent genuine anomalies — critical for preventing alert fatigue.

**Trade-off**: Bonferroni is conservative (misses real anomalies). For threat hunting where missing a true positive is costly, Benjamini-Hochberg FDR is preferred — it controls the proportion of false positives among all flagged items rather than the probability of any false positive.

**Splunk SPL**:
```spl
index=network
| stats avg(metric_value) as mu, stdev(metric_value) as sigma, count as n by metric_name
| eval z_score = (current_value - mu) / sigma
| eval raw_p = 2 * (1 - normal_cdf(abs(z_score)))
| eventstats count as num_tests
| eval bonferroni_alpha = 0.05 / num_tests
| eval significant_bonferroni = if(raw_p < bonferroni_alpha, "YES", "NO")
| sort raw_p
| streamstats count as rank
| eval fdr_threshold = (rank / num_tests) * 0.05
| eval significant_fdr = if(raw_p < fdr_threshold, "YES", "NO")
| table metric_name, z_score, raw_p, bonferroni_alpha, significant_bonferroni, significant_fdr
| where significant_bonferroni="YES" OR significant_fdr="YES"
```

---

## Summary: Hypothesis Test Selection Guide

| Scenario | Parametric | Non-Parametric | Notes |
|----------|-----------|----------------|-------|
| Sample vs. known mean | One-sample t-test | Wilcoxon signed-rank (1-sample) | Check normality first |
| Two groups, unpaired | Two-sample t-test | Mann-Whitney U | Levene's test for equal variance |
| Two groups, paired (before/after) | Paired t-test | Wilcoxon signed-rank | Same entity before/after |
| 3+ groups | One-way ANOVA | Kruskal-Wallis | Post-hoc if significant |
| 2×2 table, small n | Fisher's Exact | Fisher's Exact | N/A — exact method |
| Distribution comparison | K-S test | K-S test | Detects all distribution differences |
| Validate normality | — | Shapiro-Wilk | Required before parametric tests |
| Validate equal variance | Levene's test | Levene's (Brown-Forsythe) | Required before pooled t-test / ANOVA |
| Multiple tests at once | Bonferroni | Benjamini-Hochberg FDR | FDR preferred for hunt contexts |

### Decision Flow
```
Is data normally distributed? (Shapiro-Wilk)
├── YES → Are groups independent?
│         ├── 2 groups → Two-sample t-test (Levene first)
│         ├── 3+ groups → One-way ANOVA
│         └── Paired → Paired t-test
└── NO → Are groups independent?
          ├── 2 groups → Mann-Whitney U
          ├── 3+ groups → Kruskal-Wallis
          ├── Paired → Wilcoxon signed-rank
          └── Distribution comparison → K-S test

Running multiple tests? → Apply Bonferroni or FDR correction
```
