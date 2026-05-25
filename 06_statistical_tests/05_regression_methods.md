# Regression Methods for Threat Hunting & Detection Engineering

Regression models quantify predictive relationships between variables. In security operations, regression enables forecasting (predict tomorrow's alert volume), risk scoring (estimate breach probability), and feature importance analysis (which metrics best predict compromise).

---

## 1. Simple Linear Regression

### What It Analyzes
Models the predictive relationship between one predictor variable (X) and one continuous outcome (Y). Quantifies direction and magnitude of the linear relationship, and produces residuals for anomaly detection.

### Formula
```
Y = β₀ + β₁X + ε

Estimation (Ordinary Least Squares):
β₁ = Σ(xi - x̄)(yi - ȳ) / Σ(xi - x̄)²
β₀ = ȳ - β₁·x̄

Goodness-of-fit:
R² = 1 - SS_residual / SS_total
   = 1 - Σ(yi - ŷi)² / Σ(yi - ȳ)²

Anomaly score: residual = yi - ŷi
```

### Outputs
- Coefficients β₀ (intercept), β₁ (slope)
- R² (proportion of variance explained)
- Residuals per observation
- P-value for slope significance
- 95% confidence interval for slope

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input X | Continuous numeric | Predictor (e.g., failed_login_count) |
| Input Y | Continuous numeric | Outcome (e.g., bytes_exfiltrated) |
| Output | Float per record | Predicted Y value |
| Residual | Float per record | Actual - Predicted |
| R² | Float [0,1] | Proportion of variance explained |

### Assumptions
- Linear relationship between X and Y
- Residuals are normally distributed with mean=0
- Homoscedasticity (constant residual variance)
- Independence of observations
- No significant outliers in X (leverage points)

### Limitations
- Captures only linear relationships
- Sensitive to outliers — a single extreme point can dominate the regression line
- R² can be high even when model is badly specified (check residual plots)
- Extrapolation beyond training data range is unreliable

### Cybersecurity Use Case
**Forecasting Alert Volume from Queue Depth**

If processing queue depth linearly predicts alert generation latency, regression quantifies this relationship and enables capacity planning. Residuals flag time periods where the relationship breaks down — possibly indicating log ingestion failures or SIEM performance issues.

Also used for:
- Predicting data exfiltration volume from failed login count
- Forecasting incident duration from initial severity score
- Estimating detection lag from log source count

### Splunk SPL Example
```spl
index=_internal source=*metrics.log
| bucket _time span=1h
| stats avg(queue_depth) as q_depth, avg(alert_latency_sec) as latency by _time
| eventstats avg(q_depth) as mean_x, avg(latency) as mean_y
| eval dev_x = q_depth - mean_x
| eval dev_y = latency - mean_y
| eval cross = dev_x * dev_y
| eval sq_x = dev_x * dev_x
| stats sum(cross) as num, sum(sq_x) as denom, avg(q_depth) as mean_x, avg(latency) as mean_y
| eval beta1 = num / denom
| eval beta0 = mean_y - beta1 * mean_x
| eval r_sq = num * num / (denom * denom)
| table beta0, beta1, r_sq
```

---

## 2. Multiple Linear Regression

### What It Analyzes
Extends simple regression to multiple predictors, quantifying each predictor's independent contribution to the outcome while controlling for other variables. Essential for multi-factor security risk scoring.

### Formula
```
Y = β₀ + β₁X₁ + β₂X₂ + ... + βₙXₙ + ε

Matrix form: Y = Xβ + ε
OLS estimate: β̂ = (XᵀX)⁻¹XᵀY

Adjusted R²:
R²_adj = 1 - [(1-R²)(n-1)/(n-p-1)]
  where p = number of predictors

VIF (Variance Inflation Factor) for multicollinearity:
VIF_j = 1/(1-R²_j)
VIF > 10 → severe multicollinearity
```

### Outputs
- Coefficient for each predictor
- Adjusted R²
- F-statistic and p-value (overall model significance)
- T-statistics and p-values for each coefficient
- Residuals
- VIF values for multicollinearity check

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input X | n × p matrix | p predictors, n observations |
| Input Y | n × 1 vector | Continuous outcome |
| Output | Float per predictor | Regression coefficient |
| Prediction | Float per record | Fitted value |
| VIF | Float per predictor | Multicollinearity measure |

### Assumptions
- Linear relationships between each predictor and outcome
- No multicollinearity (correlated predictors → unstable coefficients)
- Homoscedasticity and normality of residuals
- Observations are independent

### Limitations
- Multicollinearity inflates standard errors — security metrics often correlate (bytes and connections)
- Model requires all predictors at prediction time
- Overfitting risk when p approaches n (use regularization: Ridge, Lasso)
- Does not handle categorical predictors without dummy encoding

### Cybersecurity Use Case
**Multi-Factor Incident Severity Prediction**

Build a regression model where Y = incident_resolution_time and predictors are: event_count, unique_ips, time_of_day, severity_score, team_availability. Each coefficient tells you how much each factor independently contributes to resolution time — enabling resource optimization and SLA forecasting.

Also used for:
- Predicting MTTD from: alert_type, analyst_experience, tool_coverage
- Forecasting daily alert volume from: day_of_week, recent_campaigns, patch_cycle_day
- Estimating risk score from multiple security metrics

### Splunk SPL Example (Feature Preparation)
```spl
index=incidents status=resolved
| stats
    avg(event_count) as events,
    avg(unique_ips) as ips,
    avg(severity) as sev,
    avg(resolution_time_hr) as mttr
  by incident_id
| eventstats
    avg(events) as mu_e, stdev(events) as std_e,
    avg(ips) as mu_i, stdev(ips) as std_i,
    avg(sev) as mu_s, stdev(sev) as std_s
| eval z_events = (events - mu_e) / std_e
| eval z_ips = (ips - mu_i) / std_i
| eval z_sev = (sev - mu_s) / std_s
| table incident_id, z_events, z_ips, z_sev, mttr
| outputlookup regression_features.csv
```
*Full OLS estimation requires Python/statsmodels or Splunk MLTK LinearRegression.*

---

## 3. Logistic Regression

### What It Analyzes
Models the probability of a binary outcome (breach/no-breach, malicious/benign, compromised/clean) as a function of predictor variables. Produces interpretable probability scores and log-odds coefficients.

### Formula
```
log(p/(1-p)) = β₀ + β₁X₁ + ... + βₙXₙ

Probability:
p = 1 / (1 + e^(-(β₀ + β₁X₁ + ... + βₙXₙ)))

Odds ratio for predictor j:
OR_j = e^(β_j)
  = multiplicative change in odds per 1-unit increase in X_j

Maximum Likelihood Estimation:
L = Π p_i^y_i × (1-p_i)^(1-y_i)
Log-likelihood: ℓ = Σ[y_i·log(p_i) + (1-y_i)·log(1-p_i)]
```

### Outputs
- Coefficients β (log-odds scale)
- Odds ratios e^β (interpretable scale)
- Predicted probability per observation
- Model performance: AUC-ROC, log-loss, accuracy
- Confidence intervals for coefficients
- P-values for each predictor

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input X | n × p matrix | Predictor features |
| Input Y | Binary (0/1) | Outcome (compromised, malicious, etc.) |
| Output | Float [0,1] per record | Predicted probability |
| Odds Ratio | Float | Effect size per predictor |
| Threshold | Float | Probability cutoff for classification |

### Assumptions
- Binary outcome variable
- Linear relationship between predictors and log-odds (log-odds linearity)
- No severe multicollinearity
- Large sample (n ≥ 10 × number of predictors per class)
- Observations independent

### Limitations
- Cannot handle perfect separation (predictor perfectly predicts outcome)
- Requires large samples for stable coefficient estimates
- Assumes log-odds linearity — fails for threshold-based relationships
- Sensitive to class imbalance (address with oversampling or class weights)

### Cybersecurity Use Case
**Host Compromise Probability Scoring**

Train logistic regression on confirmed compromise data with features: failed_auth_count_7d, unique_external_dest_7d, new_process_rare_score, off_hours_activity_ratio, lateral_movement_count. The model produces a probability score [0,1] for each host at each assessment window. Hosts above threshold (e.g., p > 0.7) are flagged for investigation.

**Odds Ratio Interpretation Example**:
- OR for failed_auth_count = 1.15 → each additional failure increases compromise odds by 15%
- OR for off_hours_activity = 2.8 → off-hours activity almost triples compromise odds

Also used for:
- Email classification: phishing vs. legitimate
- Network flow classification: malicious vs. benign
- User risk scoring for privileged access management

### Splunk SPL Example (MLTK)
```spl
index=endpoint
| lookup compromised_hosts.csv hostname OUTPUT label
| eval is_compromised = if(label="compromised", 1, 0)
| stats
    sum(failed_auth) as failed_auth_7d,
    dc(dest_ip) as unique_dests,
    sum(off_hours_events) as off_hours,
    dc(new_process) as new_procs
  by hostname, is_compromised
| fit LogisticRegression is_compromised from failed_auth_7d unique_dests off_hours new_procs
    into host_compromise_model
| apply host_compromise_model
| eval risk_score = round('probability(1)' * 100, 1)
| where risk_score > 70
| sort - risk_score
| table hostname, risk_score, failed_auth_7d, unique_dests, off_hours
```

---

## Summary: Regression Method Selection Guide

| Scenario | Method | Key Output |
|----------|--------|-----------|
| Single metric predicts another | Simple Linear | Slope coefficient, R², residuals |
| Multiple metrics predict continuous outcome | Multiple Linear | Coefficients per feature, Adjusted R² |
| Binary outcome probability scoring | Logistic | Probabilities [0,1], odds ratios |
| Risk scoring with interpretability needed | Logistic | Odds ratios explain each factor's contribution |
| Forecasting alert/event volume | Linear (AR or Multiple) | Predictions + residual anomaly flagging |
| Feature importance for detection | Logistic coefficient magnitude | Which indicators matter most |

### DeTTECT Integration Pattern
```
1. Identify detection gap (DeTTECT YAML: visibility_score < 3)
2. Select regression model matching threat scenario
3. Engineer features from available log sources
4. Train on confirmed incident data (or simulate)
5. Output risk scores to SIEM lookup table
6. Trigger alert when score exceeds threshold
7. Update model quarterly as threat landscape shifts
```
