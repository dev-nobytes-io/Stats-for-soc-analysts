# Time Series Statistical Tests for Threat Hunting

Time series methods analyze sequences of observations collected over time, detecting patterns, anomalies, and structural changes in temporal security telemetry. These are foundational for detecting beaconing, scheduled tasks, staged exfiltration, and behavioral drift.

---

## 1. Autoregressive (AR) Model

### What It Analyzes
Models the current value of a time series as a linear function of its own past values. Residuals (actual - predicted) that exceed normal variance indicate anomalous observations.

### Formula
```
AR(p): Xt = c + Σᵢ₌₁ᵖ φᵢ·X(t-i) + εt

where:
  p = order (number of lagged terms)
  φᵢ = autoregressive coefficients
  c = constant (drift)
  εt = white noise error (IID, mean=0)

Anomaly: |εt| > 2σε indicates unexpected deviation
```

### Outputs
- AR coefficients {φ₁, ..., φₚ}
- Residuals per time step
- Residual variance σ²
- One-step-ahead predictions
- Anomaly flag when residual exceeds threshold

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Ordered numeric series | Evenly spaced time series (counts, volumes) |
| p | Integer | Model order (use AIC/BIC to select) |
| Threshold | Float | Residual z-score for anomaly flag |
| Output | Float per step | One-step prediction |
| Anomaly | Boolean | True when residual exceeds threshold |

### Assumptions
- Stationary series (constant mean and variance over time)
- Serial autocorrelation in residuals should be minimal after fitting
- Linear relationship between current and past values
- Equal time intervals between observations

### Limitations
- Requires stationarity — detrend/difference before fitting
- Model order p selection impacts performance
- Purely linear model — misses nonlinear cyclical patterns
- Breaks down during regime changes (attacker changes behavior)

### Cybersecurity Use Case
**Beaconing Detection via Connection Count Modeling**

A compromised host's connection count to a C2 server follows a predictable AR(1) pattern (each interval's count is similar to the last). Once fitted, large residuals indicate session interruptions, C2 channel switches, or burst exfiltration embedded within beaconing traffic.

Also used for:
- Modeling expected login counts per hour to flag brute force spikes
- Predicting DNS query rates to detect DGA activation
- Flagging CPU usage spikes that deviate from AR-predicted baseline

### Splunk SPL Examples

**AR(1) Approximation on Login Volume**
```spl
index=auth
| bucket _time span=1h
| stats count as login_count by _time
| sort _time
| streamstats current=false window=1 avg(login_count) as prev_count
| eval predicted = prev_count
| eval residual = login_count - predicted
| eventstats avg(residual) as mean_resid, stdev(residual) as std_resid
| eval resid_z = (residual - mean_resid) / std_resid
| where abs(resid_z) > 2.5
| table _time, login_count, predicted, residual, resid_z
```

**AR-Based DNS Spike Detection**
```spl
index=dns
| bucket _time span=5m
| stats count as query_count by _time, src_ip
| sort _time
| streamstats current=false window=3 avg(query_count) as ar_pred by src_ip
| eval residual = query_count - ar_pred
| eventstats stdev(residual) as resid_std by src_ip
| eval anomaly_score = abs(residual) / resid_std
| where anomaly_score > 3 AND query_count > 50
| sort - anomaly_score
| table _time, src_ip, query_count, ar_pred, anomaly_score
```

---

## 2. Moving Average (MA) Model

### What It Analyzes
Models the current value as a function of past error terms (white noise residuals), not past values. Captures short-term shock effects that dissipate over time.

### Formula
```
MA(q): Xt = μ + εt + Σᵢ₌₁ᵍ θᵢ·ε(t-i)

where:
  q = order (number of lagged error terms)
  θᵢ = moving average coefficients
  εt = white noise error
  μ = process mean

Simple moving average (for smoothing):
SMA(t) = (1/w) × Σᵢ₌₀^(w-1) X(t-i)
```

### Outputs
- Smoothed series (SMA)
- MA model coefficients
- Residuals (for anomaly detection)
- Exponentially weighted moving average (EWMA) variant

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Ordered time series | Security metric (counts, bytes, rates) |
| Window w | Integer | Smoothing window size |
| Output | Float per step | Smoothed value |
| Deviation | Float | Actual vs. smoothed delta |

### Assumptions
- Short-memory process (shocks fade within q steps)
- Stationary series
- Error terms are IID white noise

### Limitations
- Pure MA cannot capture long-term autocorrelation (use AR or ARIMA)
- SMA has lag — reacts slowly to genuine trend changes
- Window size selection trades off responsiveness vs. stability

### Cybersecurity Use Case
**Real-Time Beaconing Detection with EWMA**

Exponentially weighted moving average (EWMA) smooths connection interval series while reacting quickly to deviations. When a beacon switches C2 endpoints (causing interval change), EWMA detects the shift within 2-3 intervals rather than waiting for a full window.

Also used for:
- Smoothed threshold alerting for event rates
- Detecting sudden volume changes in email traffic (spam campaigns)
- Monitoring SIEM ingest rate for log source failures

### Splunk SPL Examples

**EWMA-Based Alerting on Connection Rate**
```spl
index=network
| bucket _time span=5m
| stats count as conn_count by _time, src_ip
| sort _time
| streamstats current=true window=10 avg(conn_count) as sma_10 by src_ip
| eval ewma = if(isnull(ewma), conn_count, 0.3 * conn_count + 0.7 * prev_ewma)
| eval deviation = abs(conn_count - ewma)
| eventstats avg(deviation) as mean_dev, stdev(deviation) as std_dev by src_ip
| eval deviation_z = (deviation - mean_dev) / std_dev
| where deviation_z > 3
| table _time, src_ip, conn_count, ewma, deviation_z
```

**Moving Average Envelope for Alert Rate Monitoring**
```spl
index=_internal source=*scheduler.log
| bucket _time span=1h
| stats count as alert_count by _time
| sort _time
| streamstats window=168 avg(alert_count) as sma_7d,
              stdev(alert_count) as std_7d
| eval upper_band = sma_7d + 2 * std_7d
| eval lower_band = sma_7d - 2 * std_7d
| eval band_breach = if(alert_count > upper_band OR alert_count < lower_band, "ANOMALOUS", "normal")
| where band_breach = "ANOMALOUS"
| table _time, alert_count, sma_7d, upper_band, lower_band
```

---

## 3. ARIMA (AutoRegressive Integrated Moving Average)

### What It Analyzes
Combines AR (autoregression), I (differencing for stationarity), and MA (moving average errors) into a unified model for forecasting and anomaly detection on non-stationary time series.

### Formula
```
ARIMA(p,d,q):

Step 1 - Difference d times to achieve stationarity:
  W(t) = Δᵈ X(t) = (1-B)ᵈ X(t)

Step 2 - Fit ARMA(p,q) to W(t):
  W(t) = c + Σᵢ₌₁ᵖ φᵢ W(t-i) + εt + Σⱼ₌₁ᵍ θⱼ ε(t-j)

Seasonal extension: SARIMA(p,d,q)(P,D,Q)s
  Adds seasonal AR, differencing, MA terms at period s
```

### Outputs
- Fitted ARIMA model parameters
- In-sample fitted values
- Forecast with confidence intervals
- Residuals (anomaly scores)
- AIC/BIC for model selection

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Ordered time series | Security metric (evenly spaced) |
| (p,d,q) | Integer triple | Model order |
| Forecast horizon | Integer | Steps ahead to predict |
| Output | Float per step | Predicted value + CI |
| Anomaly | Boolean | Observation outside CI |

### Assumptions
- After differencing d times, series is stationary
- Residuals are white noise (check with Ljung-Box test)
- No structural breaks in the series during fitting period
- Sufficient history (≥ 2 × seasonal period)

### Limitations
- Requires stationarity after differencing
- Sensitive to outliers in training data
- Manual (p,d,q) selection requires ACF/PACF analysis
- Computationally intensive; does not scale to millions of series without parallelization

### Cybersecurity Use Case
**Predicting and Anomaly-Detecting Daily Authentication Volume**

Authentication volume has weekly seasonality (more on weekdays, less on weekends). SARIMA(1,1,1)(1,1,1)₇ models this, producing forecasts with tight confidence intervals. Observations outside the CI on business days indicate either a mass brute-force attack or an authentication service failure. On weekends, anomalies often signal unauthorized after-hours access.

### Splunk SPL Example (Forecast-Based Anomaly Detection)
```spl
index=auth
| timechart span=1d count as daily_logins
| predict daily_logins algorithm=LLP5 future_timespan=7 CI=95
| eval anomaly = if(daily_logins > upper95 OR daily_logins < lower95, 1, 0)
| where anomaly = 1
| table _time, daily_logins, predicted(daily_logins), upper95, lower95
```

---

## 4. Exponential Smoothing (ETS)

### What It Analyzes
State-space model that weights recent observations more heavily using an exponential decay factor. ETS models handle trend and seasonality through additive or multiplicative components.

### Formula
```
Simple (no trend, no seasonality):
  Level:  Lt = α·Xt + (1-α)·L(t-1)
  Forecast: F(t+h) = Lt

Double (with additive trend):
  Level:  Lt = α·Xt + (1-α)·(L(t-1) + T(t-1))
  Trend:  Tt = β·(Lt - L(t-1)) + (1-β)·T(t-1)

Triple / Holt-Winters (trend + seasonality):
  Level, Trend, and Seasonal components
  Additive or multiplicative seasonality
```

### Outputs
- Smoothed level series
- Trend component
- Seasonal component
- Forecasts with prediction intervals
- Residuals (anomaly scores when |residual| >> σ)

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Ordered time series | Security metric |
| α | Float (0,1) | Level smoothing parameter |
| β | Float (0,1) | Trend smoothing parameter |
| γ | Float (0,1) | Seasonal smoothing parameter |
| Output | Float | Forecast per step |

### Assumptions
- Time series has consistent trend/seasonality structure
- Parameters α, β, γ stable over the forecast horizon
- Additive vs. multiplicative component choice requires inspection

### Limitations
- Does not handle abrupt structural breaks well
- Multiplicative models require strictly positive values
- Single exponential smoothing has no trend/seasonality handling

### Cybersecurity Use Case
**Detecting Anomalous After-Hours Login Volume**

Holt-Winters triple exponential smoothing captures weekly and daily seasonality in authentication logs. When an attacker uses a compromised account to authenticate at 3AM on a Tuesday (overnight low-activity period), ETS forecasts near-zero activity and the observed spike generates a large residual — triggering an alert.

### Splunk SPL Example
```spl
index=auth
| timechart span=1h count as logins
| predict logins algorithm=LL future_timespan=24 holdback=168
| eval anomaly = if(logins > upper95 OR logins < lower95, "ANOMALY", "normal")
| eval severity = round(abs(logins - predicted(logins)) / stdev(logins) * 10, 1)
| where anomaly = "ANOMALY"
| table _time, logins, predicted(logins), severity
```

---

## 5. Change Point Detection

### What It Analyzes
Identifies time points where the statistical properties (mean, variance, trend) of a series shift significantly. In security, change points mark when adversarial behavior begins, escalates, or changes tactics.

### Formula
```
CUSUM (Cumulative Sum):
  S(t) = max(0, S(t-1) + (Xt - μ0 - k))
  Alert when S(t) > h

where:
  μ0 = baseline mean
  k = allowance (typically 0.5σ)
  h = decision threshold (typically 4-5σ)

PELT (Pruned Exact Linear Time):
  Minimizes: Σ[C(y(τ_{j-1}+1):τ_j)] + β·n_changepoints
  where C = cost function (e.g., negative log-likelihood)
  β = penalty for each changepoint
```

### Outputs
- Change point timestamps
- Pre/post change point statistics (mean, variance)
- CUSUM statistic series
- Confidence intervals for change point location

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Ordered time series | Any security metric |
| Method | Enum | CUSUM, PELT, Binary Segmentation |
| Penalty β | Float | Controls sensitivity (higher = fewer CPs) |
| Output | List[timestamp] | Change point timestamps |

### Assumptions
- Series is piecewise stationary (constant stats within segments)
- Sufficient data before and after each change point
- Change points are relatively rare

### Limitations
- Retrospective (offline) methods require complete data
- Online CUSUM can detect CPs in near-real-time but with lag
- False positives during natural seasonality transitions
- Penalty parameter selection requires domain knowledge

### Cybersecurity Use Case
**Detecting Attacker Dwell Time Onset**

After initial compromise, attackers often enter a reconnaissance phase characterized by a step-change in network traffic volume, unique host access count, or process diversity. Change point detection identifies the exact timestamp when this behavioral shift occurred — enabling precise dwell time estimation and forensic investigation scoping.

Also used for:
- Detecting when a DGA domain generation switches algorithm
- Identifying when a compromised account begins operating autonomously
- Flagging log volume changes indicating coverage gaps (log source failure or evasion)

### Splunk SPL Examples

**CUSUM for Detecting Sudden Volume Increase**
```spl
index=network src_ip="192.168.1.50"
| bucket _time span=15m
| stats sum(bytes_out) as bytes by _time
| eventstats avg(bytes) as mu, stdev(bytes) as sigma
| eval k = 0.5 * sigma
| eval h = 5 * sigma
| sort _time
| streamstats current=true window=100 values(bytes) as recent_bytes
| eval cusum = max(0, prev_cusum + (bytes - mu - k))
| where cusum > h
| table _time, bytes, cusum, mu, sigma
```

---

## 6. Spectral Analysis (Frequency Domain)

### What It Analyzes
Transforms a time series into the frequency domain using Fourier analysis to identify periodic patterns. In security, beaconing manifests as dominant frequency peaks in connection timing data.

### Formula
```
Discrete Fourier Transform (DFT):
X(k) = Σₙ₌₀^(N-1) x(n) · e^(-j2πkn/N)

Power Spectral Density:
PSD(k) = |X(k)|² / N

Dominant frequency: f* = argmax_k PSD(k)
Period: T* = 1/f* (in sampling units)

Lomb-Scargle periodogram for unevenly spaced data
```

### Outputs
- Power spectrum (PSD)
- Dominant frequency and period
- Spectral peaks above noise floor
- Confidence intervals for peak significance

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Time series (uniform spacing) | Connection intervals, event counts |
| Output | Frequency spectrum | Power per frequency bin |
| Dominant Period | Float | Seconds/minutes of beacon interval |
| Significance | Boolean | Peak above 95% confidence level |

### Assumptions
- Uniformly spaced time series (resample if needed)
- Series length N should be power of 2 for FFT efficiency
- Periodic signal present in noise

### Limitations
- Requires uniformly spaced data (interpolation introduces artifacts)
- Short series have low frequency resolution
- Spectral leakage without windowing (apply Hanning/Hamming window)
- Cannot directly handle multiple overlapping periodic signals well

### Cybersecurity Use Case
**Beacon Period Identification**

A C2 beacon with 300-second check-in interval creates a dominant frequency peak at f = 1/300 Hz in the DFT of connection interval data. Even with ±30 second jitter, the peak remains identifiable. Spectral analysis distinguishes human-driven browsing (broad, non-periodic spectrum) from automated beaconing (sharp spectral peak).

### Splunk SPL Example
```spl
index=network src_ip="10.0.1.42" dest_ip="198.51.100.7"
| sort _time
| streamstats current=false window=1 last(_time) as prev_time
| eval interval_sec = _time - prev_time
| where interval_sec > 0 AND interval_sec < 3600
| bin interval_sec span=10
| stats count as freq by interval_sec
| sort interval_sec
| eval dominant = if(freq = max(freq), "DOMINANT_PERIOD", "background")
| where dominant = "DOMINANT_PERIOD"
| eval period_label = interval_sec . " seconds (" . round(interval_sec/60, 1) . " minutes)"
| table interval_sec, freq, period_label
```

---

## 7. ACF/PACF Analysis

### What It Analyzes
- **ACF (Autocorrelation Function)**: Measures correlation between a series and its lagged values at each lag
- **PACF (Partial ACF)**: Measures correlation at lag k after removing the effect of shorter lags

Used to identify AR and MA model orders for ARIMA fitting, and to detect seasonality and periodic patterns.

### Formula
```
ACF at lag k:
ρ(k) = Cov(Xt, X(t-k)) / Var(Xt)
     = Σ(Xt - X̄)(X(t-k) - X̄) / Σ(Xt - X̄)²

PACF at lag k:
φ(k,k) from Yule-Walker equations or Durbin-Levinson algorithm

Significance bounds: ±1.96 / √N  (95% CI)
```

### Outputs
- Correlogram (ACF plot with lag on x-axis)
- PACF plot
- Significant lags (outside ±1.96/√N bounds)
- Suggested ARIMA order (p from PACF, q from ACF)

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | Ordered time series | Any stationary security metric |
| Max lag | Integer | Maximum lag to compute (typically 40–100) |
| Output | Float per lag | Autocorrelation coefficient |
| Significance | Boolean | True if outside ±1.96/√N |

### Assumptions
- Series is stationary
- Observations are approximately normally distributed

### Limitations
- Only valid for stationary series (difference first if needed)
- Large sample needed (n ≥ 50) for reliable ACF estimates
- ACF interpretation requires analyst expertise

### Cybersecurity Use Case
**Identifying Beacon Interval Structure**

ACF analysis of connection timing series reveals the lag at which autocorrelation is highest — corresponding to the beacon interval. A C2 beacon at 5-minute intervals shows a significant ACF spike at lag 5 (for 1-minute bins). This is faster and more interpretable than Fourier analysis for short time series.

Also used for:
- Identifying if a series is AR or MA dominant (for ARIMA order selection)
- Detecting daily/weekly seasonality in authentication logs
- Validating that residuals from a fitted model are truly white noise

### Splunk SPL Example
```spl
index=network src_ip="10.0.2.15"
| bucket _time span=1m
| stats count as conn_count by _time
| sort _time
| eval lag1 = lag(conn_count, 1)
| eval lag2 = lag(conn_count, 2)
| eval lag5 = lag(conn_count, 5)
| eval lag10 = lag(conn_count, 10)
| eventstats avg(conn_count) as mu, stdev(conn_count) as sigma
| eval acf_lag1 = (conn_count - mu) * (lag1 - mu) / (sigma * sigma)
| eval acf_lag5 = (conn_count - mu) * (lag5 - mu) / (sigma * sigma)
| stats avg(acf_lag1) as ACF_1, avg(acf_lag5) as ACF_5
| eval significant_threshold = 1.96 / sqrt(1440)
| eval lag1_significant = if(abs(ACF_1) > significant_threshold, "YES", "NO")
| eval lag5_significant = if(abs(ACF_5) > significant_threshold, "YES", "NO")
| table ACF_1, ACF_5, significant_threshold, lag1_significant, lag5_significant
```

---

## Summary: Time Series Method Selection Guide

| Scenario | Method | Why |
|----------|--------|-----|
| Short-term spike detection | AR(1) residuals | Simple, fast, catches deviations from yesterday |
| Real-time smoothed alerting | EWMA | Balances responsiveness and stability |
| Non-stationary seasonal data | ARIMA/SARIMA | Handles trend + weekly seasonality |
| After-hours activity detection | ETS (Holt-Winters) | Explicit seasonal component |
| Detecting onset of attack dwell | Change Point (CUSUM) | Identifies behavioral shift timestamp |
| Beacon interval identification | Spectral Analysis | Detects periodic signal in noise |
| ARIMA model order selection | ACF/PACF | Required preprocessing step |
| Combined pipeline | ETS forecast + CUSUM | Forecast-aware change point detection |
