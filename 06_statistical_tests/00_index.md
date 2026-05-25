# Statistical Tests for Threat Hunting — Index

This directory covers all 46 statistical tests used in security operations and detection engineering. Each test includes: what it analyzes, outputs, I/O specification, formulas, cybersecurity use case, assumptions, limitations, and Splunk SPL examples.

## Test Categories

| File | Category | Tests Covered |
|------|----------|--------------|
| [01_univariate_tests.md](01_univariate_tests.md) | Univariate | Z-Score, MAD, IQR, Grubbs, Benford's Law |
| [02_bivariate_tests.md](02_bivariate_tests.md) | Bivariate | Pearson, Spearman, Kendall's Tau, Chi-Square, Point-Biserial |
| [03_multivariate_tests.md](03_multivariate_tests.md) | Multivariate | PCA, K-Means, Hierarchical, Isolation Forest, LOF, DBSCAN |
| [04_time_series_tests.md](04_time_series_tests.md) | Time Series | AR, MA, ARIMA, ETS, Change Point, Spectral Analysis, ACF/PACF |
| [05_regression_methods.md](05_regression_methods.md) | Regression | Simple Linear, Multiple Linear, Logistic Regression |
| [06_hypothesis_tests.md](06_hypothesis_tests.md) | Hypothesis Tests | t-tests (one-sample, two-sample, paired), ANOVA, Mann-Whitney U, Wilcoxon, Kruskal-Wallis, Fisher's Exact, K-S, Shapiro-Wilk, Levene, Bonferroni/FDR |
| [07_classification_metrics.md](07_classification_metrics.md) | Classification Metrics | Confusion Matrix, ROC/AUC, Precision-Recall/F1, MCC, Calibration/Brier Score |

## Complete Test List (46 Tests)

### Univariate (5)
1. Z-Score
2. Median Absolute Deviation (MAD)
3. Interquartile Range (IQR)
4. Grubbs' Test
5. Benford's Law

### Bivariate (5)
6. Pearson Correlation
7. Spearman Rank Correlation
8. Kendall's Tau
9. Chi-Square Test of Independence
10. Point-Biserial Correlation

### Multivariate (6)
11. Principal Component Analysis (PCA)
12. K-Means Clustering
13. Hierarchical Clustering
14. Isolation Forest
15. Local Outlier Factor (LOF)
16. DBSCAN

### Time Series (7)
17. Autoregressive (AR) Model
18. Moving Average (MA) Model
19. ARIMA / SARIMA
20. Exponential Smoothing (ETS / Holt-Winters)
21. Change Point Detection (CUSUM / PELT)
22. Spectral Analysis (FFT / Periodogram)
23. ACF / PACF

### Regression (3)
24. Simple Linear Regression
25. Multiple Linear Regression
26. Logistic Regression

### Hypothesis Tests (13)
27. Shapiro-Wilk (normality test)
28. Levene's Test (variance equality)
29. One-Sample T-Test
30. Two-Sample T-Test (Welch / pooled)
31. Paired T-Test
32. One-Way ANOVA
33. Mann-Whitney U (Wilcoxon Rank-Sum)
34. Wilcoxon Signed-Rank
35. Kruskal-Wallis
36. Fisher's Exact Test
37. Kolmogorov-Smirnov (K-S) Test
38. Bonferroni Correction
39. Benjamini-Hochberg FDR

### Classification Metrics (7)
40. Confusion Matrix (TP, FP, TN, FN + derived metrics)
41. ROC Curve & AUC
42. Precision-Recall Curve & F1/F2 Score
43. Matthews Correlation Coefficient (MCC)
44. Calibration Curve & Brier Score
45. Cramér's V (effect size for chi-square)
46. Average Precision (PR-AUC)

---

## Test Selection Guide

### By Detection Scenario

| Threat Scenario | Primary Test | Secondary Test |
|----------------|-------------|----------------|
| Beaconing | Spectral Analysis | Z-Score on interval variance |
| Data exfiltration | Z-Score + MAD | IQR on bytes |
| Brute force | Z-Score on fail_count | Change Point Detection |
| Lateral movement | Spearman (privilege progression) | Chi-Square (host × account) |
| Insider threat | K-Means (peer group) | Benford's Law (file access counts) |
| C2 clustering | DBSCAN | Isolation Forest |
| Behavioral drift | Change Point (CUSUM) | ARIMA residuals |
| Detection model evaluation | ROC/AUC, MCC | Precision-Recall, F2 |
| Multi-factor host scoring | Isolation Forest | LOF |
| Campaign attribution | K-S test (distribution compare) | Hierarchical clustering |

### Decision Flow: Parametric vs Non-Parametric

```
Is data normally distributed? (Shapiro-Wilk, Q-Q plot)
├── YES, n > 30 → Use parametric (t-tests, ANOVA, Pearson)
│   └── Equal variance? (Levene's) → Pooled t-test; else Welch
└── NO → Use non-parametric (Mann-Whitney, Kruskal-Wallis, Spearman)
         OR transform data (log, sqrt) and retest normality

Multiple simultaneous tests? → Apply Bonferroni or FDR
Rare event detection? → Use PR-AUC and F2 over Accuracy and ROC-AUC
```

---

## Integration Points

**DeTTECT → Test Selection**: Map ATT&CK technique gaps to required statistical test based on observable signature type (temporal → time series; behavioral → multivariate; rare event → robust univariate).

**Splunk MLTK Tests Available**:
- `fit IsolationForest` — anomaly detection
- `fit KMeans` — clustering
- `fit LocalOutlierFactor` — LOF
- `fit StandardScaler` — feature normalization
- `fit LogisticRegression` — classification
- `predict` — time series forecasting (ARIMA/ETS)
- `anomalydetection` — built-in anomaly scoring

**Python Libraries for Advanced Tests**:
```python
from scipy import stats             # All hypothesis tests
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans, DBSCAN
from sklearn.decomposition import PCA
from sklearn.neighbors import LocalOutlierFactor
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, average_precision_score, matthews_corrcoef
from statsmodels.tsa.arima.model import ARIMA
from statsmodels.tsa.holtwinters import ExponentialSmoothing
import ruptures                     # Change point detection (PELT)
```
