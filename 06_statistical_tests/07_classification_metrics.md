# Classification & Prediction Performance Metrics

Classification metrics evaluate how well a detection model or rule distinguishes malicious from benign activity. Choosing the wrong metric leads to over-optimistic evaluation — a model with 99% accuracy on a dataset with 1% attack rate is useless if it predicts "benign" every time. These metrics expose that failure.

---

## The Confusion Matrix Foundation

All classification metrics derive from four fundamental counts:

```
                    Predicted Positive    Predicted Negative
Actual Positive  |  TP (True Positive)  | FN (False Negative)  | ← Attack present
Actual Negative  |  FP (False Positive) | TN (True Negative)   | ← No attack

TP = Correct attack detection
TN = Correct benign classification
FP = False alarm (alert on benign activity)
FN = Missed attack (detection failure)
```

**Security priorities**: Minimizing FN (missed attacks) is typically primary; minimizing FP (alert fatigue) is secondary. These goals are in tension.

---

## 1. Confusion Matrix & Derived Metrics

### What It Analyzes
Provides a complete picture of all four classification outcomes, enabling calculation of accuracy, sensitivity, specificity, precision, recall, and NPV.

### Formulas
```
Accuracy         = (TP + TN) / (TP + TN + FP + FN)
Sensitivity/Recall = TP / (TP + FN)           ← detect rate for attacks
Specificity      = TN / (TN + FP)             ← detect rate for benign
Precision/PPV    = TP / (TP + FP)             ← confidence in alert
NPV              = TN / (TN + FN)             ← confidence in "clean" call
Fall-out (FPR)   = FP / (FP + TN) = 1 - Specificity
```

### Outputs
- 2×2 confusion matrix
- All derived rate metrics
- Class-specific error rates

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Predicted Labels | Binary array | Model or rule output (0=clean, 1=alert) |
| Actual Labels | Binary array | Ground truth (confirmed attack/clean) |
| Output | 4 integers | TP, TN, FP, FN |
| Derived | Float per metric | Accuracy, sensitivity, etc. |

### Assumptions
- Labels are binary (0/1, clean/attack)
- Ground truth is reliable (labeled data quality matters)

### Limitations
- Accuracy is misleading for imbalanced classes (1% attack rate → 99% accuracy by always predicting clean)
- Single threshold: all metrics depend on the chosen classification threshold
- Does not reflect probability calibration

### Cybersecurity Use Case — Threshold Selection
**Intrusion Detection Rule Evaluation**

A behavioral detection rule for lateral movement is evaluated on 10,000 network sessions where 100 are confirmed lateral movement:
- TP=85, FP=200, TN=9700, FN=15
- Sensitivity = 85% (catches 85 of 100 attacks)
- Precision = 85/285 = 29.8% (nearly 3 false alarms per real alert)
- This informs whether to loosen threshold (increase recall, more FP) or tighten it (increase precision, more FN)

### Splunk SPL
```spl
index=detections
| lookup ground_truth.csv session_id OUTPUT is_attack
| eval TP = if(predicted=1 AND is_attack=1, 1, 0)
| eval FP = if(predicted=1 AND is_attack=0, 1, 0)
| eval TN = if(predicted=0 AND is_attack=0, 1, 0)
| eval FN = if(predicted=0 AND is_attack=1, 1, 0)
| stats sum(TP) as TP, sum(FP) as FP, sum(TN) as TN, sum(FN) as FN
| eval Sensitivity = round(TP / (TP + FN), 3)
| eval Specificity = round(TN / (TN + FP), 3)
| eval Precision   = round(TP / (TP + FP), 3)
| eval Accuracy    = round((TP + TN) / (TP + TN + FP + FN), 3)
| eval NPV         = round(TN / (TN + FN), 3)
| eval FPR         = round(FP / (FP + TN), 3)
| table TP, FP, TN, FN, Sensitivity, Specificity, Precision, Accuracy, NPV, FPR
```

---

## 2. ROC Curve & AUC

### What It Analyzes
The Receiver Operating Characteristic curve plots True Positive Rate (Sensitivity) against False Positive Rate across all possible classification thresholds. AUC (Area Under the Curve) summarizes performance as a single threshold-independent scalar.

### Formula
```
For each threshold t:
  TPR(t) = TP(t) / (TP(t) + FN(t))   ← y-axis
  FPR(t) = FP(t) / (FP(t) + TN(t))   ← x-axis

AUC = ∫₀¹ TPR(FPR) d(FPR)
    = P(score_positive > score_negative)  ← probability interpretation

Trapezoid approximation:
AUC ≈ Σᵢ (FPR_i+1 - FPR_i)(TPR_i + TPR_i+1) / 2

Interpretation:
  AUC = 0.5 → random classifier
  AUC = 0.7 → acceptable
  AUC = 0.8 → good
  AUC = 0.9 → excellent
  AUC = 1.0 → perfect (suspicious — check for leakage)
```

### Outputs
- ROC curve (set of TPR/FPR pairs across thresholds)
- AUC scalar ∈ [0.5, 1.0]
- Optimal threshold (Youden's J: max TPR-FPR)
- Confidence interval for AUC (bootstrap or Delong method)

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Predicted Score | Float [0,1] | Model probability or anomaly score |
| Actual Labels | Binary | Ground truth |
| Threshold Range | Float array | Values to sweep (0 to 1) |
| Output | Float | AUC value |
| Optimal Threshold | Float | Maximizes TPR - FPR |

### Assumptions
- Binary classification outcome
- Predicted scores are ordinal (higher = more likely positive)
- AUC meaningful for class-balanced evaluation; use PR-AUC for imbalanced

### Limitations
- AUC does not reflect absolute performance at any threshold
- Insensitive to class imbalance — can be high even with poor rare-class detection
- Optimistic when attack class is rare (use Precision-Recall curve instead)
- AUC comparison between models requires same test set

### Cybersecurity Use Case
**Comparing Detection Algorithms**

Two anomaly detectors are evaluated on the same labeled network dataset. Isolation Forest achieves AUC=0.87; LOF achieves AUC=0.79. This confirms Isolation Forest is the better choice for deployment, independent of threshold selection. The ROC curve also shows at what FPR the desired TPR (e.g., ≥ 90%) is achievable.

**Threshold Selection for Operations**: If SOC capacity allows only 20 false alerts/day, find the threshold at FPR = 20/(total_benign_per_day) and read off the corresponding TPR.

### Splunk SPL (AUC Approximation)
```spl
index=ml_scores
| lookup ground_truth.csv event_id OUTPUT is_attack
| sort - anomaly_score
| streamstats count as rank
| eventstats count as N,
             sum(eval(if(is_attack=1,1,0))) as P,
             sum(eval(if(is_attack=0,1,0))) as N_neg
| eval TPR = cumsum(eval(if(is_attack=1,1,0))) / P
| eval FPR = cumsum(eval(if(is_attack=0,1,0))) / N_neg
| eval auc_trapezoid = (FPR - prev_FPR) * (TPR + prev_TPR) / 2
| stats sum(auc_trapezoid) as AUC
| eval AUC = round(AUC, 3)
| eval performance = case(AUC > 0.9, "EXCELLENT", AUC > 0.8, "GOOD", AUC > 0.7, "ACCEPTABLE", true(), "POOR")
| table AUC, performance
```

---

## 3. Precision-Recall Curve & F1-Score

### What It Analyzes
Plots Precision against Recall across all thresholds. Directly measures model performance on the rare positive class — far more informative than ROC when attacks are rare. F1-Score is the harmonic mean of Precision and Recall at a chosen threshold.

### Formula
```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)

F1 = 2 × (Precision × Recall) / (Precision + Recall)
   = 2TP / (2TP + FP + FN)

Fβ (generalized, weight recall β times more than precision):
Fβ = (1 + β²) × (Precision × Recall) / (β² × Precision + Recall)

  β > 1 → penalize FN more (critical for security: don't miss attacks)
  β < 1 → penalize FP more (critical for alert fatigue reduction)
  β = 2 (F2) recommended for detection engineering

PR-AUC (Average Precision):
AP = Σₙ (Rₙ - Rₙ₋₁) × Pₙ
```

### Outputs
- PR curve
- F1-score at each threshold
- Maximum F1 threshold (optimal operating point)
- Average Precision (PR-AUC)
- F2 score (if recall-weighted)

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Predicted Score | Float [0,1] | Anomaly or classification score |
| Actual Labels | Binary | Ground truth |
| β | Float | Recall weight (β=2 for security) |
| Output | Float | F1 or Fβ at each threshold |
| PR-AUC | Float | Summary scalar |

### Assumptions
- Binary classification
- Imbalanced classes (PR-AUC more informative than ROC-AUC when attack prevalence < 10%)

### Limitations
- PR curve has no natural baseline (unlike ROC where baseline = 0.5)
- F1 treats FP and FN equally — use Fβ to adjust
- AP can be optimistic when score distribution has many tied values

### Cybersecurity Use Case
**Malware Detection in Highly Imbalanced Log Data**

In a dataset with 0.5% malware events (1,000 malicious out of 200,000 logs), a model with AUC=0.92 might still have precision of only 10% at the operating threshold — generating 9 false alerts for every real detection. PR-AUC of 0.65 vs 0.80 meaningfully differentiates two models in this space where ROC-AUC cannot.

**F2 Score for Detection Engineering**: Use β=2 to weight recall twice as heavily as precision — catching more attacks is worth accepting more false alerts.

### Splunk SPL
```spl
index=ml_scores
| lookup ground_truth.csv event_id OUTPUT is_attack
| sort - anomaly_score
| streamstats sum(eval(if(is_attack=1,1,0))) as cumTP,
              sum(eval(if(is_attack=0,1,0))) as cumFP,
              count as cumN
| eventstats sum(eval(if(is_attack=1,1,0))) as total_P
| eval Precision = cumTP / cumN
| eval Recall = cumTP / total_P
| eval F1 = if(Precision+Recall > 0, 2*Precision*Recall/(Precision+Recall), 0)
| eval F2 = if(4*Precision+Recall > 0, 5*Precision*Recall/(4*Precision+Recall), 0)
| sort - F1
| head 1
| table anomaly_score, Precision, Recall, F1, F2
| rename anomaly_score as optimal_threshold
```

---

## 4. Matthews Correlation Coefficient (MCC)

### What It Analyzes
A single metric that accounts for all four confusion matrix cells simultaneously. Considers true and false positives AND negatives — robust to class imbalance. Equivalent to the Phi coefficient (correlation between predicted and actual binary labels).

### Formula
```
MCC = (TP×TN - FP×FN) / √[(TP+FP)(TP+FN)(TN+FP)(TN+FN)]

Range: -1 to +1
  MCC = +1 → perfect prediction
  MCC =  0 → random prediction
  MCC = -1 → inverse prediction (systematic misclassification)

MCC = 0 only when classifier is truly uninformative:
  Contrast with accuracy = 0.99 on imbalanced data (misleadingly high)
```

### Outputs
- MCC scalar ∈ [-1, 1]
- Comparison across models at same operating threshold

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | TP, FP, TN, FN | Four confusion matrix cells |
| Output | Float [-1, 1] | MCC score |
| Interpretation | String | Poor/Fair/Good/Excellent |

### Assumptions
- Binary classification
- No assumption about class balance
- More informative than F1 when class distribution is unknown or variable

### Limitations
- Less interpretable than F1 for stakeholder communication
- Not directly comparable across datasets with different base rates
- Does not reflect probability calibration

### Cybersecurity Use Case
**Model Selection on Imbalanced Security Data**

Two models evaluated on 10,000 events (50 attacks):

Model A: TP=40, FP=10, TN=9940, FN=10 → F1=0.80, MCC=0.63
Model B: TP=45, FP=200, TN=9750, FN=5 → F1=0.30, MCC=0.44

F1 alone incorrectly suggests Model A is far superior. MCC shows both models have issues but Model A is genuinely better. MCC penalizes Model B for the 200 false positives that F1 downweights.

### Splunk SPL
```spl
index=detections
| lookup ground_truth.csv event_id OUTPUT is_attack
| stats
    sum(eval(if(predicted=1 AND is_attack=1, 1, 0))) as TP,
    sum(eval(if(predicted=1 AND is_attack=0, 1, 0))) as FP,
    sum(eval(if(predicted=0 AND is_attack=0, 1, 0))) as TN,
    sum(eval(if(predicted=0 AND is_attack=1, 1, 0))) as FN
| eval numerator = TP*TN - FP*FN
| eval denominator = sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN))
| eval MCC = if(denominator > 0, round(numerator / denominator, 3), 0)
| eval interpretation = case(
    MCC > 0.7, "EXCELLENT",
    MCC > 0.5, "GOOD",
    MCC > 0.3, "FAIR",
    MCC > 0, "POOR",
    true(), "RANDOM or WORSE")
| table TP, FP, TN, FN, MCC, interpretation
```

---

## 5. Calibration Curve & Brier Score

### What It Analyzes
Measures whether predicted probabilities match actual event frequencies. A well-calibrated model that outputs p=0.8 should be correct 80% of the time. Miscalibrated models mislead analysts into under- or over-weighting alerts.

### Formula
```
Brier Score (lower is better):
BS = (1/n) × Σᵢ (pᵢ - yᵢ)²

Range: 0 (perfect) to 1 (worst)
Baseline Brier Score (predict always mean prevalence):
BS_ref = p̄(1-p̄)

Brier Skill Score (relative improvement):
BSS = 1 - BS/BS_ref   (positive = better than baseline)

Calibration (Expected Calibration Error):
ECE = Σₖ (nₖ/N) × |acc(Bₖ) - conf(Bₖ)|
  where Bₖ = k-th probability bin
```

### Outputs
- Brier Score (scalar)
- Brier Skill Score
- Calibration plot (mean predicted probability vs. actual event rate per bin)
- ECE (Expected Calibration Error)
- Reliability diagram

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Predicted Probability | Float [0,1] | Model output probability |
| Actual Labels | Binary | Ground truth |
| Bins | Integer | Number of calibration bins (10 typical) |
| Output | Float | Brier Score |
| Calibration | Float per bin | Mean predicted vs. actual rate |

### Assumptions
- Probabilities are meaningful estimates (not arbitrary scores)
- Sufficient data in each calibration bin (≥ 30 per bin recommended)

### Limitations
- Requires large evaluation set for reliable calibration curves
- Calibration may vary across operating thresholds
- Poor calibration can be corrected with Platt scaling or isotonic regression

### Cybersecurity Use Case
**Alert Priority Scoring Validation**

A SOC triage model outputs "probability of true positive" scores. If analysts are told a score of 0.85 means 85% likely real, but the actual rate at that score is only 20%, they will over-investigate low-priority alerts. Brier Score and calibration curves validate whether score labels are actionable for prioritization.

**Practical Fix**: Calibrate using Platt scaling (logistic regression on outputs) or isotonic regression before surfacing scores to analysts.

### Splunk SPL
```spl
index=triage_scores
| lookup ground_truth.csv alert_id OUTPUT is_true_positive
| eval prob_bin = floor(score * 10) / 10
| stats avg(score) as mean_predicted, avg(is_true_positive) as actual_rate,
        count as n by prob_bin
| eval calibration_error = abs(mean_predicted - actual_rate)
| eval weighted_error = (n / 5000) * calibration_error
| stats sum(weighted_error) as ECE,
        sum(eval(n * pow(mean_predicted - actual_rate, 2))) as BS_num,
        sum(n) as N
| eval Brier_Score = round(BS_num / N, 4)
| eval ECE = round(ECE, 4)
| eval calibration_quality = case(
    ECE < 0.05, "WELL CALIBRATED",
    ECE < 0.10, "MODERATE CALIBRATION",
    true(), "POORLY CALIBRATED - recalibrate model")
| table Brier_Score, ECE, calibration_quality
```

---

## Summary: Metric Selection by Scenario

| Scenario | Primary Metric | Secondary | Avoid |
|----------|---------------|-----------|-------|
| Imbalanced attack detection | PR-AUC, F2 | MCC | Accuracy |
| Comparing two classifiers | ROC-AUC | MCC | Accuracy |
| Setting alert threshold | Precision-Recall at threshold | F1 or F2 | AUC alone |
| Validating risk scores for prioritization | Brier Score, Calibration | ECE | None |
| Single number for reporting | MCC | F1 | Accuracy |
| Understanding tradeoffs at all thresholds | ROC curve | PR curve | Single accuracy |
| SOC alert fatigue evaluation | Precision | FPR | Recall alone |
| Missing attacks is catastrophic | Recall/Sensitivity | F2, NPV | Precision alone |

### Detection Engineering Integration

```
1. Define acceptable FPR for SOC capacity
2. Plot ROC curve → find threshold achieving target FPR
3. At that threshold: compute F2 (if recall-priority) or F1 (balanced)
4. Validate calibration → Brier Score < 0.1 for actionable scores
5. Report MCC alongside F1 to stakeholders (catches imbalance blindspots)
6. Re-evaluate quarterly as threat landscape and prevalence shift
```
