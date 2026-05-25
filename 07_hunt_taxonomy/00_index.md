# Hunt Taxonomy — Index

This directory covers the complete threat hunting taxonomy: four primary hunt types, custom multi-phase chains, and the 12-month Hunt Jeopardy rotation framework.

## Files

| File | Content |
|------|---------|
| [01_hypothesis_driven.md](01_hypothesis_driven.md) | Hypothesis-driven hunts: specific threat group attribution, kill chain correlation, DeTTECT integration, Tracecat automation |
| [02_anomaly_driven.md](02_anomaly_driven.md) | Anomaly-driven hunts: baseline deviation, ML-based process behavior, UEBA clustering |
| [03_indicator_and_technique_driven.md](03_indicator_and_technique_driven.md) | Indicator hunts (hashes, IPs, domains) and technique hunts (ATT&CK-mapped SPL) |
| [04_custom_chains_and_jeopardy.md](04_custom_chains_and_jeopardy.md) | Multi-phase chains (ransomware, supply chain, insider, cryptojacking) and 12-month Jeopardy calendar |

## Hunt Type Taxonomy

```
Hunt Taxonomy
├── Hypothesis-Driven (top-down)
│   ├── Specific threat group (e.g., APT29/SolarWinds)
│   └── Kill chain correlation (e.g., Kerberoasting → lateral movement)
│
├── Anomaly-Driven (bottom-up)
│   ├── Statistical baseline deviation (Z-score, IQR, MAD)
│   └── ML-based process/user behavior (Isolation Forest, K-Means)
│
├── Indicator-Driven (known-bad)
│   ├── Malware hashes
│   └── Credential compromise indicators
│
├── Technique-Driven (ATT&CK-based)
│   ├── T1566 — Phishing
│   ├── T1021 — Remote Services (RDP)
│   ├── T1055 — Process Injection
│   └── T1134 — Token Impersonation
│
└── Custom Chains (lifecycle hunts)
    ├── Ransomware intrusion lifecycle (9 phases)
    ├── Supply chain trojanization
    ├── Insider data theft
    └── Cryptojacking
```

## Hunt Jeopardy: 12-Month Calendar Summary

| Quarter | Month | Theme |
|---------|-------|-------|
| Q1 | January | APT Campaign Kickoff |
| Q1 | February | Ransomware Pre-Positioning |
| Q1 | March | Nation-State Espionage |
| Q2 | April | Web Shell Deployment |
| Q2 | May | Cloud & SaaS Compromise |
| Q2 | June | Supply Chain Attacks |
| Q3 | July | Reconnaissance & Initial Access |
| Q3 | August | Persistence Deep-Dive |
| Q3 | September | Credential Harvesting |
| Q4 | October | Anti-Forensics & Defense Evasion |
| Q4 | November | Privilege Escalation Chains |
| Q4 | December | Year-End Review + Retro Hunt |

## Statistical Tests by Hunt Type

| Hunt Type | Key Statistical Tests |
|-----------|----------------------|
| Hypothesis-Driven | Chi-Square, Pearson, Z-Score |
| Anomaly-Driven | Z-Score, MAD, IQR, Isolation Forest, LOF, K-Means |
| Indicator-Driven | Binomial CI for prevalence estimation |
| Technique-Driven | Z-Score, Chi-Square, Change Point |
| Chain Hunts | Time series (CUSUM, ARIMA), Benford's Law, K-S test |

## Integration Points

**DeTTECT**: Map coverage gaps to hunt types. Low-visibility techniques → hypothesis or technique-driven hunts. No baseline data → anomaly-driven hunt deferred until telemetry collected.

**Splunk**: Each hunt file contains ready-to-run SPL queries. Tested on Splunk Enterprise 9.x with Sysmon and Windows Security Event Log data.

**Tracecat**: Hunt automation patterns in `01_hypothesis_driven.md`. Multi-phase workflows with conditional trigger logic.

**Neo4j**: Graph queries in `01_hypothesis_driven.md` and `04_custom_chains_and_jeopardy.md` for chain correlation and hunt coverage visualization.
