# Splunk Performance & Architecture — Index

This directory covers production-grade SPL implementation: `tstats` with accelerated data models, the full streaming vs. distributed command architecture, and CIM field mappings for every major security data source.

## Files

| File | Content |
|------|---------|
| [01_tstats_and_data_models.md](01_tstats_and_data_models.md) | tstats syntax, data model acceleration, CIM compliance setup, performance benchmarks, troubleshooting |
| [02_streaming_commands_deep_dive.md](02_streaming_commands_deep_dive.md) | streamstats, eventstats, transaction, eval, autoregress, accum, predict — where each runs and when to use each |
| [03_statistical_tests_with_tstats.md](03_statistical_tests_with_tstats.md) | All statistical tests from `06_statistical_tests/` rewritten with tstats for 30-day baseline scale |
| [04_cim_field_mapping.md](04_cim_field_mapping.md) | CIM field mapping for Sysmon, Windows Security Log, Corelight/Zeek, Palo Alto, Azure AD, Web proxy |

## When to Use This Directory

- You're scaling a hunt from "works on 24 hours" to "works on 90 days"
- You're building a scheduled detection that runs every 5 minutes
- Your `stats` search is timing out on a large time range
- You're onboarding a new data source and need CIM field mappings
- You're populating a MLTK model from a 30-day feature dataset

## Architecture Summary

```
Raw search (index=*):
  Best for: investigations, ad-hoc hunts, small time windows, new data sources
  Limit: ~24h at network scale before timeouts

tstats (FROM datamodel=):
  Best for: scheduled detections, 7-90 day baselines, dashboards, ML feature builds
  Requires: data model acceleration enabled + CIM-compliant sourcetypes
  Speed: 10-30× faster than raw search for the same time range

Streaming (streamstats, eval):
  Best for: running stats, lag values, per-event scoring, session-aware calculations
  Runs on: Search Head only (after data aggregation)
  Key: runs after tstats — use tstats to minimize the result set first

Distributed (stats, timechart):
  Best for: final aggregation, group-by statistics
  Runs on: Indexers (partial) + Search Head (merge)
  Key: most of the work happens on indexers — maximize early filtering
```

## Integration with Statistical Tests

Each test in `06_statistical_tests/` has a naive (index=*) version in that file and a production (tstats) version in `03_statistical_tests_with_tstats.md`:

| Test | tstats Section |
|------|---------------|
| Z-Score | §1 — Network Traffic |
| IQR | §2 — Authentication |
| MAD | §3 — Process Execution |
| Benford's Law | §4 — File System |
| Change Point (CUSUM) | §5 — Auth Rate |
| Pearson Correlation | §6 — Beaconing |
| Isolation Forest | §7 — Multi-feature (tstats + MLTK) |
| K-Means | §8 — User Behavior Segmentation |
| First-Seen | §9 — New Destinations/Processes |
| Lateral Movement Chain | §10 — Multi-model join |
