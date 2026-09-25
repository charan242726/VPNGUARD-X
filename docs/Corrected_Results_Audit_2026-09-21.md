# VPNGUARD-X corrected-results audit — 21 September 2026

## Decision

The corrected evaluation successfully fixes the packet-loss linkage and dedicated unseen-application test defects. It supplies 840 five-seed method results with all four capture conditions and internally consistent aggregate arithmetic. The evidence now supports a research narrative about **constraint enforcement and explicit failure/abstention under distribution shift**, but it does not support claims of universally accurate configuration inference, nominal 90% prediction-set coverage, or reliable open-world rejection.

The work is promising but **not yet ready for submission to Computer Networks**. Split files and prediction records are missing from the review archive; the supplied bootstrap pools seed-specific model scores and understates between-seed instability; scenario-manifest provenance remains broken; and cooperative anti-replay/lifetime telemetry remains unresolved.

## Evidence inventory

| Evidence | Audit result |
| --- | --- |
| Metric files | 840/840 parsed successfully |
| Design | 28 split identifiers × 5 seeds × 6 method combinations |
| Seeds | 11, 22, 33, 44, 55; 168 method runs per seed |
| Split families | LOCO 18, LOCIPHER 3, LOMODE 2, IPv4→IPv6, native ESP→NAT-T, NAT-T→native ESP, cross-stack, unseen-application OOD |
| Packet loss | All 840 metrics contain 0%, 10%, 30%, and 50% groups |
| Dedicated OOD | Non-null AUROC and FPR95 in all 30 applicable method files |
| Aggregate arithmetic | Recomputed means agree with `aggregate-results.json` |
| Dataset identifier | One SHA-256 across all 840 runs: `0952c6dd5433aa78574e3a8a433c0bc34c3eade72d36425b70d77c923d1c86c2` |
| Split identifiers/hashes | 140 unique hashes are referenced, but split JSON files are absent |
| Predictions | Absent; their recorded SHA-256 values cannot be checked |
| Environment | Python 3.14.7, NumPy 2.2.1, Torch 2.14.0+cu130 in all method records; differs from the pinned Python 3.12 target |

## Configuration inference

The following are descriptive, equal-weight means over the available split/seed summaries. They combine heterogeneous shift experiments and should not replace split-specific tables or hierarchical uncertainty intervals.

| Method | Exact match | Set coverage | Mean set size | Constraint violations |
| --- | ---: | ---: | ---: | ---: |
| CGII + XGBoost prior | 0.476 | 0.419 | 0.683 | 0.000 |
| Deterministic parser feasible set | 0.640 | 1.000 | 3.115 | 0.000 |
| Unconstrained XGBoost | 0.033 | 0.041 | 1.533 | 0.799 |

The parser point estimate is an arbitrary argmax/tie consequence of an unweighted feasible set; its meaningful outputs are feasible-set coverage and size. CGII strongly reduces the unconstrained model's invalid decisions and narrows the parser feasible set, but loses substantial coverage. Empty conformal sets are now retained as abstentions, which explains mean set sizes below one.

| Shift family | CGII exact match | CGII set coverage | CGII mean set size | Parser set coverage/size | Unconstrained violation rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| Leave-one-configuration-out | 0.412 | 0.412 | 0.747 | 1.000 / 3.058 | 0.806 |
| Cross-stack | 0.378 | 0.273 | 0.362 | 1.000 / 5.519 | 0.434 |
| IPv4→IPv6 | 0.761 | 0.561 | 0.561 | 1.000 / 1.588 | 1.000 |
| Native ESP→NAT-T | 0.951 | 0.941 | 0.941 | 1.000 / 1.247 | 1.000 |
| NAT-T→native ESP | 0.560 | 0.181 | 0.181 | 1.000 / 3.987 | 1.000 |

Thus the defensible CGII claim is hard-constraint satisfaction with transparent abstention and a measurable informativeness/coverage trade-off. A 90% conformal coverage claim is not supported under held-out shifts. This is consistent with the declared absence of an exchangeability guarantee under distribution shift.

## Packet-loss robustness

Descriptive means over all split/seed summaries show the intended degradation experiment is now active:

| Loss | Configuration exact match (CGII) | Configuration set coverage (CGII) | XGBoost traffic balanced accuracy | TCN traffic balanced accuracy |
| ---: | ---: | ---: | ---: | ---: |
| 0% | 0.519 | 0.458 | 0.852 | 0.827 |
| 10% | 0.510 | 0.450 | 0.775 | 0.819 |
| 30% | 0.476 | 0.421 | 0.652 | 0.728 |
| 50% | 0.401 | 0.348 | 0.648 | 0.642 |

These values demonstrate graceful but material degradation. Formal claims require corrected hierarchical intervals and should be reported per shift family because the same captures appear in several evaluation families.

## Known-class traffic and OOD

Known-class classification is generally strong in the controlled generator environment. For example, TCN balanced accuracy is 0.893 for LOCO and 0.874 cross-stack; XGBoost obtains 0.852 and 0.869 respectively. Native ESP→NAT-T is a weakness for TCN (0.763 versus XGBoost 0.856). These results must be described as controlled cyber-range performance, not as evidence of real-world application classification.

Dedicated unseen-application detection is weak:

| Model | Five-seed mean OOD AUROC | FPR95 | UNKNOWN recall |
| --- | ---: | ---: | ---: |
| XGBoost | 0.540 | 1.000 | 0.405 |
| TCN | 0.599 | 0.858 | 0.243 |

TCN AUROC is highly unstable across seeds: 0.502, 0.521, 0.504, 0.925 and 0.541. The median is approximately 0.521. Reliable UNKNOWN handling is therefore not established. The paper should report this limitation and avoid presenting the current confidence-threshold gate as a solved open-world detector.

## Calibration, protocol extraction and latency

- The corrected CGII sets reveal rather than conceal empty-set abstention, but coverage is far below 0.90 under several shifts. Report empirical coverage, set size and abstention rate together.
- Mean protocol field accuracy across repeated split summaries is approximately 0.806 and macro-F1 0.763. This is not an independent parser benchmark because records are reused across splits. Produce a single capture-level, per-field and per-loss protocol-extraction table.
- The latency file contains 900 captures × 5 repeats. Mean is 7.43 ms, p50 3.26 ms, p95 35.56 ms and p99 48.94 ms. Its declared scope is `DETERMINISTIC_CORE_NO_LEARNED_MODEL`; it is not end-to-end model-inclusive latency.
- Active-learning label efficiency remains `TBD — requires learning-curve experiment` in all 840 metric files. Either execute that experiment or remove it from the empirical contribution list.

## Bootstrap defect and correction

The submitted bootstrap combines predictions from five separately fitted evaluation seeds and calculates a pooled metric before resampling scenario groups. Scores from independently calibrated models are not necessarily comparable across seeds. This produces, for example, a pooled TCN OOD estimate of 0.529 while the equal-seed mean is 0.599 and conceals the seed-44 outlier.

Version 0.2.4 changes the procedure to a hierarchical bootstrap: resample evaluation seeds first, then resample replicate groups within each selected seed, calculate the metric within each seed, and average seed-level metrics. It also adds paired CGII-versus-parser effects alongside CGII-versus-unconstrained-XGBoost effects. Corrected intervals are **TBD — requires rerunning the bootstrap using private prediction files**.

## Remaining provenance limitations

- All 900 ground-truth scenario hashes still disagree with the included scenario manifests. Configuration fields agree, but cryptographic linkage to the originally executed manifests is unavailable unless authentic backups are restored.
- Endpoint records configure anti-replay but report an observed zero replay window; raw redacted XFRM state is absent. Treat anti-replay validation as unresolved.
- The observed `sa.configured_lifetime` values appear to be decreasing remaining-time values. Validate and rename this telemetry field before using it as deterministic evidence.
- The actual split JSONs and prediction JSONLs are required for independent leakage, OOD-control, hash and bootstrap verification.

## Publication claim matrix

| Proposed claim | Status |
| --- | --- |
| CGII enforces protocol constraints and eliminates invalid configuration outputs in these experiments | Supported |
| Packet-loss robustness was evaluated at 10%, 30%, and 50% | Supported, pending corrected intervals |
| Controlled cross-stack evaluation includes strongSwan→Libreswan | Supported |
| CGII universally outperforms deterministic parsing | Not supported |
| Prediction sets achieve nominal 90% coverage under held-out shifts | Not supported |
| UNKNOWN traffic is reliably detected | Not supported |
| End-to-end system latency is below the reported deterministic-core latency | Not tested |
| Active learning reduces label requirements | TBD — requires experiment |

## Required final actions

1. Use version 0.2.4 and rerun only `experiments.bootstrap_results` on the existing private predictions; model retraining is not required for this statistical correction.
2. Generate the next safe-review ZIP with the 0.2.4 script so it includes all 140 split JSONs, `bootstrap*.json`, `latency*.json`, aggregate results and 840 metrics.
3. Include prediction files in a separate compressed private review bundle if size permits, or provide a deterministic hash/index plus a compact per-seed prediction export containing the fields required to reproduce metrics and bootstrap intervals.
4. Add capture-level per-field protocol extraction, an explicit conformal abstention rate, and paired CGII-versus-parser coverage/size effects.
5. Resolve or disclose scenario-manifest and cooperative-telemetry limitations.
6. Reassess the Computer Networks manuscript after the corrected hierarchical intervals. The credible novelty is evidence-bounded inference and constraint-safe abstention, not superior point accuracy or solved OOD detection.
