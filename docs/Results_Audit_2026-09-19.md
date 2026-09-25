# VPNGUARD-X results audit — 19 September 2026

**Status:** Submitted range inventory is complete according to its manifests. The archived metrics are preliminary and must not be presented as a verified final five-seed evaluation. Corrected benchmark results: **TBD — requires experiment**.

## Scope and limits

Reviewed `Results_VPNGUARD-X_safe_review.zip` (8,060 ZIP members; archive integrity test passed), the supplied 0.2.1 source, the JSON result tables, and local regression tests. The ZIP does **not** contain 3,600 PCAPs, the 3,600-row JSONL dataset, split-manifest files, or per-example predictions. The inventory asserts that its on-disk PCAP hashes match; I cannot independently hash absent PCAPs, re-extract features, reconstruct splits from their bytes, or reproduce model fitting from this ZIP. This is an artifact and source-code audit, not independent confirmation of all measurements.

## Inventory

| Item | Supplied manifest/evidence | Assessment |
| --- | ---: | --- |
| Original FULL runs | 900: 810 strongSwan + 90 interop | Claimed complete; 900 associated ground-truth records present |
| LOSS_10, LOSS_30, LOSS_50 | 900 per level | Claimed complete; 2,700 loss manifests and ground-truth records present |
| Split manifests | 140 reported by dataset audit | Split bytes absent; audit reports valid with a byte-identical-loss warning |
| Method/seed evaluations | 840 metric JSON files = 28 split identifiers × 5 seeds × 6 method combinations | Present; protocol, configuration, traffic and calibration summaries are preliminary |
| Dataset | manifest reports 3,600 rows, 18 configurations, 9 application profiles | JSONL absent; manifest hash cannot be checked independently |
| Reproducibility | seeds 11,22,33,44,55 | Present in metric metadata; execution used Python 3.14.7 rather than pinned 3.12 |

## Findings that affect claims

1. **Packet-loss metrics missing (blocking).** All 840 method metric files have only `incomplete_capture["0.0"]`. In the submitted code, `_linked_test_rows` tests `source_artifact_id in test_ids`, but `source_artifact_id` is a root lineage hash while FULL `artifact_id` hashes an additional `transformation_seed=None`. The derivative captures therefore never enter test evaluation. The presence of 2,700 derivative captures does not constitute a completed packet-loss robustness experiment. Corrected 10%, 30%, 50% curves: **TBD — requires experiment**.
2. **Dedicated unseen-application OOD split lacks negative controls (blocking for that split).** Its test partition contains UNKNOWN only; AUROC and FPR95 are `null` in its 30 metric files. The XGBoost and TCN application training helpers correctly filter out UNKNOWN, so the OOD results in other mixed-label splits are usable as preliminary, split-specific results. The dedicated unseen-application AUROC/FPR95 are **TBD — requires experiment**.
3. **Conformal sets were silently repaired to singleton argmax.** If the conformal selection was empty, the engine replaced it with a top candidate and the unconstrained benchmark did likewise. This changes the advertised set construction and obscures abstention. Reported CGII sets have mean size exactly 1; CGII five-seed mean coverage is 44.44% over the 18 leave-one-configuration-out splits (unweighted split mean), versus 100% feasible-set inclusion for parser-only at mean size 2.39. Under cross-stack shift CGII coverage is 55.78% versus parser-only 100% at size 4.5. These are descriptive comparisons of different set sizes, not evidence of a 90% coverage guarantee. Current CGII behavior is not a sound basis for a calibrated-coverage manuscript claim.
4. **The strongest baseline must be included.** On LOCO, parser-only exact match averages 66.67%, CGII 44.44%; on cross-stack, parser-only 100%, CGII 55.78%. Parser-only `exact_match` breaks ties in an unweighted feasible set and should not be interpreted as a uniquely identified configuration. Report feasible-set coverage and size alongside this diagnostic point metric. Existing bootstrap paired effects compare CGII with unconstrained XGBoost, not parser-only; add paired comparison with parser-only and report uncertainty and set-size tradeoff.
5. **OOD limitation.** The mixed-label OOD AUROC for XGBoost is approximately 0.71 across the 27 applicable split summaries (descriptive unweighted mean), with FPR95 near 0.98. This is insufficient to claim reliable unknown rejection. One must not extrapolate synthetic application separation to unseen real deployments.
6. **Unfinished claims.** Active-learning efficiency remains `TBD — requires learning-curve experiment`. Separate latency results measure the deterministic core (900 inputs, five repeats, mean approximately 5.80 ms, p95 approximately 25.75 ms), not model-inclusive end-to-end evaluation. Distinguish endpoint configured truth from actually negotiated attributes when judging CHILD-SA parameters and PFS.

## Applied source correction (0.2.2 evaluation fix)

- Match loss variants to test FULL captures using `replicate_group` and `source_artifact_id`; report each variant count in `--dry-run`, and flag a split where loss data exist but none links to its FULL test rows.
- Reserve group-disjoint known controls by application class in the dedicated unseen-application test; leave UNKNOWN out of both training and calibration.
- Return empty conformal sets as empty and flag abstention; do not synthesize singleton predictions. Recalibration and evaluation are required after this change.
- Added lineage and OOD split regression tests. `python -m unittest discover -s tests -q`: 26 tests passed on the audit host. This is a local code test, not a reproduction of any empirical result.

## Student execution checklist

Work from the students' original **private** run directory with the 3,600 paired captures and ground-truth records, the complete `data/generated/vpnguard_x_combined.jsonl`, and the 140 split manifests. Retain original results in a separate read-only location. Run inside the controlled lab only; do not upload endpoint secrets or raw PCAPs publicly.

1. Extract the corrected source ZIP as a new copy; set up the pinned Python environment from `requirements/` and record `python --version`, dependency versions, stack/container digests, host OS and hardware. The submitted 3.14.7 environment needs an explicit deviation statement if retained.
2. Regenerate the dataset from private artifacts if needed: `python -m experiments.build_dataset artifacts/range --output data/generated/vpnguard_x_combined.jsonl`. Check 900 FULL + 900 each LOSS level, the dataset hash and the ground-truth pairing. Do not silently combine records from multiple runs.
3. Regenerate split manifests **after the OOD fix**: `python -m experiments.make_splits data/generated/vpnguard_x_combined.jsonl --output artifacts/splits --seeds 11 22 33 44 55`; audit them with `python -m experiments.audit_dataset data/generated/vpnguard_x_combined.jsonl --splits artifacts/splits --output artifacts/audits/dataset-and-splits.json`. Check no lineage group crosses partitions and each dedicated OOD test has both known and UNKNOWN rows.
4. Before training, run `python -m experiments.run_evaluation data/generated/vpnguard_x_combined.jsonl artifacts/splits --output artifacts/results_corrected --dry-run`. Inspect `artifacts/results_corrected/dry-run.json`. For a 90-FULL cross-stack test expect 90 each at FULL, LOSS_10, LOSS_30, LOSS_50, total 360. Investigate any missing loss level; no exception for the dedicated OOD split.
5. Fit/evaluate with `python -m experiments.run_evaluation data/generated/vpnguard_x_combined.jsonl artifacts/splits --output artifacts/results_corrected --app-models xgboost tcn --epochs 30 --alpha 0.1`. Require 140 splits × 6 method combinations = 840 metrics JSON files, with `incomplete_capture` keys `0.0`, `0.1`, `0.3`, `0.5` in every applicable run. Preserve full predictions, model hashes and aggregate outputs privately. Recompute bootstrap intervals from the corrected predictions; include a paired CGII vs parser-only effect. The old result JSON must never be merged into the corrected aggregate.
6. Produce real active-learning curves and model-inclusive latency measurements if those claims are in the manuscript. Audit configuration prediction-set size and coverage, OOD AUROC/FPR95 and abstention separately per split; do not assume coverage under cross-domain shift.
7. For independent audit without transferring 1.2 GB, prepare a new safe ZIP containing the dataset JSONL plus SHA256 manifest, all split JSONs, dataset/split audit, corrected aggregate and bootstrap outputs, per-method metrics, reproducibility manifest, and **one or two authorized redacted PCAP/ground-truth pairs** with hashes. Keep raw credential material and unredacted private captures out. We can then cross-check the dataset, split groups and summary arithmetic; verifying all PCAP hash claims still requires local access to all source PCAPs.

## Publication decision

A strong, credible research paper remains feasible, but **publishability of the claimed outcomes is not yet established**. Present these results as preliminary, fix evaluation first, and write the conclusions from corrected five-seed evidence. The novelty claim should be bounded inference/observability with transparent unknowns and constraints; it must withstand comparison with the deterministic parser baseline and demonstrate the calibration/robustness limits honestly.
