# VPNGUARD-X safe-review audit — 21 September 2026

## Decision

The submitted `safe_review.zip` verifies that a large capture inventory exists, but it is **not a corrected evaluation bundle** and cannot be used to update the manuscript results. Corrected performance, packet-loss robustness and dedicated OOD results remain **TBD — requires experiment evidence**.

## What the ZIP establishes

- ZIP integrity passed: 7,206 entries, approximately 22.45 MB uncompressed.
- 900 FULL ground-truth records and 900 records at each of LOSS_10, LOSS_30 and LOSS_50 are present.
- The inventory reports 810 strongSwan FULL runs and 90 strongSwan-to-Libreswan FULL runs, with five seeds (11, 22, 33, 44 and 55).
- The 2,700 derivative records link internally to the correct FULL-capture SHA-256 values. Their external loss manifests equal the embedded loss metadata, the transformation-manifest hashes agree, and realized loss fractions agree with packet counts.
- All 900 run identifiers are unique. Application profiles cover the six known classes and three registered UNKNOWN profiles.

The ZIP excludes all PCAP bytes. Its `verified_pcap_hashes: true` statement was produced on the student's host and cannot be independently repeated from this archive.

## Blocking omissions

The archive contains no per-method metrics, aggregate results, predictions, split manifests, dataset JSONL, preflight record or source snapshot. Therefore it cannot establish:

- inclusion of 10%, 30% and 50% captures in corrected evaluation;
- 140 corrected split definitions and group-disjointness;
- 840 method/seed evaluations;
- non-null AUROC and FPR95 for the dedicated unseen-application test;
- conformal abstention behavior after removal of singleton repair;
- corrected bootstrap intervals, model hashes or execution environment.

The likely packaging cause is that corrected results were written to `artifacts/results_corrected`, while the 0.2.2 safe-review script selected only `artifacts/results`. The script also omitted `artifacts/splits`.

## Scenario-manifest provenance defect

Every one of the 900 FULL ground-truth records disagrees with its included scenario manifest:

- identity, seed, stack, source scenario and `configured_properties` agree in all 900 cases;
- `ground_truth.scenario_manifest_hash == scenario_manifest.manifest_hash` fails in all 900 cases;
- each included scenario manifest was generated after capture completion and remains marked `COMPILED_NOT_EXECUTED`.

The most likely mechanism is a later batch run in `compile` mode using the completed range directory. The previous resume guard protected completed runs only in `run` mode; compilation could overwrite their manifests without replacing PCAPs or ground truth. Version 0.2.3 protects completed directories in both modes.

Do not rewrite ground-truth hashes or claim that the replacement manifests authenticate the captures. Restore the original scenario manifests from a backup if available. If they are unavailable, retain both values in a reconciliation audit, state that configuration fields agree but the original manifest files were overwritten, and treat cryptographic scenario-manifest provenance as unavailable. The captures can still be used for evaluation, subject to this disclosed limitation; rerunning all 900 range cases is not automatically required.

## Dataset-hash observation

The dataset manifest now reports SHA-256 `0952c6dd5433aa78574e3a8a433c0bc34c3eade72d36425b70d77c923d1c86c2`, whereas the earlier results package reported `b4d3616bd39d402465af8c10230d94dac4212f1125b47227b978e0ff79865174`. The JSONL is absent, so the change cannot be audited. Dataset rows include absolute local paths in the current builder; moving or rebuilding the same evidence in a different directory can change the byte-level dataset hash. Record this cause explicitly or normalize paths before the definitive run.

## Cooperative-telemetry inconsistency

All supplied records configure `child.anti_replay_enabled: true`, while their copied endpoint observations report `child.anti_replay_enabled: false` and `child.replay_window_size: 0`. This may reflect direction-specific XFRM states or normalization of mixed inbound/outbound state rather than the actual receiver policy; the redacted raw XFRM telemetry is absent, so it cannot be resolved here. Treat anti-replay as unvalidated and do not claim cooperative confirmation until the raw authorized telemetry is inspected per SA and direction.

The observed field called `sa.configured_lifetime` also ranges below 3,600 seconds, consistent with a remaining-time counter rather than the configured lifetime of 3,600 seconds. The VICI normalization and field name require validation before lifetime is used as deterministic evidence. These telemetry concerns do not explain the missing packet-loss metrics, because the current dataset builder extracts hard evidence from packet analysis, but they affect cooperative-validation and security-assessment claims.

## Required next package

Using the updated source, run from the project root:

```bash
python scripts/prepare_safe_review.py --project . --output ../VPNGUARD-X_corrected_safe_review.zip
```

Before upload, inspect the printed `result_roots`. A complete corrected package should report:

- a `results_corrected` root;
- 840 `metrics.json` files;
- an aggregate-results file;
- loss keys `0.0`, `0.1`, `0.3`, `0.5`, each occurring in all applicable metrics;
- zero null dedicated-OOD metric files;
- 140 included split JSON files;
- explicit scenario-manifest mismatch count, unless the authentic originals were restored.

If `results_corrected` is absent locally, run the corrected dry-run first and verify each applicable test has FULL, LOSS_10, LOSS_30 and LOSS_50 rows. Then execute the five-seed evaluation using the commands in `docs/Results_Audit_2026-09-19.md`. Do not merge earlier metrics into the corrected directory.

## Publication status

The cyber-range scale and cross-stack inventory are useful assets. However, the attached ZIP contains no corrected empirical outputs, and its scenario-manifest chain is broken. Publication readiness is therefore **not yet established**. The manuscript must wait for a reviewable corrected evaluation bundle and should disclose any unrecoverable provenance limitation.
