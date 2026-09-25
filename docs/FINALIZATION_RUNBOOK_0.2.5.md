# VPNGUARD-X Finalization Runbook — v0.2.5

## Purpose

This is the only finalization path for the already executed five-seed benchmark. It does **not** rerun the cyber-range and does **not** retrain XGBoost or TCN. It reads the immutable prediction records, corrects metric semantics, revalidates stored endpoint telemetry, and produces separate SIH and publication deliverables.

Do not run this command on the small safe-review ZIP. That ZIP intentionally excludes the dataset and `predictions.jsonl` files needed for independent recomputation. Run it on the students' full repository.

## The correction being made

Configuration inference is set-valued. Earlier evaluation code selected `max(candidate_posterior)` even when several candidates had equal probability. JSON serialization sorted dictionary keys, so that arbitrary point decision could change after saving and loading a prediction.

Version 0.2.5 uses this rule:

1. If the calibrated prediction set contains exactly one candidate, emit that candidate as the point decision.
2. If it contains zero or more than one candidate, abstain from a point decision.
3. Count abstentions as incorrect in unconditional exact-match and macro-F1.
4. Report point-prediction rate, abstention rate, conditional exact-match, prediction-set coverage, mean set size, and constraint-violation rate separately.

The prediction files are not changed. Corrected metrics are written to a new timestamped directory.

## The two evidence limitations

### L1 — Historical scenario-manifest provenance

The executed ground truth records contain the hash of the manifest used at execution time. In the reviewed evidence, the currently stored manifests were regenerated later and have different hashes, even though their scenario ID, seed, stack, and configured properties agree with ground truth.

The finalizer measures both facts. It does not replace hashes or claim that semantic equality repairs the missing original cryptographic provenance. The manuscript must disclose this limitation.

### L2 — Hidden CHILD-SA and runtime properties

PFS, anti-replay state, ESN, CHILD transforms, and configured lifetime are not all passively observable. Earlier telemetry parsing also conflated IKE transforms with nested CHILD-SA transforms, treated remaining lifetime as configured lifetime, and could miss Linux XFRM's extended replay window.

The finalizer reparses stored authorized VICI/XFRM telemetry without changing ground truth. A property is marked validated only when an endpoint value supports it. Missing evidence remains unvalidated or unknown. `life-time` is treated as remaining active-SA time, not configured lifetime.

## One-command execution

From the extracted finalization-kit directory on Windows PowerShell or Command Prompt:

```bat
py install_finalization_kit.py --project "D:\SIH\VPNGUARD-X_Safe_Sharing_0.2.1\VPNGUARD-X" --finalize
```

If the full repository is elsewhere, replace only the quoted path. The installer backs up every overwritten source file before copying the patch.

On Linux:

```bash
python3 install_finalization_kit.py --project /path/to/VPNGUARD-X --finalize
```

The publication bootstrap defaults to 2,000 hierarchical resamples with seed `26160`. Do not use a reduced bootstrap for manuscript results. Runtime is machine-dependent and must be measured rather than guessed.

## Mandatory input inventory

The selected full repository must contain:

- one combined generated dataset JSONL whose SHA-256 matches the result metadata;
- 3,600 dataset rows: 900 FULL plus 900 at each 10%, 30%, and 50% packet-loss level;
- 140 split manifests: 28 split definitions for each of five seeds;
- 840 `predictions.jsonl` files and their adjacent source `metrics.json` files;
- 3,600 ground-truth records;
- the stored redacted VICI/XFRM telemetry where cooperative revalidation is expected.

The finalizer verifies hashes, run identities, seeds, split leakage, stack counts, packet-loss coverage, and source tests. A failed prerequisite stops finalization and names the audit file to inspect.

## Outputs

All outputs are under:

```text
artifacts/finalization/run-<UTC timestamp>/
```

The original dataset, captures, predictions, metrics, splits, and ground truth are not modified.

| Output | Meaning |
|---|---|
| `FINALIZATION_SUMMARY.json` | Machine-readable index of the complete run |
| `reports/SIH_READINESS.md` | SIH prototype/reproducibility gate |
| `reports/PUBLICATION_READINESS.md` | Manuscript evidence gate and claim boundaries |
| `results/**/metrics.json` | Corrected per-run metrics |
| `results/aggregate-results.json` | Corrected aggregate table |
| `results/bootstrap-hierarchical.json` | Hierarchical intervals and paired CGII effects |
| `audits/prediction-lineage.json` | Dataset, prediction, and split hash verification |
| `audits/scenario-manifest-provenance.json` | L1 measurement and disclosure |
| `audits/cooperative-telemetry-validation.json` | L2 endpoint-evidence revalidation |
| `data/vpnguard_x_combined.sanitized.jsonl` | Portable dataset with scientific fields unchanged |
| `publication_evidence/*.zip` | Common evidence plus one prediction archive per seed |
| `VPNGUARD-X_SIH_Source_0.2.5.zip` | Clean source/reproducibility release |

`artifacts/finalization/LATEST.txt` contains the latest run-directory name.

## Interpreting status

- `PASS` means every automated gate passed and no mandatory disclosure was detected.
- `PASS_WITH_DISCLOSED_LIMITATIONS` or `CONDITIONAL_PASS_WITH_MANDATORY_DISCLOSURES` means the scientific outputs were recomputed successfully, but L1 and/or L2 must remain explicit in the demo and manuscript.
- `FAIL` means the named prerequisite or evidence check did not pass. Do not copy values into the manuscript until it is resolved.

No script can honestly reconstruct the original executed manifest after it has been replaced or validate a hidden parameter when endpoint evidence was never retained. Those cases remain bounded limitations rather than patched claims.
