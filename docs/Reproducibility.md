# Reproducibility Guide

## Invariants

1. Every cyber-range PCAP has one adjacent `ground_truth.json` with matching filename and SHA-256.
2. Scenario IDs and seeds must exist in `data/CyberRange_Scenario_Matrix.csv`.
3. Ground truth separates configured expectations from endpoint-observed selected state.
4. Publishable telemetry excludes PSKs, private keys, IKE/ESP keys, and unredacted XFRM key bytes.
5. Train/calibration/test artifacts are disjoint by declared replicate group.
6. Model output stores model, dataset, split, feature-schema, catalogue, policy, and calibration hashes.
7. Missing measurements remain `TBD — requires experiment`.

## Environment record

For each frozen experiment, record:

- git commit or source archive SHA-256;
- Python and exact dependency lock;
- OS/kernel, CPU, memory, and accelerator/driver;
- Docker/Compose and resolved image digests;
- strongSwan and second-stack versions/build flags;
- policy/candidate/scenario/observability hashes;
- seed and deterministic-algorithm settings;
- capture point/filter/snap length/time base;
- raw-to-derived artifact hash chain.

The reference source checksum and strongSwan version are embedded in `cyber_range/Dockerfile` and each range manifest. The Debian base tag must be converted to its resolved digest for the institutional benchmark lock; the repository does not invent an unverified digest.

## Recommended execution order

```bash
python -m unittest discover -s tests -v
python experiments/plan_benchmark.py --profile pilot --stack strongSwan-6.1.0 --output artifacts/plans/strongswan-pilot.csv
python cyber_range/batch.py artifacts/plans/strongswan-pilot.csv --output artifacts/range --mode compile
python cyber_range/batch.py artifacts/plans/strongswan-pilot.csv --output artifacts/range --mode run --fail-fast
python cyber_range/range.py validate artifacts/range
python experiments/generate_incomplete_captures.py artifacts/range
python experiments/build_dataset.py artifacts/range --output data/generated/dataset.jsonl
python experiments/make_splits.py data/generated/dataset.jsonl --output artifacts/splits --seeds 11 22 33 44 55
python experiments/audit_dataset.py data/generated/dataset.jsonl --splits artifacts/splits
python experiments/run_evaluation.py data/generated/dataset.jsonl artifacts/splits --output artifacts/results --app-models xgboost tcn --epochs 30
```

Run all enabled scenario/seed combinations before training. Preserve failed runs with failure reason; do not silently remove failures from the sampling frame.

## Incomplete captures

Apply `experiments/incomplete_capture.py` to held-out full captures with independent seeds. The manifest records requested and realized loss. Never mix a thinned derivative or its source across train/test partitions.

## Result release checklist

- Split manifest reviewed for leakage.
- Calibration data not reused for model fitting or final testing.
- Exact software/container/model hashes attached.
- Confidence intervals and replicate-level dispersion reported.
- Every planned metric reported or explicitly marked missing with reason.
- Negative/failed scenarios included in the accounting.
- No secret or unauthorized data present.
