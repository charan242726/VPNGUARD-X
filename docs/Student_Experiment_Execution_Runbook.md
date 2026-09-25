# VPNGUARD-X Student Experiment Execution Runbook

**Purpose:** execute the controlled cyber-range, generate the research dataset,
train XGBoost and TCN baselines, complete five-seed evaluation, run all declared
generalization and 10/30/50% packet-loss experiments, and perform the preferred
strongSwan-to-Libreswan validation.

**Current empirical results:** **TBD — requires experiment**  
**Safety boundary:** isolated institutional laboratory only; never point any
script at public or unauthorized systems.

## 1. What the students will produce

The minimum publishable evidence package is:

1. a frozen source archive or git commit;
2. one preflight/environment record;
3. balanced strongSwan run-plan CSV and manifest;
4. successful and failed run accounting for every planned row;
5. one hash-matched `ground_truth.json` per PCAP;
6. 10%, 30%, and 50% loss derivatives with lineage manifests;
7. one model-ready JSONL dataset and dataset card;
8. five seeded split families;
9. fitted XGBoost configuration/application models and TCN application models;
10. parser-only, unconstrained-XGBoost, and calibrated CGII prediction records;
11. per-seed and mean±sample-SD results for every split;
12. preferably, a strongSwan→Libreswan interop dataset and cross-stack split;
13. final tables whose values can be traced to prediction-record hashes.

Software tests are not experimental results. Until items 3–13 exist, every
accuracy, calibration, OOD, robustness, and latency value remains
`TBD — requires experiment`.

## 2. Team roles

| Role | Responsibility | Must not do |
|---|---|---|
| Range lead | Host preparation, Docker isolation, plan execution, failed-run log | Modify labels after seeing results |
| Protocol lead | Check selected IKE/CHILD state against PCAP observability | Copy endpoint-only values into passive `OBSERVED` fields |
| Data lead | Hashes, schema checks, lineage, split leakage audit | Split individual packets/flows from one run across partitions |
| ML lead | XGBoost/TCN fitting, calibration, OOD gate, seeded runs | Tune on final test data or report the best seed only |
| Statistics lead | Aggregate, bootstrap extension, ablations, tables | Treat packets as independent experimental samples |
| Reproducibility lead | Environment/image digests, archive, dataset card | Delete failed scenarios silently |

At least two students should sign off each final artifact: its producer and one
reviewer from another role.

## 3. Laboratory requirements

Use a dedicated x86-64 Linux workstation or VM, preferably Ubuntu 24.04 LTS or
an institutional equivalent, with:

- hardware virtualization and a current Linux kernel;
- 8 CPU cores minimum, 16 recommended;
- 32 GiB RAM recommended;
- 100 GiB free storage before a full run;
- Docker Engine and Compose v2;
- permission to run containers with `NET_ADMIN`;
- Python 3.12 and `venv`;
- no route from the cyber-range networks to public targets.

The ranges use Docker `internal: true` networks and fixed RFC 1918/ULA
addresses. The traffic generator rejects any target outside its hard-coded
allow-list. These controls are mandatory, not optional.

## 4. Install and preflight

From the repository root:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements/all.lock
python -m pip install -e .
python scripts/lab_preflight.py --output artifacts/environment/preflight.json --require-docker
```

Acceptance gate A:

- all unit tests pass;
- the strongSwan Compose file validates;
- Docker is reachable without changing the scripts;
- at least 100 GiB is free, or the team records and approves a smaller storage
  plan;
- `preflight.json` is retained unchanged.

The Libreswan Compose check is preferred for the cross-stack phase. A failure
there does not invalidate the strongSwan experiment, but cross-stack results
must remain `not executed` until fixed.

## 5. Generate balanced plans

The legacy scenario matrix is useful for protocol coverage, but its original
traffic labels are not sufficiently crossed with configurations for a clean ML
experiment. The benchmark planner treats those rows as configuration templates
and crosses every selected configuration with six known and three OOD traffic
profiles.

### 5.1 StrongSwan pilot

```bash
python experiments/plan_benchmark.py \
  --profile pilot \
  --stack strongSwan-6.1.0 \
  --output artifacts/plans/strongswan-pilot.csv

python cyber_range/batch.py artifacts/plans/strongswan-pilot.csv \
  --output artifacts/range \
  --mode compile

python cyber_range/batch.py artifacts/plans/strongswan-pilot.csv \
  --output artifacts/range \
  --mode run --fail-fast
```

The pilot contains 18 runs: two configurations × nine traffic profiles × one
seed. Inspect all failures before continuing. Do not change a proposal merely
to make a failed row disappear; update the matrix/design, explain the reason,
and regenerate the plan with a new version.

### 5.2 StrongSwan full plan

```bash
python experiments/plan_benchmark.py \
  --profile full \
  --stack strongSwan-6.1.0 \
  --output artifacts/plans/strongswan-full.csv

python cyber_range/batch.py artifacts/plans/strongswan-full.csv \
  --output artifacts/range \
  --mode compile

python cyber_range/batch.py artifacts/plans/strongswan-full.csv \
  --output artifacts/range \
  --mode run
```

The supplied full design contains 810 runs: 18 configurations × 9 profiles ×
5 seeds × 1 session. `batch.py` is resumable and skips only runs with both a
PCAP and adjacent ground truth. Keep the host otherwise idle while timing data
are collected.

Acceptance gate B:

```bash
python cyber_range/range.py validate artifacts/range
```

- each planned row is `COMPLETED` or has an explicit retained failure reason;
- every completed PCAP contains a reconstructed IKE session and ESP flow;
- both endpoints show an established CHILD-SA/XFRM state;
- no ground-truth record contains a PSK, private key, session key, or unredacted
  XFRM key;
- the completed sampling frame is reported, including failures.

### 5.3 Deliberately legacy controls

IKEv1 and weak-algorithm rows are supplementary parser/policy negative controls,
not part of the balanced five-seed application benchmark. Run only inside the
same isolated range, retain negotiation failures as outcomes, and never weaken
the host outside these containers:

```bash
for seed in 11 22 33; do
  python cyber_range/range.py run \
    --scenario VGX-I1-V4-TUN-CBC14-NATIVE-WEB \
    --seed "$seed" --output artifacts/legacy-controls
  python cyber_range/range.py run \
    --scenario VGX-I1-V4-TUN-3DES2-NATT-BULK \
    --seed "$seed" --output artifacts/legacy-controls
  python cyber_range/range.py run \
    --scenario VGX-I2-V4-TUN-CBC5-NATIVE-CTRL \
    --seed "$seed" --output artifacts/legacy-controls
done
```

If the pinned stack no longer supports a legacy primitive, report the condition
as an implementation rejection. Do not substitute a different algorithm while
keeping the old label.

## 6. Generate incomplete captures

Generate loss derivatives only after all pristine FULL captures are immutable:

```bash
python experiments/generate_incomplete_captures.py artifacts/range
python cyber_range/range.py validate artifacts/range
```

The command creates 10%, 30%, and 50% independent Bernoulli packet-removal
variants. Each derivative records requested and realized loss, source hash,
transformation seed, and root artifact ID. Never copy a derivative into a
different replicate group. Never train on the derivative of a final-test PCAP.

The evaluation runner includes linked derivatives only when their pristine
source is in that split's test partition.

## 7. Build and audit the primary dataset

```bash
python experiments/build_dataset.py artifacts/range \
  --output data/generated/vpnguard_x.jsonl

python experiments/audit_dataset.py data/generated/vpnguard_x.jsonl \
  --output artifacts/audits/dataset-before-splits.json
```

Review the manifest counts for stack, capture variant, application profile, and
excluded failed runs. A warning that the FULL configuration-by-traffic cells
are unbalanced must be resolved or justified before training.

Complete `data/DATASET_CARD_TEMPLATE.md` using measured counts and hashes. Do
not include the synthetic demo or unit-test fixtures.

## 8. Preferred strongSwan→Libreswan validation

Libreswan 5.4 is pinned to release commit
`5eb03b7772b312e705feab9ad5868678a3c007e6`. The initial interop subset is
intentionally limited to IKEv2, IPv4, native ESP, tunnel mode, and two common
AES proposal families. This prevents an unvalidated translation table from
contaminating the cross-stack claim.

```bash
python experiments/plan_benchmark.py \
  --profile pilot \
  --stack strongSwan-6.1.0-to-Libreswan-5.4 \
  --output artifacts/plans/libreswan-pilot.csv

python cyber_range/batch.py artifacts/plans/libreswan-pilot.csv \
  --output artifacts/range \
  --mode compile

python cyber_range/batch.py artifacts/plans/libreswan-pilot.csv \
  --output artifacts/range \
  --mode run --fail-fast
```

Manually verify one GCM and one CBC pilot run:

- strongSwan `swanctl --list-sas --raw` reports the expected selected IKE and
  CHILD transforms;
- Libreswan `ipsec showstates` and `ipsec trafficstatus` show the peer and ESP
  SA;
- both `ip -s xfrm state` exports contain ESP state and are redacted on disk;
- the PCAP shows the expected IKEv2 exchange, native ESP, and both directions;
- configured and endpoint-selected values agree.

Then execute the full 90-run interop plan:

```bash
python experiments/plan_benchmark.py \
  --profile full \
  --stack strongSwan-6.1.0-to-Libreswan-5.4 \
  --output artifacts/plans/libreswan-full.csv

python cyber_range/batch.py artifacts/plans/libreswan-full.csv \
  --output artifacts/range \
  --mode run

python cyber_range/range.py validate artifacts/range
python experiments/generate_incomplete_captures.py artifacts/range
```

For the frozen paper run, replace `fedora:43` in the build argument with its
resolved content digest and record the built image ID. If Libreswan compilation
or interoperability cannot be completed, report cross-stack as `not executed`;
do not substitute a same-stack result.

## 9. Rebuild the combined dataset and create five-seed splits

After adding interop captures and their derivatives:

```bash
python experiments/build_dataset.py artifacts/range \
  --output data/generated/vpnguard_x_combined.jsonl

python experiments/make_splits.py data/generated/vpnguard_x_combined.jsonl \
  --output artifacts/splits \
  --seeds 11 22 33 44 55

python experiments/audit_dataset.py data/generated/vpnguard_x_combined.jsonl \
  --splits artifacts/splits \
  --output artifacts/audits/dataset-and-splits.json
```

`make_splits.py` uses only FULL captures to define train/calibration/test IDs.
The seed changes the group-level calibration allocation and is also used for
model initialization. The generated families include:

- every leave-one-configuration-out split;
- every leave-one-cipher-out split;
- both leave-one-mode-out directions;
- IPv4→IPv6;
- native ESP→NAT-T and NAT-T→native ESP;
- strongSwan→Libreswan when both stacks exist;
- unseen-application OOD.

Acceptance gate C: `audit_dataset.py` reports `valid: true` and no
replicate-group leakage. Resolve warnings before fitting any final model.

## 10. Train and evaluate the baselines

First perform a manifest-only dry run:

```bash
python experiments/run_evaluation.py \
  data/generated/vpnguard_x_combined.jsonl artifacts/splits \
  --output artifacts/results-dry-run \
  --app-models xgboost tcn \
  --dry-run
```

Then run one split and reduced TCN epochs only as an engineering pilot:

```bash
python experiments/run_evaluation.py \
  data/generated/vpnguard_x_combined.jsonl artifacts/splits \
  --output artifacts/results-pilot \
  --app-models xgboost tcn \
  --epochs 2 \
  --max-splits 1
```

Pilot metrics are debugging evidence and must not enter the paper. For the
declared experiment, run all five seed directories and the locked 30 epochs:

```bash
python experiments/run_evaluation.py \
  data/generated/vpnguard_x_combined.jsonl artifacts/splits \
  --output artifacts/results \
  --app-models xgboost tcn \
  --epochs 30 \
  --alpha 0.10
```

For each split and seed, the script fits:

- XGBoost on flow statistics for application classification;
- TCN on masked signed-length/inter-arrival sequences for application
  classification;
- XGBoost candidate prior for configuration inference;
- scalar temperature calibration for application probabilities;
- an in-domain rejection gate for UNKNOWN/OOD;
- split-conformal configuration prediction sets;
- parser-only, unconstrained-XGBoost, and CGII-projected ablations.

It writes prediction JSONL before metric JSON. This ordering ensures every
number can be recomputed. A failed training/calibration run is a failed planned
run; it must not be replaced by a hand-entered value.

Measure end-to-end deterministic-core latency separately so batched model
training code is not mistaken for system latency:

```bash
python experiments/benchmark_system_latency.py \
  data/generated/vpnguard_x_combined.jsonl \
  --output artifacts/results/system-latency.json \
  --repeats 5
```

This includes PCAP reading, parsing, reconstruction, observability, feature
extraction, CGII, policy, risk, and remediation without a learned model. Report
that scope explicitly. If model-inclusive latency is added later, keep it as a
separate declared measurement and identify the model/hardware hash.

## 11. Experiments and interpretation

| Experiment | Training domain | Test domain | Primary interpretation |
|---|---|---|---|
| LOCO | All but one complete configuration | Held-out configuration | Does the system widen/abstain under unseen configurations? |
| Leave-one-cipher | Other ESP cipher families | Held-out cipher | Open-world crypto generalization; exact unseen-candidate prediction is not assumed |
| Leave-one-mode | Tunnel or transport | Opposite mode | Application robustness and evidence-bounded uncertainty |
| IPv4→IPv6 | IPv4 | IPv6 | Address-family shift |
| Native→NAT-T | Native ESP | UDP-encapsulated ESP | Encapsulation shift |
| strongSwan→Libreswan | strongSwan | Interop/Libreswan responder | Implementation-stack shift |
| Unseen application | Six known classes | Held-out OOD profiles | UNKNOWN detection, AUROC, FPR95 |
| Packet loss | Pristine only | Linked 10/30/50% derivatives | Evidence loss, prediction-set growth, performance degradation |

An atomic candidate classifier cannot be expected to assign learned probability
to a completely unseen candidate. In LOCO/leave-one-cipher results, emphasize
whether CGII retains ground-truth containment, obeys hard constraints, expands
prediction sets, and avoids false certainty. Do not present argmax alone.

## 12. Required metrics

Report each seed and the mean with sample standard deviation. Required metrics:

- protocol field accuracy/macro-F1 and missing-field count;
- configuration exact match and macro-F1;
- protocol-constraint violation rate;
- prediction-set coverage and mean size;
- application balanced accuracy, macro-F1, one-vs-rest AUROC;
- ECE (15 bins), Brier score, and NLL;
- open-world balanced accuracy/macro-F1 including UNKNOWN;
- OOD AUROC and FPR95;
- performance at 0%, 10%, 30%, and 50% loss;
- latency mean/p50/p95/p99;
- active-learning efficiency only if the separate learning-curve experiment is
  actually run.

The current aggregator reports per-seed values, mean, and sample SD. Compute
scenario-grouped bootstrap 95% confidence intervals and paired CGII effects by
resampling complete replicate groups rather than packets:

```bash
python experiments/bootstrap_results.py artifacts/results \
  --output artifacts/results/bootstrap-confidence-intervals.json \
  --iterations 2000 \
  --seed 26160
```

## 13. Export manuscript tables

```bash
python experiments/export_results.py artifacts/results/aggregate-results.json \
  --csv artifacts/results/manuscript-results.csv \
  --markdown artifacts/results/manuscript-results.md
```

Copy only these traceable values into the manuscript. For each table, retain
the dataset, split, prediction, model, calibration, and result hashes. Replace
every manuscript `TBD — requires experiment` individually; leave unexecuted
experiments explicitly marked.

## 14. Publication acceptance checklist

- [ ] Plans were generated before viewing outcomes.
- [ ] Configuration and application factors are crossed in FULL data.
- [ ] All five seeds are present; no best-seed selection occurred.
- [ ] Failed rows are counted and explained.
- [ ] Every PCAP has valid adjacent ground truth and matching SHA-256.
- [ ] No endpoint secret appears in the release.
- [ ] Source/derivative lineage never crosses partitions.
- [ ] Calibration groups are disjoint from training and test groups.
- [ ] UNKNOWN profiles are excluded from ordinary application training.
- [ ] CGII prediction sets—not only point predictions—are reported.
- [ ] Constraint violation and evidence completeness are reported.
- [ ] Packet-loss degradation is evaluated on linked held-out captures.
- [ ] Cross-stack claims are made only if Libreswan pilot and full runs pass.
- [ ] Per-seed results, dispersion, confidence intervals, and effect sizes are
  included.
- [ ] Hardware/software/container versions and hashes are archived.
- [ ] Dataset card, code archive, split manifests, and result records are ready
  for anonymous review or a justified controlled-access release.

## 15. Troubleshooting without invalidating the experiment

- **Docker unavailable:** stop; use the designated Linux lab host. Do not
  replace the range with synthetic PCAPs.
- **Proposal rejected:** retain logs, check the stack's supported algorithms,
  and revise the design version before rerunning all affected cells.
- **No ESP packets:** check both XFRM states, routes, selectors, and application
  service. Do not label the run completed.
- **PCAP hash mismatch:** quarantine the entire run directory and rerun that
  predeclared row.
- **Split leakage:** regenerate splits after correcting `replicate_group`; do
  not manually edit split IDs.
- **TCN nondeterminism error:** record hardware/driver details and run the
  declared CPU path unless a new accelerator protocol is preregistered.
- **Libreswan build/interop failure:** keep the failure artifact; publish the
  strongSwan experiment without a cross-stack claim or fix and rerun the entire
  interop plan.

## 16. Implementation documentation used for the range

- strongSwan proposal syntax and PFS behavior:
  <https://docs.strongswan.org/docs/latest/config/proposals.html>
- strongSwan `swanctl.conf`:
  <https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html>
- Libreswan `ipsec.conf` parameters and proposal syntax:
  <https://libreswan.org/man/ipsec.conf.5.html>
- Libreswan 5.4 release commit:
  <https://github.com/libreswan/libreswan/commit/5eb03b7772b312e705feab9ad5868678a3c007e6>
- optional ISCXVPN2016 dataset description:
  <https://www.unb.ca/cic/datasets/vpn.html>

Record the access/review date in the frozen dataset card. These implementation
documents supplement—not replace—the RFC/NIST rule sources in
`docs/Standards_Rulebook.md`.
