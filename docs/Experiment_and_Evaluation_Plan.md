# VPNGUARD-X Experiment and Evaluation Plan

**Version:** 0.1.0  
**Current results:** **TBD — requires experiment**  
**Safety boundary:** Controlled local cyber-range only

## 1. Research questions

- **RQ1:** How accurately does the deterministic parser extract properties that are actually visible?
- **RQ2:** Does CGII improve configuration inference while driving protocol-constraint violations to zero?
- **RQ3:** Are configuration prediction sets calibrated and usefully small?
- **RQ4:** Does UNKNOWN/OOD handling prevent confident misclassification of unseen applications and stacks?
- **RQ5:** How do packet loss and missing handshake segments affect evidence completeness, set size, and risk interval width?
- **RQ6:** Do minimum-change counterfactuals reduce configuration edit cost relative to a generic checklist?
- **RQ7:** What latency and resource cost are introduced by parsing, feature extraction, ML, constraint projection, and reporting?

## 2. Units of analysis and leakage control

The raw unit is a packet. Packets are grouped into directional flows, bidirectional sessions, CHILD-SAs, IKE-SAs, scenario runs, and configuration families. Splitting occurs at the highest relevant group—normally scenario run or complete configuration—never at packet level.

Every record carries:

- scenario ID;
- run/seed ID;
- configuration fingerprint;
- stack/version;
- capture point;
- application generator and session ID;
- PCAP SHA-256;
- ground-truth SHA-256.

Exact-file and scenario-group overlap checks must pass before training.

## 3. Cyber-range factors

The initial matrix covers:

- IKEv2 and deliberately legacy IKEv1;
- tunnel and transport mode;
- IKE/ESP AES-GCM, AES-CBC+HMAC-SHA-2, ChaCha20-Poly1305 where supported, and selected legacy negative controls;
- KE groups 14, 19, 20, and legacy groups 2/5 where the stack explicitly permits controlled testing;
- CHILD-SA PFS on/off;
- IPv4 and IPv6;
- native ESP and NAT-T;
- WEB, VIDEO, VOIP, BULK/FILE, INTERACTIVE/MESSAGING, ICMP/CONTROL;
- UNKNOWN/OOD generators held out from training.

The scenario generator rejects internally inconsistent proposals, such as AEAD plus a separate integrity algorithm.

## 4. Replication

- Default seeds: `11, 22, 33, 44, 55`.
- Planned repetitions: one independently seeded session for each of five seeds per configuration-by-traffic cell (five sessions per cell in total).
- All randomness originates from a recorded seed hierarchy: experiment → scenario → application session → packet-loss injection.
- Time-dependent tests record UTC timestamps but do not use wall time as an unrecorded source of randomness.

Final sample sizes are reported after successful generation; they are currently **TBD**.

## 5. Dataset construction

1. Compile scenario from `data/CyberRange_Scenario_Matrix.csv`.
2. Validate scenario and strongSwan proposal syntax.
3. Start isolated containers/namespaces with no public target interaction.
4. Start capture at the declared observation point.
5. Initiate IKE/IPsec and wait for explicit establishment signal.
6. Export VICI and XFRM state from both authorized peers.
7. Generate application traffic for a seeded duration/volume.
8. Stop capture and export final state/counters.
9. Compute hashes and finalize ground truth.
10. Run parser and compare only properties designated observable/derivable.

Failed scenarios remain in an audit log and are excluded using predeclared failure rules, not outcome-driven manual deletion.

## 6. Baselines

### Protocol/configuration baselines

1. Uniform candidate set.
2. Deterministic parser only.
3. Independent majority label per field.
4. XGBoost candidate/field classifier without constraints.
5. TCN sequence classifier without constraints.
6. XGBoost + CGII.
7. TCN + CGII.
8. Full CGII + calibration + OOD/evidence gates.

### Application baselines

1. Majority class.
2. XGBoost on flow statistics.
3. TCN on signed packet size and inter-arrival sequences.
4. Optional stronger published representation if time/resources permit; it must use the same split.

### Remediation baselines

1. Static best-practice checklist.
2. Rule-by-rule greedy changes.
3. Exact minimum-change search over the tested catalogue.

## 7. Generalization protocols

### 7.1 Leave-one-configuration-out (LOCO)

Each complete configuration is held out in turn. No flow/session from that configuration appears in training or calibration.

### 7.2 Leave-one-cipher-out

Hold out one ESP algorithm family. Report whether the system appropriately widens/abstains rather than maps it to a known cipher.

### 7.3 Leave-one-mode-out

Train on tunnel or transport and test on the other. Because passive mode may be unobservable, focus on application robustness and calibrated configuration uncertainty rather than forcing mode recovery.

### 7.4 IPv4 to IPv6

Train on IPv4 scenarios and test on matched IPv6 scenarios.

### 7.5 Native ESP to NAT-T

Train on native ESP, test on matched UDP-encapsulated ESP, then reverse.

### 7.6 Cross-stack

Train on strongSwan and test on a second authorized stack if legally and technically feasible. If not performed, mark **not executed**, not zero.

### 7.7 Unseen-application OOD

Hold out one or more application generators/classes and introduce unrelated encrypted/control traffic. UNKNOWN is the positive OOD class.

## 8. Incomplete-capture tests

Create deterministic corruptions without modifying the original PCAP:

- independent packet removal at approximately 10%, 30%, and 50%;
- removal of the full IKE_SA_INIT exchange;
- capture beginning after tunnel establishment;
- removal of one direction;
- snap-length truncation;
- short observation windows.

For each corruption, preserve a transformation manifest and seed. Measure parser degradation, evidence completeness, candidate-set expansion, risk-interval width, and ground-truth containment.

## 9. Metrics

### 9.1 Protocol extraction

- field-level precision, recall, F1;
- exact match for fully observable tuples;
- false-observation rate: values incorrectly labeled `OBSERVED`;
- unknown correctness: hidden properties correctly withheld;
- session reconstruction pair/cluster precision and recall.

### 9.2 Configuration inference

- exact-match accuracy;
- per-field macro-F1;
- top-k accuracy as diagnostic;
- protocol-constraint violation rate;
- conflict rate and root causes.

### 9.3 Application traffic

- balanced accuracy;
- macro-F1;
- one-vs-rest AUROC and AUPRC where defined;
- per-class recall, including UNKNOWN;
- selective risk/coverage curve.

### 9.4 Calibration and prediction sets

- ECE with binning sensitivity;
- multiclass Brier score;
- NLL;
- empirical prediction-set coverage;
- mean/median/90th-percentile set size;
- class-conditional and configuration-conditional coverage diagnostics.

### 9.5 OOD

- OOD AUROC and AUPRC;
- FPR95;
- accepted OOD rate at the chosen threshold;
- in-distribution coverage retained after abstention.

### 9.6 Robustness

- relative performance drop by loss level;
- risk-interval containment of ground-truth risk;
- set-size growth versus evidence loss;
- monotonicity violations, if any.

### 9.7 System

- per-stage latency median/p95/p99;
- throughput in packets/s and flows/s;
- peak RSS and model size;
- API response size;
- active-learning macro-F1 versus labeled-scenario count.

## 10. Statistical analysis

- Report per-seed results and mean with standard deviation; do not report only the best seed.
- Use scenario-grouped bootstrap confidence intervals, resampling complete scenario runs.
- For paired method comparisons, use paired bootstrap differences on the same held-out runs.
- Report effect size and interval, not only a p-value.
- Correct families of confirmatory comparisons using Holm’s procedure.
- Mark analyses as confirmatory or exploratory before execution.
- Do not pool repeated packets as independent samples.

## 11. Calibration protocol

Training, calibration, threshold-selection, and test groups are disjoint. Calibration is repeated within each outer generalization split. OOD thresholds use a validation OOD set distinct from held-out OOD test applications. Coverage is not claimed when the target distribution violates the declared exchangeability assumption; results are then described empirically.

## 12. Active learning

Initial seed set is selected by configuration diversity, not random packets. Acquisition functions:

1. constrained entropy;
2. prediction-set size;
3. evidence conflict;
4. OOD score;
5. diversity-aware combination.

The oracle is authorized ground truth at scenario level. Compare macro-F1/coverage against random scenario acquisition at matched label budgets.

## 13. Ablation table template

| Method | Exact match | Constraint violations | Coverage | Set size | OOD AUROC | Risk containment |
|---|---:|---:|---:|---:|---:|---:|
| ML only | TBD | TBD | N/A | 1 | TBD | TBD |
| ML + constraints | TBD | TBD | N/A | TBD | TBD | TBD |
| ML + calibration | TBD | TBD | TBD | TBD | TBD | TBD |
| Full CGII | TBD | TBD | TBD | TBD | TBD | TBD |

## 14. Stopping, exclusion, and failure rules

- Do not stop based on favorable accuracy.
- A run is valid only if both ground-truth peers agree on the selected SA fields or disagreement is explicitly diagnosed.
- Infrastructure failures are rerun with the same seed and recorded.
- Parser failures are retained as failures for robustness metrics unless the file is proven corrupt before capture finalization.
- Unsupported stack/cipher combinations are `not feasible`, not negative observations.
- Manual relabeling requires a signed correction record.

## 15. Reproducibility package

Each released experiment includes:

- scenario matrix and generated configs;
- safe runner scripts;
- hashes, version/digest manifest, and seeds;
- ground truth without secrets;
- parser/features version;
- split assignments;
- trained model/calibrator hashes where redistribution permits;
- per-example predictions and candidate sets;
- metrics and bootstrap replicates;
- failures/exclusions;
- commands needed to reproduce tables and figures.

## 16. Execution status

The repository includes the experiment harness and test fixtures. Full cyber-range execution, training, and quantitative tables are **TBD — requires experiment on a Linux host with Docker/Podman, NET_ADMIN, and strongSwan-compatible kernel facilities**.
