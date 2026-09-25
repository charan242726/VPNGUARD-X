# VPNGUARD-X

For code/evidence sharing, follow [Safe Sharing Guide](docs/Safe_Sharing_Guide.md) before publishing or uploading experimental artifacts.

**SIH 26160 — Evidence-Bounded and Constraint-Guided AI Framework for IPsec VPN Security Assurance**

VPNGUARD-X is a working research prototype that analyzes authorized IKE/IPsec captures without claiming that encryption reveals endpoint-only state. Every reported property is labeled exactly one of:

| Label | Meaning |
|---|---|
| `OBSERVED` | Parsed from packet structure/capture metadata or supplied authorized endpoint telemetry |
| `DETERMINISTICALLY_DERIVED` | Follows uniquely from observed premises and a registered rule |
| `AI_INFERRED` | Model estimate with model ID/hash and calibrated confidence metadata |
| `UNKNOWN/UNOBSERVABLE` | Unsupported, protected, endpoint-local, missing, conflicting, or rejected as open-world |

No empirical accuracy value is hard-coded or claimed by the source repository. Accept benchmark values only from a hash-verified finalization run over the executed prediction records; any absent value remains **TBD — requires experiment**.

## What is implemented

- Dependency-free classic-PCAP reader and Ethernet/Linux-cooked/raw-IP decoder.
- Conservative IPv4/IPv6, UDP 500/4500, IKEv2, native ESP, ESP-in-UDP, NAT keepalive, and limited IKEv1 identification.
- Visible IKE_SA_INIT proposal/selection and KE parsing; protected payload boundary enforcement.
- IKE session and directional ESP/SPI reconstruction with retransmission, duplicate, and observed-gap accounting.
- Executable IPsec observability matrix and authorized strongSwan/VICI/XFRM adapters with secret rejection/redaction.
- Flow-statistical and fixed-length packet-sequence features without decryption.
- Trainable XGBoost and masked TCN baselines; temperature scaling, split-conformal candidate sets, and UNKNOWN gate.
- CGII hard-constraint projection, conflict abstention, posterior renormalization, entropy, completeness, and unresolved-field reporting.
- Versioned RFC/NIST rules with source section/rationale; certain/possible/not-supported/not-evaluable semantics.
- Candidate-wise normalized policy-loss interval and catalogue-bounded minimum-change remediation.
- FastAPI, Streamlit, CLI, technical/executive Markdown, and lossless JSON reports.
- Docker-internal strongSwan 6.1.0 range compiler/runner, seeded traffic generator, redacted telemetry, and PCAP-ground-truth validation.
- Generalization splits, 10/30/50% deterministic incomplete-capture generation, metrics, and active-learning harness.
- Optional RFC 9370 multiple-key-exchange evidence module that never identifies a protected KEM from size alone.

## Quick proof-of-function

Python 3.12 is required. The core path needs only PyYAML.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements/core.lock
python -m unittest discover -s tests -v
python scripts/smoke_demo.py
```

The smoke demo creates a synthetic IKEv2/ESP fixture—not experimental data—and produces an evidence JSON export, Markdown copies, and polished `technical_report.pdf` and `executive_report.pdf` files under `artifacts/smoke_demo/reports/`.

Analyze an authorized classic PCAP:

```bash
python vpnguardx.py analyze capture.pcap --profile nist_800_77r1 --output artifacts/assessment
```

Cooperative validation accepts a JSON object whose keys are canonical evidence properties:

```bash
python vpnguardx.py analyze capture.pcap \
  --cooperative-json authorized_properties.json \
  --output artifacts/cooperative
```

Example properties include `child.mode`, `child.encryption`, `child.integrity`, `child.pfs_group`, `child.esn`, `child.anti_replay_enabled`, `sa.configured_lifetime`, and `ike.authentication_family`. Never supply secrets or key material.

## Service and dashboard

```bash
python -m pip install -e '.[service,dashboard]'
uvicorn api.main:app --host 127.0.0.1 --port 8000
streamlit run dashboard/app.py
```

## Desktop analyst console

The Electron console keeps model weights on the local backend; the React UI receives only
the evidence-bounded assessment. It starts its capture workflow only after the operator
acknowledges authorization, then performs `capture → analyze → report` using the fixed
IKE/ESP filter. For the supplied demo bundle, it launches the verified bundle at
`artifacts/deployment_bundle` with its explicit `SYNTHETIC_SOFTWARE_DEMO` label. Do not
present its predictions as benchmark-validated for a new AES-128 or real-messaging trace.

```bash
cd vpnguardx-desktop
npm run dev
```

## Linux desktop installation

Full guide: [Linux Installation](docs/Linux_Installation.md).

For a source checkout on Debian/Ubuntu-family Linux, run the reviewed installer:

```bash
git clone https://github.com/charan242726/ip-sec-vpn-analyzer-new-.git
cd ip-sec-vpn-analyzer-new-
./install.sh
./scripts/launch-desktop.sh
```

The installer creates the app-local Python runtime at
`~/.config/VPNGUARD-X/.venv`, installs the desktop dependencies, and
optionally asks an administrator to grant packet-capture capability **only** to
`dumpcap`. It never runs the Electron application as root and never grants a
capability to the Python analyzer. Accept that prompt only on a machine and
interfaces you are authorized to monitor.

`launch-desktop.sh` opens Electron. Do **not** open `http://localhost:5173`
in a browser: a browser has no Electron security bridge, cannot invoke the
local Python analyzer, and is intentionally blocked from presenting the
analyst console. On startup, the desktop app validates the local Python
runtime and the bundled deployment model before enabling analysis.

To diagnose an installation before opening the UI:

```bash
~/.config/VPNGUARD-X/.venv/bin/python vpnguardx.py health \
  --deployment artifacts/deployment_bundle --allow-demo-deployment
```

To create the Debian package from source:

```bash
cd vpnguardx-desktop
npm run dist:deb
```

The resulting package is `vpnguardx-desktop/dist/VPNGUARD-X-<version>-amd64.deb`.
It bundles the desktop UI, Python analysis source, and verified deployment
bundle. The target Linux machine still needs a compatible Python runtime with
the declared ML dependencies; use `install.sh` on that machine before relying
on model-backed analysis. This is deliberate: the desktop app is never silently
installed with a privileged or opaque Python environment.

Analyze with an explicit verified bundle outside the desktop console:

```bash
python vpnguardx.py analyze capture.pcap \
  --deployment artifacts/deployment_bundle --allow-demo-deployment \
  --output artifacts/assessment
```

The API limits upload size, accepts classic PCAP only, uses temporary files, and returns the full evidence-bounded result. Add authentication, TLS, tenant isolation, malware/content handling, retention controls, and a queue before any national/production deployment.

## Authorized passive live capture

The capture command performs no active probe and uses a fixed IPsec filter. It refuses to run without explicit acknowledgement:

```bash
sudo python vpnguardx.py capture eth0 --duration 30 \
  --output artifacts/live/capture.pcap --i-am-authorized
```

## Cyber-range

Compile a scenario without privilege:

```bash
python cyber_range/range.py compile \
  --scenario VGX-I2-V4-TUN-GCM19-NATIVE-WEB \
  --seed 11 --output artifacts/range
```

Execute on a dedicated Docker/Compose host with `NET_ADMIN`:

```bash
python cyber_range/range.py run \
  --scenario VGX-I2-V4-TUN-GCM19-NATIVE-WEB \
  --seed 11 --output artifacts/range
python cyber_range/range.py validate artifacts/range
```

Only fixed internal networks and matrix-defined scenarios are accepted. StrongSwan 6.1.0 source is checksum-verified. Each generated PCAP must have a hash-matched `ground_truth.json`; XFRM keys are redacted. See `cyber_range/README.md`.

The separately versioned AES-128, messaging-like, and synthetic-email scenarios in
`data/Demo_Extension_Scenario_Matrix.csv` are presentation-only/OOD extensions.
They are intentionally excluded from the frozen benchmark dataset, trained models,
and bootstrap accuracy claims. Follow [Demo Extension Runbook](docs/Demo_Extension_Runbook.md).

## Dataset and experiments

```bash
python experiments/plan_benchmark.py --profile pilot --stack strongSwan-6.1.0 \
  --output artifacts/plans/strongswan-pilot.csv
python cyber_range/batch.py artifacts/plans/strongswan-pilot.csv \
  --output artifacts/range --mode compile
python cyber_range/batch.py artifacts/plans/strongswan-pilot.csv \
  --output artifacts/range --mode run --fail-fast
python experiments/generate_incomplete_captures.py artifacts/range
python experiments/build_dataset.py artifacts/range --output data/generated/dataset.jsonl
python experiments/make_splits.py data/generated/dataset.jsonl --output artifacts/splits \
  --seeds 11 22 33 44 55
python experiments/audit_dataset.py data/generated/dataset.jsonl --splits artifacts/splits
```

Train baselines after choosing a generated split manifest:

```bash
python -m pip install -e '.[ml]'
python models/train_xgboost.py data/generated/dataset.jsonl artifacts/splits/LOCO__example.json \
  --task application --output models/artifacts/xgb-app
python models/train_tcn.py data/generated/dataset.jsonl artifacts/splits/LOCO__example.json \
  --output models/artifacts/tcn-app
```

The experiment plan requires LOCO, leave-one-cipher, leave-one-mode, IPv4→IPv6, native ESP→NAT-T, cross-stack when feasible, unseen-application OOD, and incomplete captures. Splits keep scenario/replicate groups disjoint. See `docs/Experiment_and_Evaluation_Plan.md`.

The end-to-end student procedure, balanced 810-run strongSwan design, preferred
90-run strongSwan→Libreswan validation, five-seed evaluation command, acceptance
gates, and manuscript export are in `docs/Student_Experiment_Execution_Runbook.md`.

If the full experiment has already completed, do not retrain merely to correct
the point-metric semantics. Run the immutable-prediction finalizer described in
`docs/FINALIZATION_RUNBOOK_0.2.5.md`; it preserves original artifacts and writes
separate SIH and publication packages under `artifacts/finalization/`.

## Repository map

```text
common/            evidence/provenance/logging/reproducibility
parser/            PCAP, IP/UDP/IKE/ESP, live capture, sessionization
observability/     matrix engine and cooperative telemetry
features/          flow and temporal metadata features
models/            XGBoost, TCN, candidate-prior bridge, UNKNOWN gate
calibration/       temperature scaling, conformal sets, metrics
cgii/              candidate catalogue, constraints, projection engine
policy/            versioned rule evaluation
risk/              bounded policy loss
remediation/       minimum-change compliant counterfactuals
crypto_agility/    RFC 9370 future-ready evidence module
cyber_range/       isolated strongSwan range and traffic generator
experiments/       split, perturbation, dataset, metric, active-learning tools
api/ dashboard/    service and analyst UI
reports/           JSON, technical, and executive output
tests/             synthetic protocol and system tests
configs/ data/     candidates, rules, experiments, observability/scenarios
docs/              specifications, rulebook, limitations, reproducibility
```

## CGII in one equation

For catalogue `C`, hard evidence `O`, feasible set `C_O`, and model candidate prior `q_theta(c|x)`:

```math
P(c\mid O,x)=\frac{q_\theta(c\mid x)\mathbf 1[c\in C_O]}{\sum_{c'\in C_O}q_\theta(c'\mid x)}.
```

Eliminated candidates receive zero probability. Contradictory hard evidence returns `EVIDENCE_CONFLICT`, not an unconstrained guess. With no learned prior, the reference system returns the full evidence-feasible set. With a learned prior, calibrated prediction sets should replace unsupported point predictions.

## Scientific and operational limits

- A passive IKEv2 capture normally cannot reveal peer identity/authentication, CHILD-SA algorithms, PFS, mode, configured lifetime, ESN, anti-replay state/window, selectors, or inner application plaintext.
- UDP/4500 proves framing only after structural demultiplexing; it does not by itself prove an active translator.
- An SPI indexes SA state; it does not encode the cipher, keys, mode, lifetime, or replay policy.
- Prediction-set coverage, classifier performance, OOD performance, robustness, latency distributions, and active-learning efficiency are all **TBD — requires experiment**.
- The 28-candidate reference catalogue demonstrates the algorithm and covers the declared initial scenarios; it is not an exhaustive IANA transform registry or production configuration inventory.
- Docker tunnel execution and second-stack interoperability were not run in the repository-authoring environment and must be verified on the designated laboratory host.

## Required first-deliverable artifacts

- `docs/VPNGUARD_X_Technical_Specification.md`
- `docs/Novelty_and_Literature_Gap.md`
- `docs/CGII_Algorithm_Specification.md`
- `docs/Experiment_and_Evaluation_Plan.md`
- `data/IPsec_Observability_Matrix.csv`
- `data/CyberRange_Scenario_Matrix.csv`
- `docs/Standards_Rulebook.md`

See `SECURITY.md` before using any capture or cyber-range function.
