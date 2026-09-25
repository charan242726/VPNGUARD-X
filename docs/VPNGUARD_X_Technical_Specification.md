# VPNGUARD-X Technical Specification

**Project:** SIH 26160 — AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework  
**System name:** VPNGUARD-X — Evidence-Bounded and Constraint-Guided AI Framework for IPsec VPN Security Assurance  
**Specification version:** 0.1.0  
**Status:** Implementation baseline  
**Empirical results:** **TBD — requires experiment**

## 1. Purpose

VPNGUARD-X analyzes IKE/IPsec packet captures without pretending that encryption exposes endpoint configuration. Its central contract is that every reported property carries both a value and an epistemic status:

- `OBSERVED`: present directly in authenticated or unauthenticated packet structure, capture metadata, or authorized endpoint telemetry.
- `DETERMINISTICALLY_DERIVED`: follows uniquely from observed evidence and an explicit protocol rule.
- `AI_INFERRED`: estimated from traffic features, with calibrated uncertainty and source-model metadata.
- `UNKNOWN/UNOBSERVABLE`: not supportable from the available evidence, conflicting, or withheld because confidence/evidence is insufficient.

The system is intended for authorized defensive assessment in a controlled cyber-range or on captures supplied by their owner. It must not scan, attack, authenticate to, or alter public or unauthorized VPN endpoints.

## 2. Research claim

The primary research contribution is **CGII (Constraint-Guided IPsec Inference)**. CGII combines:

1. deterministic IKE/ESP parsing;
2. an explicit observability model;
3. protocol-consistency constraints;
4. a learned candidate prior;
5. calibrated set-valued prediction;
6. standards-traceable policy evaluation; and
7. interval-valued risk and minimum-change counterfactual remediation.

The novelty is not the coexistence of a parser, classifier, dashboard, and rule engine. It is the end-to-end prevention of unsupported claims under partial encrypted evidence.

## 3. Scope

### 3.1 In scope

- Classic PCAP ingestion and optional authorized live capture.
- Ethernet, IPv4, IPv6, UDP, IKEv2, limited legacy IKEv1 identification, native ESP, and UDP-encapsulated ESP.
- IKE header and visible IKE_SA_INIT payload parsing.
- IKE/ESP session reconstruction with retransmission awareness.
- Passive observability classification at property level.
- Authorized strongSwan/VICI and Linux XFRM ground-truth ingestion.
- Flow and packet-sequence feature extraction without payload decryption.
- XGBoost and TCN baselines for application classification/configuration candidate scoring.
- Open-world `UNKNOWN` handling and incomplete-capture robustness.
- CGII candidate elimination, constrained posterior, calibrated prediction sets, and conflict detection.
- RFC/NIST policy profiles with rule provenance.
- Risk intervals and robust/contingent counterfactual remediation.
- FastAPI service, Streamlit dashboard, JSON and Markdown reports.
- Controlled strongSwan scenario compilation and execution assets.
- Reproducible experiments, seeds, manifests, tests, and artifact hashes.

### 3.2 Out of scope for the passive mode

- Decrypting IKE or ESP.
- Recovering keys, PSKs, certificates, or endpoint secrets.
- Treating outer IP addresses as authenticated peer identities.
- Treating an ESP SPI as if it disclosed the matching SAD entry.
- Claiming CHILD-SA encryption, integrity, PFS, mode, ESN, anti-replay state, lifetime, or traffic selectors unless supported by authorized telemetry or another explicit evidence route.
- Vulnerability exploitation or active probing.

## 4. Authoritative semantic baseline

The implementation uses the following sources, with rule-level section references recorded in `docs/Standards_Rulebook.md` and `configs/policy_rules.yaml`:

- RFC 7296, *Internet Key Exchange Protocol Version 2 (IKEv2)*.
- RFC 4303, *IP Encapsulating Security Payload (ESP)*.
- RFC 3948, *UDP Encapsulation of IPsec ESP Packets*, for NAT-T demultiplexing.
- RFC 8247, IKEv2 algorithm implementation requirements and guidance.
- RFC 8221, ESP/AH algorithm implementation requirements and guidance.
- RFC 9395, IKEv1 and obsolete-algorithm deprecation.
- RFC 9370, IKEv2 multiple key exchanges.
- NIST SP 800-77 Rev. 1, *Guide to IPsec VPNs*.
- strongSwan 6.1 documentation for VICI, `swanctl`, proposals, and supported features.

Dynamic guidance is versioned by recording retrieval date, document version, strongSwan version, Linux/kernel version, container digest, Python lock, model hash, and policy-rules hash in each run manifest.

## 5. Operating modes

### 5.1 Passive Black-Box Mode

**Inputs:** PCAP or authorized live capture plus optional capture metadata.  
**Trust boundary:** packet bytes only; no decryption material.  
**Permitted outputs:** visible protocol facts, deterministic consequences, calibrated AI inference, and explicit unknowns.

Because IKEv2 protects IKE_AUTH, CREATE_CHILD_SA, and INFORMATIONAL payloads after IKE_SA_INIT, their exchange type, message ID, direction, length, and timing may remain visible while their protected contents do not. The parser must not convert exchange presence into hidden-payload claims.

### 5.2 Cooperative Validation Mode

**Optional authorized inputs:**

- `swanctl --list-sas --raw` or equivalent VICI export;
- `swanctl --list-conns --raw`;
- `ip -s xfrm state` and `ip -s xfrm policy`;
- scenario definition and container/runtime manifest.

Endpoint values are tagged `OBSERVED` with source `VICI`, `XFRM`, or `SCENARIO_GROUND_TRUTH`, never as packet observations. Cooperative data is used to validate passive inference, create labels, and measure observability—not to leak into held-out passive features.

## 6. System architecture

| Module | Responsibility | Primary output |
|---|---|---|
| `cyber_range/` | Compile and run isolated strongSwan scenarios; capture PCAP and telemetry | PCAP + one-to-one ground truth |
| `parser/` | Dependency-free PCAP reader, packet decoder, IKE/ESP parser, sessionizer | normalized packet/session records |
| `observability/` | Assign evidence status and completeness; merge cooperative evidence | evidence ledger |
| `features/` | Flow statistics and fixed-length packet sequences | model-ready arrays/tables |
| `models/` | XGBoost, TCN, model serialization, OOD scores | candidate/application probabilities |
| `calibration/` | Temperature/scalar calibration and split-conformal sets | calibrated probabilities and sets |
| `cgii/` | Candidate generation, hard constraints, posterior projection, abstention | constrained candidate distribution |
| `policy/` | Versioned RFC/NIST rules and profile evaluation | certain/possible findings |
| `risk/` | Aggregate candidate-wise policy loss | bounded risk interval |
| `remediation/` | Minimum-cost compliant counterfactual search | robust and contingent changes |
| `reports/` | Technical/executive serialization | JSON/Markdown reports |
| `api/` | FastAPI endpoints | service interface |
| `dashboard/` | Streamlit evidence-first UI | analyst interface |
| `experiments/` | split generation, evaluation, robustness/OOD tests | result artifacts, initially TBD |

## 7. End-to-end processing

1. Compute SHA-256 of every input and assign a run ID.
2. Parse capture format and link layer. Unsupported formats fail explicitly or are converted by an external, version-recorded TShark step.
3. Decode IPv4/IPv6/UDP and distinguish IKE, native ESP, ESP-in-UDP, NAT keepalive, and unrelated traffic.
4. Parse visible IKE headers and unencrypted IKE_SA_INIT payloads. Preserve raw transform identifiers alongside mapped names.
5. Reconstruct IKE and ESP sessions, direction, retransmissions, observed sequence gaps, and capture completeness indicators.
6. Build a property-level evidence ledger using the observability matrix.
7. Extract flow and packet-sequence features; exclude decrypted data and ground-truth-only fields.
8. Produce application probabilities, configuration-candidate prior `q_theta(c|x)`, and OOD score.
9. Build hard evidence constraints from `OBSERVED` and eligible `DETERMINISTICALLY_DERIVED` entries.
10. Eliminate incompatible candidates and renormalize the prior over the surviving set.
11. Apply calibration. Return a candidate set unless a single candidate is justified.
12. Evaluate every candidate in the returned set against the selected policy profile.
13. Report findings as `certain` only when all supported candidates violate a rule; otherwise report `possible` or `not_evaluable`.
14. Compute candidate-wise risk and return `[minimum, maximum]`, not a false-precision point score.
15. Search for lowest-cost compliant configuration changes. Separate changes common to every supported candidate from contingent changes.
16. Generate technical and executive reports with traceable evidence and limitations.

## 8. Core data contracts

### 8.1 Evidence record

```json
{
  "property": "child.mode",
  "value": null,
  "status": "UNKNOWN/UNOBSERVABLE",
  "confidence": null,
  "source": "RFC7296_OBSERVABILITY",
  "source_locator": "RFC 7296 Sections 1.3.1 and 1.3.2",
  "rationale": "USE_TRANSPORT_MODE is carried inside a protected exchange",
  "run_id": "..."
}
```

Required invariants:

- `OBSERVED` and `DETERMINISTICALLY_DERIVED` require a source and rationale.
- `AI_INFERRED` requires model ID, model hash, calibrated confidence, and training-domain identifier.
- `UNKNOWN/UNOBSERVABLE` must include a reason code.
- `confidence` is not permitted for deterministic claims unless it represents capture quality separately.

### 8.2 Candidate configuration

The reference implementation models a finite, versioned catalogue of complete candidate configurations. Candidate fields include IKE version, outer IP version, encapsulation, IKE transforms, IKE KE group, CHILD-SA mode/transforms/PFS, ESN, anti-replay, lifetime, and authentication family. Production catalogues may be generated from organizational configuration templates rather than a Cartesian product.

### 8.3 Ground truth record

Each cyber-range PCAP has exactly one JSON ground-truth record containing:

- scenario ID and definition hash;
- seed;
- authorized endpoint configurations;
- selected IKE and CHILD-SA state from both peers;
- XFRM state/policy snapshots;
- application label and generator parameters;
- capture point, start/end times, packet-loss injection, and truncation settings;
- PCAP path, size, and SHA-256;
- strongSwan/container/kernel versions;
- scenario outcome and failure reason.

Secrets and raw session keys are excluded from publishable ground truth.

## 9. Observability and evidence completeness

The observability matrix is executable metadata, not just documentation. For requested property set `J`, evidence completeness is:

```math
E = \frac{\sum_{j \in J} w_j s_j}{\sum_{j \in J} w_j},
```

where `s_j = 1` for `OBSERVED`, `s_j = rho_d` for `DETERMINISTICALLY_DERIVED`, `s_j = rho_a * calibrated_confidence_j` for `AI_INFERRED`, and `s_j = 0` for `UNKNOWN/UNOBSERVABLE`. Defaults are `rho_d=0.95` and `rho_a=0.5`; they are presentation weights, not probabilities, and are sensitivity-tested.

Completeness never changes a hidden property into an observed one. It controls analyst warnings, minimum-evidence gates, and report wording.

## 10. Security-policy semantics

- IETF implementation statuses (`MUST`, `SHOULD`, etc.) are stored separately from an organization's deployment policy. A mandatory-to-implement algorithm is not automatically mandatory-to-use.
- RFC 9395 updates RFC 8247/RFC 8221; later guidance takes precedence where it explicitly updates a status.
- NIST rules are isolated in a named profile and are not presented as universal IETF requirements.
- A rule can fire only if its predicate is supported for at least one candidate.
- Findings contain rule ID, profile/version, source section, evidence/candidate support, severity, rationale, and remediation.

## 11. Risk semantics

Let `G` be the prediction set. Candidate risk is a normalized policy loss:

```math
R(c) = \frac{\sum_r w_r I_r(c)}{\sum_r w_r},
```

where `I_r(c)` is a rule-specific loss. The report returns:

```math
[R_min, R_max] = [\min_{c\in G} R(c),\max_{c\in G}R(c)].
```

The interval is accompanied by candidate count, posterior mass, evidence completeness, and unevaluable properties. It is not a probability of compromise and must not be labeled as such.

## 12. Counterfactual remediation

Given selected policy `pi`, cost function `d`, and supported configuration `c`, remediation solves:

```math
c* = argmin_{c' in C: compliant_pi(c')} d(c,c').
```

For a prediction set, VPNGUARD-X reports:

- **robust changes:** present in the minimum remediation for every supported candidate;
- **contingent changes:** required only for specified candidates/evidence branches;
- minimum and maximum change cost;
- configuration syntax as a draft requiring operator review.

The engine never applies remediation automatically.

## 13. API and UI requirements

Minimum API endpoints:

- `GET /health`
- `GET /v1/policy/profiles`
- `POST /v1/analyze/evidence`
- `POST /v1/analyze/pcap`
- `POST /v1/cgii/project`
- `POST /v1/remediation`

The dashboard must lead with capture scope and evidence completeness. It must visually separate observed, derived, inferred, and unknown properties; show candidate sets before policy findings; and prohibit a single security score when the supported risk interval is non-degenerate.

## 14. Failure and abstention behavior

| Condition | Required behavior |
|---|---|
| Unsupported capture format/link type | Fail with actionable error; do not return empty success |
| Truncated packet | Preserve packet metadata; mark affected parsing unknown |
| Missing IKE_SA_INIT | Do not claim negotiated IKE transforms |
| Multiple compatible candidates | Return a set and interval |
| No compatible candidate | Return `EVIDENCE_CONFLICT`; retain conflicting evidence |
| OOD score above threshold | Application=`UNKNOWN`; retain class probabilities as diagnostics |
| Calibration unavailable | Label set as heuristic; do not claim coverage |
| Policy source/version missing | Disable the rule and fail policy validation |
| Cooperative/passive disagreement | Preserve both sources; raise `GROUND_TRUTH_MISMATCH` |

## 15. Reproducibility and provenance

- Global seeds: `11, 22, 33, 44, 55` unless an experiment specifies otherwise.
- Grouped splits use scenario/configuration IDs so packets or flows from one generated session cannot cross train/test boundaries.
- Exact environment versions are in `requirements.lock.txt` and `configs/environment.lock.yml`.
- Every result directory contains `manifest.json`, configuration snapshots, input hashes, logs, metrics, predictions, and environment information.
- Test fixtures are synthetic protocol-conformance fixtures and are never reported as empirical performance.
- No accuracy, F1, AUROC, latency, coverage, or other performance value is included until generated by a recorded experiment.

## 16. Prototype acceptance criteria

The prototype is acceptable when:

1. all unit tests pass;
2. a synthetic native-ESP PCAP and NAT-T PCAP parse correctly;
3. visible IKEv2 fields receive correct evidence statuses;
4. hidden CHILD-SA properties remain unknown in passive mode;
5. cooperative evidence can resolve those properties without changing their source label;
6. CGII assigns zero mass to hard-constraint violations;
7. constrained probability sums to one when candidates survive;
8. ambiguous evidence returns multiple candidates;
9. policy evaluation distinguishes certain from possible findings;
10. risk output is an interval;
11. remediation returns a minimum-cost compliant alternative without applying it;
12. API and CLI smoke tests complete; and
13. cyber-range scenario generation creates one ground-truth template per planned PCAP.

Large-scale performance results remain **TBD — requires experiment** until the controlled range is executed.
