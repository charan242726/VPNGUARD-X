# Implementation and Verification Status

**Release:** 0.2.5 research prototype and finalization tooling  
**Status date:** 2026-09-23  
**Numerical research results in the source release:** **Not bundled; accept only the hash-verified finalization output**

## Verified in the authoring environment

The core implementation was compiled with Python 3.12 and exercised with the standard-library test suite. The tests construct packet bytes directly and verify:

- classic-PCAP ingestion;
- IKEv2 fixed header, IKE_SA_INIT SA/transform/KE parsing;
- responder selection extraction;
- native ESP and RFC 3948 ESP-in-UDP/non-ESP-marker demultiplexing;
- IKE session and ESP sequence-gap reconstruction;
- protected-field `UNKNOWN/UNOBSERVABLE` behavior;
- passive and cooperative pipeline outputs;
- hard-evidence monotonicity and AI non-elimination;
- evidence-conflict abstention and constrained-posterior normalization;
- conformal/temperature/open-world utilities;
- set-valued policy, risk interval, and catalogue-bounded remediation;
- flow/sequence feature dimensions;
- reproducible cyber-range compilation and secret-free manifest;
- balanced configuration-by-traffic benchmark planning and resumable batch compilation;
- bounded strongSwan-to-Libreswan configuration generation with secret-free manifests;
- incomplete-capture thinning, source lineage, dataset auditing, and split non-overlap;
- five-seed split generation and manifest-only end-to-end evaluation dry-run;
- JSON, technical Markdown, and executive Markdown reports.

The verification command and its current expected count are:

```bash
python -m unittest discover -s tests -v
# 38 tests; all must pass. Test count may increase in later versions.
```

The count is a software verification fact, not an experimental performance result.

## Implemented but requiring the target environment

| Subsystem | Why external execution is required | Acceptance evidence |
|---|---|---|
| strongSwan Docker range | Docker build, `NET_ADMIN`, kernel XFRM, packet capture | completed `ground_truth.json`, hash-matched PCAP, VICI/XFRM records, container digests |
| XGBoost training | generated labeled range dataset and ML dependency set | model artifact/hash, split/dataset/training manifest, held-out predictions |
| TCN training | same plus PyTorch runtime | state hash, deterministic runtime record, held-out predictions |
| FastAPI runtime | optional service dependencies | health/analyze contract tests in deployment image |
| Streamlit dashboard | optional dashboard dependencies/browser | rendered analyst acceptance test |
| strongSwan→Libreswan | supplied Libreswan 5.4 release-commit build and bounded interop Compose path still need Docker execution | cross-stack manifest, endpoint-selected SA agreement, PCAP, image digests |
| RFC 9370/ML-KEM pilot | validated provider/plugin support on both peers | VICI-confirmed selected algorithms; no packet-size guess |

## Result finalization

The source release does not embed experimental values. On an executed student repository, `scripts/finalize_vpnguard_x.py` verifies immutable predictions and split hashes, recomputes singleton-or-abstain configuration metrics without retraining, produces hierarchical intervals, and emits SIH/publication readiness reports. See `docs/FINALIZATION_RUNBOOK_0.2.5.md`.

Any value absent from that finalization output remains **TBD — requires experiment**. Historical manifest provenance and unavailable endpoint evidence remain disclosed limitations; the tooling does not manufacture replacements.

## Prototype-to-production gaps

- Add authenticated multi-tenant API access, TLS, upload scanning, quotas, retention controls, and background jobs.
- Validate parser behavior against a curated corpus and independent decoder; add PCAPNG conversion with a version-locked toolchain if required.
- Replace/reference-extend the finite candidate catalogue with organization-tested configuration templates.
- Establish signed policy/rule releases and formal standards-review ownership.
- Threat-model malicious captures and fuzz parsers before exposed deployment.
- Freeze container base image digests and package hashes for the benchmark environment.
- Obtain ethics/data authorization and document privacy controls for any non-synthetic captures.
