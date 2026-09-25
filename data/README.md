# VPNGUARD-X datasets

The repository intentionally does **not** ship fabricated research data.  The
benchmark dataset is produced from the isolated cyber-range, with one adjacent
`ground_truth.json` for every PCAP and a hash chain into the model-ready JSONL.

## Required datasets

1. **Balanced strongSwan benchmark (primary).** Generate every FULL run in the
   balanced plan. This is the authoritative dataset for parser accuracy,
   configuration inference, calibration, application classification, and
   generalization experiments.
2. **10/30/50% incomplete-capture derivatives (required robustness set).**
   Generate only from pristine FULL captures. Keep each derivative in the same
   replicate group as its source so it can never cross a split boundary.
3. **strongSwan-to-Libreswan interop captures (preferred external-stack set).**
   Begin with the two conservative IKEv2/IPv4/native-ESP configurations in
   `configs/benchmark_design.yaml`. Do not report a cross-stack result unless
   both endpoint state and the captured IKE/ESP session validate.
4. **ISCXVPN2016 (optional external traffic-shift check).** The official UNB
   page is <https://www.unb.ca/cic/datasets/vpn.html>. It can test whether a
   traffic classifier transfers to older, independently generated VPN traffic.
   It does not provide the endpoint-selected IPsec configuration ground truth
   needed for CGII and must not be used to claim CHILD-SA, PFS, mode, lifetime,
   ESN, or anti-replay accuracy.

## What is not a research dataset

`examples/synthetic_demo/` and test fixtures prove parser behavior only. They
must never be included in a training or evaluation table.

## Generated layout

```text
artifacts/range/<run-id>/seed-<seed>/
  capture.pcap
  ground_truth.json
  scenario_manifest.json
  left_sas.raw
  right_sas.raw
  left_xfrm.redacted.txt
  right_xfrm.redacted.txt
  derived/loss-10/{capture.pcap,ground_truth.json,capture.pcap.loss.json}
  derived/loss-30/{capture.pcap,ground_truth.json,capture.pcap.loss.json}
  derived/loss-50/{capture.pcap,ground_truth.json,capture.pcap.loss.json}
```

Model-ready rows are validated against
`experiments/schemas/dataset_record.schema.json`. Before sharing data, exclude
`swanctl.conf`, `ipsec.secrets`, private keys, PSKs, session keys, unredacted
XFRM output, and any container credential cache.
