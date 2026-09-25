# Synthetic proof-of-function

`synthetic_ikev2_esp.pcap` contains four programmatically constructed Ethernet/IPv4 packets: an IKE_SA_INIT request/response and two native ESP records. It contains no captured real-world traffic, secrets, or encrypted application data.

The paired `ground_truth.json` records the exact fixture hash and byte-level expected facts. `technical_report.md` and `executive_report.md` demonstrate current output wording. They are software examples, not experimental results or accuracy evidence.

Regenerate through:

```bash
python scripts/smoke_demo.py
```
