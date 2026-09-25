# Demo Extension Runbook

These scenarios close demonstration coverage gaps without modifying the immutable
benchmark dataset, trained models, prediction records, or bootstrap results.
They are functional parser/policy/gateway-telemetry demonstrations, **not** ML
accuracy evidence.

## Included extensions

| Scenario | Coverage | Traffic label | Claim boundary |
|---|---|---|---|
| `VGX-DEMO-I2-V4-TUN-A128GCM19-MSG` | AES-128-GCM, DH 19, PFS | `INTERACTIVE_MESSAGING` | Messaging-like proxy; never call it WhatsApp |
| `VGX-DEMO-I2-V4-TUN-A128CBC14-EMAIL` | AES-128-CBC + HMAC, DH 14, PFS | `EMAIL` | Synthetic SMTP/IMAP-like lab traffic only |

The scenarios use fixed internal cyber-range addresses, deterministic seeds, and
secret-free ground truth. The traffic generator rejects external targets. No
real WhatsApp account, real mail account, personal message, mail content, PSK,
or session key is collected or published.

## Compile and run

```bash
python cyber_range/range.py compile \
  --matrix data/Demo_Extension_Scenario_Matrix.csv \
  --scenario VGX-DEMO-I2-V4-TUN-A128GCM19-MSG --seed 11 \
  --output artifacts/demo_extensions

python cyber_range/range.py run \
  --matrix data/Demo_Extension_Scenario_Matrix.csv \
  --scenario VGX-DEMO-I2-V4-TUN-A128GCM19-MSG --seed 11 \
  --output artifacts/demo_extensions
```

Repeat for the AES-128-CBC/email row, then validate the paired PCAP/ground truth:

```bash
python cyber_range/range.py validate artifacts/demo_extensions
```

## Presentation wording

Use: “AES-128 and email/messaging-like traces are isolated functional demo
extensions. The parser and gateway-assisted policy assessment are evidence
based; these traces are outside the frozen ML benchmark and have no reported
classifier accuracy.”

To make `AES-128`, `EMAIL`, or a new `WHATSAPP` class benchmark-validated,
perform a separately versioned experiment: range execution, dataset build,
leakage audit, splits, retraining, inference, calibration/OOD evaluation, and
bootstrap finalization. Never append these files to the existing dataset.
