# Automated isolated strongSwan cyber-range

This range is restricted to Docker-internal RFC 1918 and IPv6 ULA networks. It does not accept arbitrary targets. Execute it only on an authorized laboratory host with Docker, Compose, `NET_ADMIN`, and enough resources to compile strongSwan.

The image build pins strongSwan 6.1.0 and verifies the source archive SHA-256. The Debian base tag is resolved and recorded by `docker compose images`; promote the resolved digest into your institutional image lock before a frozen benchmark release.

Compile without privileges:

```bash
python cyber_range/range.py compile \
  --scenario VGX-I2-V4-TUN-GCM19-NATIVE-WEB \
  --seed 11 --output artifacts/range
```

Run the isolated scenario:

```bash
python cyber_range/range.py run \
  --scenario VGX-I2-V4-TUN-GCM19-NATIVE-WEB \
  --seed 11 --output artifacts/range
```

Validate the one-to-one PCAP/ground-truth invariant:

```bash
python cyber_range/range.py validate artifacts/range
```

Every completed `capture.pcap` is paired with `ground_truth.json`, hashes, endpoint SA telemetry, redacted XFRM state, scenario seed, and application label. `swanctl.conf` contains a deterministic laboratory-only PSK and is permission-restricted; exclude it from published datasets. XFRM key material is redacted before persistence.

The disabled multiple-key-exchange scenario remains off until the ML-KEM provider/plugin and both peers are validated. It is a crypto-agility extension, not the core novelty.

For research data, use `experiments/plan_benchmark.py` and
`cyber_range/batch.py`; the planner crosses each VPN configuration with every
traffic profile to avoid configuration/application confounding. The optional
`compose.libreswan.yaml` path pins Libreswan 5.4 to its release commit and is
limited to a conservative IKEv2/IPv4/native-ESP interoperability subset. Follow
`docs/Student_Experiment_Execution_Runbook.md` and run the Libreswan pilot
before making any cross-stack claim.
