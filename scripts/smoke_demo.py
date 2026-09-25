#!/usr/bin/env python3
"""Generate a synthetic fixture and execute the complete analysis pipeline."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline import VPNGuardXPipeline
from reports import write_reports
from tests.fixtures import write_synthetic_pcap


def main() -> int:
    output = ROOT / "artifacts/smoke_demo"
    output.mkdir(parents=True, exist_ok=True)
    pcap = write_synthetic_pcap(output / "synthetic_ikev2_esp.pcap")
    bundle = VPNGuardXPipeline().analyze(pcap)
    reports = write_reports(bundle, output / "reports")
    summary = {
        "fixture": str(pcap),
        "fixture_kind": "SYNTHETIC_PROTOCOL_UNIT_FIXTURE_NOT_EMPIRICAL_DATA",
        "run_id": bundle.run["run_id"],
        "cgii_status": bundle.cgii["status"],
        "candidate_set_size": len(bundle.cgii["prediction_set"]),
        "risk_interval": [bundle.risk["minimum"], bundle.risk["maximum"]],
        "reports": reports,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
