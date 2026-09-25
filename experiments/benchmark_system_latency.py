#!/usr/bin/env python3
"""Benchmark the end-to-end deterministic VPNGUARD-X assessment path.

Model-specific latency is kept separate because each fitted model/calibrator is
split-specific.  This command measures PCAP reading, parsing, sessionization,
observability, feature extraction, CGII, policy, risk, and remediation without
claiming application-model latency.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file
from experiments.metrics import evaluate_prediction_records
from pipeline import VPNGuardXPipeline


def benchmark(dataset: str | Path, *, output: str | Path, repeats: int, limit: int | None) -> dict:
    if repeats < 1:
        raise ValueError("repeats must be positive")
    dataset_path = Path(dataset).resolve()
    rows = [
        json.loads(line)
        for line in dataset_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows = [row for row in rows if row.get("capture_variant") == "FULL"]
    if limit is not None:
        rows = rows[:limit]
    if not rows:
        raise ValueError("dataset contains no selected FULL captures")
    pipeline = VPNGuardXPipeline()
    records = []
    for row in rows:
        pcap = Path(row["pcap_path"])
        if not pcap.exists() or sha256_file(pcap) != row["pcap_sha256"]:
            raise ValueError(f"PCAP missing or hash mismatch: {pcap}")
        for repeat in range(repeats):
            bundle = pipeline.analyze(pcap)
            records.append(
                {
                    "artifact_id": row["artifact_id"],
                    "replicate_group": row.get("replicate_group"),
                    "repeat": repeat,
                    "packet_count": bundle.capture["packet_count"],
                    "latency_ms": bundle.run["latency_ms"]["total"],
                    "latency_stages_ms": bundle.run["latency_ms"],
                    "scope": "DETERMINISTIC_CORE_NO_LEARNED_MODEL",
                }
            )
    result = {
        "schema_version": "0.2.0",
        "dataset_sha256": sha256_file(dataset_path),
        "capture_count": len(rows),
        "repeats": repeats,
        "scope": "PCAP parsing through remediation; no learned model supplied",
        "metrics": evaluate_prediction_records(records)["latency"],
        "records": records,
    }
    selected = Path(output).resolve()
    selected.parent.mkdir(parents=True, exist_ok=True)
    selected.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark deterministic VPNGUARD-X system latency")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    result = benchmark(args.dataset, output=args.output, repeats=args.repeats, limit=args.limit)
    print(json.dumps({key: value for key, value in result.items() if key != "records"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
