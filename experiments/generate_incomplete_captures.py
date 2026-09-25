#!/usr/bin/env python3
"""Create hash-linked 10/30/50% loss derivatives with adjacent ground truth."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file, stable_hash
from experiments.incomplete_capture import thin_pcap


LOSS_LEVELS = (0.10, 0.30, 0.50)


def generate_loss_derivatives(
    artifact_root: str | Path,
    *,
    loss_levels: tuple[float, ...] = LOSS_LEVELS,
    overwrite: bool = False,
) -> dict:
    root = Path(artifact_root).resolve()
    sources: list[Path] = []
    for truth_path in sorted(root.rglob("ground_truth.json")):
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        if truth.get("outcome") != "COMPLETED" or truth.get("lineage"):
            continue
        if truth.get("capture", {}).get("capture_variant") != "FULL":
            continue
        sources.append(truth_path)
    records: list[dict] = []
    for truth_path in sources:
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        source_pcap = truth_path.parent / truth["capture"]["pcap_file"]
        source_sha = sha256_file(source_pcap)
        if source_sha != truth["capture"]["sha256"]:
            raise ValueError(f"source PCAP hash mismatch: {source_pcap}")
        root_artifact_id = stable_hash(
            {
                "pcap": source_sha,
                "scenario": truth["scenario_id"],
                "seed": int(truth["seed"]),
                "capture_variant": "FULL",
            }
        )[:24]
        for loss in loss_levels:
            percent = int(round(loss * 100))
            destination_dir = truth_path.parent / "derived" / f"loss-{percent:02d}"
            destination = destination_dir / "capture.pcap"
            derivative_truth_path = destination_dir / "ground_truth.json"
            if destination.exists() or derivative_truth_path.exists():
                if not overwrite:
                    records.append({"source": str(source_pcap), "loss": loss, "status": "SKIPPED_EXISTS"})
                    continue
                if destination_dir.is_dir():
                    shutil.rmtree(destination_dir)
            destination_dir.mkdir(parents=True, exist_ok=True)
            transform_seed = int(stable_hash({"root": root_artifact_id, "loss": loss})[:8], 16)
            loss_manifest = thin_pcap(source_pcap, destination, loss_fraction=loss, seed=transform_seed)
            derivative_truth = dict(truth)
            derivative_truth["schema_version"] = "0.2.0"
            derivative_truth["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
            derivative_truth["capture"] = dict(truth["capture"])
            derivative_truth["capture"].update(
                {
                    "pcap_file": destination.name,
                    "sha256": sha256_file(destination),
                    "size_bytes": destination.stat().st_size,
                    "capture_variant": f"LOSS_{percent}",
                    "loss_manifest": loss_manifest,
                }
            )
            derivative_truth["lineage"] = {
                "root_artifact_id": root_artifact_id,
                "source_artifact_id": root_artifact_id,
                "source_pcap_sha256": source_sha,
                "transformation": "INDEPENDENT_BERNOULLI_PACKET_REMOVAL",
                "transformation_manifest_sha256": sha256_file(destination.with_suffix(".pcap.loss.json")),
            }
            derivative_truth_path.write_text(json.dumps(derivative_truth, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            records.append(
                {
                    "source": str(source_pcap),
                    "destination": str(destination),
                    "loss": loss,
                    "status": "CREATED",
                    "pcap_sha256": derivative_truth["capture"]["sha256"],
                }
            )
    if not sources:
        raise ValueError("no completed FULL ground-truth/PCAP pairs found")
    result = {
        "schema_version": "0.2.0",
        "artifact_root": str(root),
        "source_capture_count": len(sources),
        "created_count": sum(record["status"] == "CREATED" for record in records),
        "skipped_count": sum(record["status"] == "SKIPPED_EXISTS" for record in records),
        "loss_levels": list(loss_levels),
        "records": records,
    }
    (root / "incomplete-capture-manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate incomplete PCAP benchmark derivatives")
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    result = generate_loss_derivatives(args.artifact_root, overwrite=args.overwrite)
    print(json.dumps({key: value for key, value in result.items() if key != "records"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
